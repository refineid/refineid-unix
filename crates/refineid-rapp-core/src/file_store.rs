//! A durable [`PairingStore`] in one owner-only directory.
//!
//! Each pairing is one file, written atomically (temporary file, `fsync`,
//! rename) with mode `0600` inside a `0700` directory. The file holds the
//! [`persistence`](crate::persistence) encoding, which includes the pair's
//! private key; nothing here prints or logs it. A pairing's file goes when
//! its key does.
//!
//! The store lives beside, not inside, the directory earlier releases used:
//! those records belong to an older protocol revision and are left
//! untouched rather than misread. A record file of an earlier encoding
//! revision in this directory belongs to an earlier protocol version: it
//! is removed, and its pairing is made again.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use refineid_rapp::{SweepError, SweepOutcome};
use zeroize::Zeroizing;

use crate::ids::PairId;
use crate::persistence::{decode_pairing_record, encode_pairing_record, is_superseded};
use crate::store::{PairingRecord, PairingStore, StoreError};

/// File extension of one stored pairing.
const RECORD_EXTENSION: &str = "pair";
/// File extension of a record being written.
const TEMPORARY_EXTENSION: &str = "tmp";
/// Owner-only directory permissions.
const DIRECTORY_MODE: u32 = 0o700;
/// Owner-only file permissions.
const FILE_MODE: u32 = 0o600;

/// What an opener does with the files of records it cannot use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sweep {
    /// Delete them; the owning program's open.
    Remove,
    /// Leave them; a reader beside the owner.
    Keep,
}

/// Pairings stored as files in one owner-only directory, each file
/// holding the whole record, its private key included.
#[derive(Debug)]
pub struct FilePairingStore {
    directory: PathBuf,
    /// Loaded records, oldest first.
    records: Vec<PairingRecord>,
}

impl FilePairingStore {
    /// The per-user directory: `$XDG_CONFIG_HOME/refineid/rapp-pairs`, or
    /// `$HOME/.config/refineid/rapp-pairs`. Under a Snap the user-common
    /// directory replaces the home directory.
    #[must_use]
    pub fn default_directory() -> PathBuf {
        let config = std::env::var_os("SNAP_USER_COMMON")
            .map(|common| PathBuf::from(common).join(".config"))
            .or_else(|| std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from))
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .unwrap_or_else(|| PathBuf::from(".config"));
        config.join("refineid").join("rapp-pairs")
    }

    /// Opens (creating if needed) the store in `directory` and loads every
    /// readable record. A record of an earlier encoding revision is
    /// removed: its pairing is made again. Any other file that does not
    /// decode is skipped, never rewritten.
    ///
    /// # Errors
    /// [`StoreError::WriteRefused`] when the directory cannot be created or
    /// read.
    pub fn open(directory: &Path) -> Result<Self, StoreError> {
        Self::load(directory, Sweep::Remove)
    }

    /// Opens (creating if needed) the store in `directory` and loads every
    /// usable record, leaving the files of other records in place: a
    /// program that reads the store beside the one that owns it opens it
    /// this way, and never deletes a record.
    ///
    /// # Errors
    /// As [`Self::open`].
    pub fn open_without_sweep(directory: &Path) -> Result<Self, StoreError> {
        Self::load(directory, Sweep::Keep)
    }

    fn load(directory: &Path, sweep: Sweep) -> Result<Self, StoreError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIRECTORY_MODE)
            .create(directory)
            .map_err(|_| StoreError::WriteRefused)?;
        let mut loaded = Vec::new();
        for entry in fs::read_dir(directory).map_err(|_| StoreError::WriteRefused)? {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some(RECORD_EXTENSION) {
                continue;
            }
            let Ok(bytes) = fs::read(&path).map(Zeroizing::new) else {
                continue;
            };
            let Ok(record) = decode_pairing_record(&bytes) else {
                if sweep == Sweep::Remove && is_superseded(&bytes) {
                    // A pairing from an earlier protocol version: its
                    // holder pairs again, so the record goes.
                    let _ = fs::remove_file(&path);
                }
                continue;
            };
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok();
            loaded.push((modified, record));
        }
        loaded.sort_by_key(|(modified, _)| *modified);
        Ok(Self {
            directory: directory.to_path_buf(),
            records: loaded.into_iter().map(|(_, record)| record).collect(),
        })
    }

    /// The directory holding the records.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Opens the store in [`Self::default_directory`].
    ///
    /// # Errors
    /// As [`Self::open`].
    pub fn open_default() -> Result<Self, StoreError> {
        Self::open(&Self::default_directory())
    }
}

/// The file of `pair_id`'s record: the identifier in lowercase hex.
pub(crate) fn path_for(directory: &Path, pair_id: PairId) -> PathBuf {
    let name: String = pair_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    directory.join(name).with_extension(RECORD_EXTENSION)
}

/// The record of `pair_id` as its file holds it, if it reads.
fn read_record(directory: &Path, pair_id: PairId) -> Option<PairingRecord> {
    let bytes = fs::read(path_for(directory, pair_id))
        .map(Zeroizing::new)
        .ok()?;
    decode_pairing_record(&bytes).ok()
}

/// Writes `record`'s file atomically.
///
/// # Errors
/// [`StoreError::WriteRefused`] when the record does not encode or the
/// file cannot be written.
fn write_record(directory: &Path, record: &PairingRecord) -> Result<(), StoreError> {
    let blob = encode_pairing_record(record).map_err(|_| StoreError::WriteRefused)?;
    write_blob(directory, record.pair_id(), &blob)
}

/// Writes `blob`, the stored form of `pair_id`'s record, as its file,
/// atomically.
///
/// # Errors
/// [`StoreError::WriteRefused`] when the file cannot be written.
fn write_blob(directory: &Path, pair_id: PairId, blob: &[u8]) -> Result<(), StoreError> {
    let path = path_for(directory, pair_id);
    let temporary = path.with_extension(TEMPORARY_EXTENSION);
    let written = (|| {
        let mut file: File = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(&temporary)?;
        file.write_all(blob)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(StoreError::WriteRefused);
    }
    Ok(())
}

/// Deletes `pair_id`'s file, its key with it, and the addresses kept
/// beside it.
///
/// # Errors
/// [`StoreError::WriteRefused`] when the file cannot be deleted.
fn delete_record(directory: &Path, pair_id: PairId) -> Result<(), StoreError> {
    fs::remove_file(path_for(directory, pair_id)).map_err(|_| StoreError::WriteRefused)?;
    crate::addresses::forget(directory, pair_id);
    Ok(())
}

impl PairingStore for FilePairingStore {
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        write_record(&self.directory, &record)?;
        self.records
            .retain(|entry| entry.pair_id() != record.pair_id());
        self.records.push(record);
        Ok(())
    }

    fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError> {
        self.records
            .iter()
            .find(|entry| entry.pair_id() == pair_id)
            .ok_or(StoreError::Unknown)
    }

    fn update(
        &mut self,
        pair_id: PairId,
        change: &mut dyn FnMut(PairingRecord) -> Option<PairingRecord>,
    ) -> Result<(), StoreError> {
        let mut outcome = Err(StoreError::Unknown);
        let directory = &self.directory;
        self.records = core::mem::take(&mut self.records)
            .into_iter()
            .filter_map(|record| {
                if record.pair_id() != pair_id {
                    return Some(record);
                }
                // Another program may have rewritten or removed the file
                // since this store read it: the change applies to the
                // record as the disk holds it now, and a record the disk
                // no longer holds readably is gone.
                let current = read_record(directory, pair_id)?;
                let durable = match change(current) {
                    Some(next) => write_record(directory, &next).map(|()| Some(next)),
                    None => delete_record(directory, pair_id).map(|()| None),
                };
                match durable {
                    Ok(next) => {
                        outcome = Ok(());
                        next
                    }
                    // The change did not reach the disk: the store holds
                    // what the disk holds.
                    Err(error) => {
                        outcome = Err(error);
                        read_record(directory, pair_id)
                    }
                }
            })
            .collect();
        outcome
    }

    fn sweep(
        &mut self,
        pair_id: PairId,
        now_ms: u64,
        session_established: bool,
    ) -> Result<SweepOutcome, SweepError<StoreError>> {
        let unknown = SweepError::Store(StoreError::Unknown);
        let position = self
            .records
            .iter()
            .position(|entry| entry.pair_id() == pair_id)
            .ok_or(unknown)?;
        // As in `update`: the sweep applies to the record as the disk holds
        // it now, and a record the disk no longer holds readably is gone.
        let Some(mut current) = read_record(&self.directory, pair_id) else {
            self.records.remove(position);
            return Err(unknown);
        };
        let directory = &self.directory;
        let outcome = current.sweep(now_ms, session_established, |blob| {
            write_blob(directory, pair_id, blob)
        });
        // Swept or refused, `current` is what the disk holds.
        if let Some(entry) = self.records.get_mut(position) {
            *entry = current;
        }
        outcome
    }

    fn pair_ids(&self) -> Vec<PairId> {
        self.records
            .iter()
            .rev()
            .map(PairingRecord::pair_id)
            .collect()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use refineid_rapp::{PAIRING_IDLE_EXPIRY_MS, PairingState, SweepError, SweepOutcome};

    use super::{FilePairingStore, path_for};
    use crate::ids::PairId;
    use crate::persistence::{PAIRING_BLOB_MAGIC, PAIRING_BLOB_VERSION};
    use crate::store::fixtures::{CREATED_AT_MS, record};
    use crate::store::{PairingStore, StoreError};

    /// Synthetic pair identifiers.
    const FIRST: [u8; refineid_rapp::PAIR_ID_SIZE] = *b"synthetic-pair-1";
    const SECOND: [u8; refineid_rapp::PAIR_ID_SIZE] = *b"synthetic-pair-2";
    /// A synthetic authentication certificate.
    const CERTIFICATE: &[u8] = b"synthetic authentication certificate";
    /// When the forgotten fixture's user forgot it.
    const FORGOTTEN_AT_MS: u64 = 1_800_000_000_000;
    /// When the fixture's pairing reaches the idle limit without a session.
    const IDLE_LIMIT_AT_MS: u64 = CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS;
    /// When another program noted a session to the fixture's pairing.
    const SESSION_AT_MS: u64 = 1_700_500_000_000;
    /// A revision before the one this build reads.
    const EARLIER_REVISION: u8 = PAIRING_BLOB_VERSION - 1;
    /// The body of a record of an earlier revision.
    const EARLIER_BODY: &[u8] = b"synthetic record of an earlier revision";
    /// The permission bits of a mode.
    const PERMISSION_BITS: u32 = 0o777;
    /// The mode of the store's directory.
    const DIRECTORY_MODE: u32 = 0o700;
    /// The mode of each record file.
    const FILE_MODE: u32 = 0o600;

    fn scratch() -> std::path::PathBuf {
        let suffix = getrandom::u64().unwrap();
        std::env::temp_dir().join(format!("refineid-rapp-store-{suffix:x}"))
    }

    /// A file holding a record of an earlier encoding revision.
    fn earlier_blob() -> Vec<u8> {
        let mut blob = PAIRING_BLOB_MAGIC.to_vec();
        blob.push(EARLIER_REVISION);
        blob.extend_from_slice(EARLIER_BODY);
        blob
    }

    #[test]
    fn records_survive_reopening_in_owner_only_files() {
        let directory = scratch();
        {
            let mut store = FilePairingStore::open(&directory).unwrap();
            store.insert(record(PairId::from_array(FIRST))).unwrap();
            store.insert(record(PairId::from_array(SECOND))).unwrap();
            store
                .update(PairId::from_array(FIRST), &mut |entry| {
                    Some(entry.with_auth_cert(Some(CERTIFICATE.to_vec())))
                })
                .unwrap();
        }
        let store = FilePairingStore::open(&directory).unwrap();
        assert_eq!(
            store.pair_ids(),
            [PairId::from_array(FIRST), PairId::from_array(SECOND)]
        );
        let first = store.get(PairId::from_array(FIRST)).unwrap();
        assert_eq!(first.auth_cert(), Some(CERTIFICATE));
        let directory_mode = std::fs::metadata(&directory).unwrap().permissions().mode();
        assert_eq!(directory_mode & PERMISSION_BITS, DIRECTORY_MODE);
        for entry in std::fs::read_dir(&directory).unwrap() {
            let mode = entry.unwrap().metadata().unwrap().permissions().mode();
            assert_eq!(mode & PERMISSION_BITS, FILE_MODE);
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_forgotten_record_keeps_its_key_and_time_across_reopening() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut store = FilePairingStore::open(&directory).unwrap();
        store.insert(record(pair_id)).unwrap();
        let key = *store.get(pair_id).unwrap().pairing().local_static_private();
        store
            .update(pair_id, &mut |entry| Some(entry.forgotten(FORGOTTEN_AT_MS)))
            .unwrap();
        let reopened = FilePairingStore::open(&directory).unwrap();
        let loaded = reopened.get(pair_id).unwrap();
        assert_eq!(loaded.state(), PairingState::Revoking);
        assert_eq!(loaded.pairing().forgotten_at_ms(), Some(FORGOTTEN_AT_MS));
        assert_eq!(loaded.pairing().local_static_private(), &key);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn an_open_without_sweep_skips_unusable_records_and_deletes_nothing() {
        let directory = scratch();
        {
            let mut store = FilePairingStore::open(&directory).unwrap();
            store.insert(record(PairId::from_array(SECOND))).unwrap();
        }
        let earlier_path = path_for(&directory, PairId::from_array(FIRST));
        std::fs::write(&earlier_path, earlier_blob()).unwrap();
        let store = FilePairingStore::open_without_sweep(&directory).unwrap();
        assert_eq!(store.pair_ids(), [PairId::from_array(SECOND)]);
        assert!(earlier_path.exists());
        let swept = FilePairingStore::open(&directory).unwrap();
        assert_eq!(swept.pair_ids(), [PairId::from_array(SECOND)]);
        assert!(!earlier_path.exists());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn removal_deletes_the_file_and_unreadable_files_are_skipped() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut store = FilePairingStore::open(&directory).unwrap();
        store.insert(record(pair_id)).unwrap();
        let garbage = directory.join("garbage.pair");
        std::fs::write(&garbage, b"not a record").unwrap();
        store.remove(pair_id).unwrap();
        assert!(!path_for(&directory, pair_id).exists());
        let reopened = FilePairingStore::open(&directory).unwrap();
        assert!(reopened.pair_ids().is_empty());
        // A file that is no record of any revision is skipped, never
        // deleted.
        assert!(garbage.exists());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn an_idle_sweep_the_disk_refused_is_repeated_by_the_next() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut store = FilePairingStore::open(&directory).unwrap();
        store.insert(record(pair_id)).unwrap();
        let blocked = path_for(&directory, pair_id).with_extension(super::TEMPORARY_EXTENSION);
        std::fs::create_dir(&blocked).unwrap();
        // A sweep that changes nothing writes nothing.
        assert_eq!(
            store.sweep(pair_id, CREATED_AT_MS, false),
            Ok(SweepOutcome::Kept)
        );
        assert_eq!(
            store.sweep(pair_id, IDLE_LIMIT_AT_MS, false),
            Err(SweepError::Store(StoreError::WriteRefused))
        );
        assert_eq!(
            store.get(pair_id).unwrap().state(),
            PairingState::PairedDisconnected
        );
        let disk = FilePairingStore::open_without_sweep(&directory).unwrap();
        assert_eq!(
            disk.get(pair_id).unwrap().state(),
            PairingState::PairedDisconnected
        );
        std::fs::remove_dir(&blocked).unwrap();
        assert_eq!(
            store.sweep(pair_id, IDLE_LIMIT_AT_MS, false),
            Ok(SweepOutcome::Expired)
        );
        let reopened = FilePairingStore::open(&directory).unwrap();
        let expired = reopened.get(pair_id).unwrap();
        assert_eq!(expired.state(), PairingState::Revoking);
        assert_eq!(expired.pairing().forgotten_at_ms(), Some(IDLE_LIMIT_AT_MS));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn an_idle_sweep_reads_the_session_another_program_noted() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut stale = FilePairingStore::open(&directory).unwrap();
        stale.insert(record(pair_id)).unwrap();
        let mut holder = FilePairingStore::open(&directory).unwrap();
        assert_eq!(
            holder.sweep(pair_id, SESSION_AT_MS, true),
            Ok(SweepOutcome::Recorded)
        );
        assert_eq!(
            stale.get(pair_id).unwrap().pairing().last_session_at_ms(),
            None
        );
        assert_eq!(
            stale.sweep(pair_id, IDLE_LIMIT_AT_MS, false),
            Ok(SweepOutcome::Kept)
        );
        assert_eq!(
            stale.get(pair_id).unwrap().pairing().last_session_at_ms(),
            Some(SESSION_AT_MS)
        );
        std::fs::remove_file(path_for(&directory, pair_id)).unwrap();
        assert_eq!(
            stale.sweep(pair_id, IDLE_LIMIT_AT_MS, false),
            Err(SweepError::Store(StoreError::Unknown))
        );
        assert!(stale.pair_ids().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_refused_write_leaves_what_the_disk_holds() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut store = FilePairingStore::open(&directory).unwrap();
        store.insert(record(pair_id)).unwrap();
        let blocked = path_for(&directory, pair_id).with_extension(super::TEMPORARY_EXTENSION);
        std::fs::create_dir(&blocked).unwrap();
        assert_eq!(
            store.update(pair_id, &mut |entry| {
                Some(entry.with_auth_cert(Some(CERTIFICATE.to_vec())))
            }),
            Err(StoreError::WriteRefused)
        );
        assert_eq!(store.get(pair_id).unwrap().auth_cert(), None);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
