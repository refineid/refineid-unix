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
    let path = path_for(directory, record.pair_id());
    let temporary = path.with_extension(TEMPORARY_EXTENSION);
    let blob = encode_pairing_record(record).map_err(|_| StoreError::WriteRefused)?;
    let written = (|| {
        let mut file: File = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(&temporary)?;
        file.write_all(&blob)?;
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
                let durable = match change(record) {
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

    use refineid_rapp::PairingState;

    use super::{FilePairingStore, path_for};
    use crate::ids::PairId;
    use crate::persistence::{PAIRING_BLOB_MAGIC, PAIRING_BLOB_VERSION};
    use crate::store::PairingStore;
    use crate::store::fixtures::record;

    /// Synthetic pair identifiers.
    const FIRST: [u8; refineid_rapp::PAIR_ID_SIZE] = *b"synthetic-pair-1";
    const SECOND: [u8; refineid_rapp::PAIR_ID_SIZE] = *b"synthetic-pair-2";
    /// A synthetic authentication certificate.
    const CERTIFICATE: &[u8] = b"synthetic authentication certificate";
    /// When the forgotten fixture's user forgot it.
    const FORGOTTEN_AT_MS: u64 = 1_800_000_000_000;
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
        std::fs::write(directory.join("garbage.pair"), b"not a record").unwrap();
        store.remove(pair_id).unwrap();
        assert!(!path_for(&directory, pair_id).exists());
        let reopened = FilePairingStore::open(&directory).unwrap();
        assert!(reopened.pair_ids().is_empty());
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
            Err(crate::store::StoreError::WriteRefused)
        );
        assert_eq!(store.get(pair_id).unwrap().auth_cert(), None);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
