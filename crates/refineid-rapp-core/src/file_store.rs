//! A durable [`PairingStore`] in one owner-only directory.
//!
//! Each pairing is one file, written atomically (temporary file, `fsync`,
//! rename) with mode `0600` inside a `0700` directory. The file holds the
//! [`persistence`](crate::persistence) encoding, which includes the pair's
//! private key; nothing here prints or logs it. A pairing's file goes when
//! its key does.
//!
//! No file holds a certificate. A record an earlier build stored with the
//! holder's certificate is rewritten without it when the store loads it,
//! keeping the file's age, and the pairing stays. A reader beside the
//! owner does this too, since the module that serves the browser may be
//! the only program running. A file owned by another user, as a privileged
//! process with an inherited home directory sees, is left to its owner: a
//! rewrite would take it from them.
//!
//! The store lives beside, not inside, the directory earlier releases used:
//! those records belong to an older protocol revision and are left
//! untouched rather than misread. A record file of an earlier encoding
//! revision in this directory belongs to an earlier protocol version: it
//! is removed, and its pairing is made again.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use refineid_rapp::{DisplayName, RecordStoreError, SweepOutcome};
use zeroize::Zeroizing;

use crate::ids::PairId;
use crate::persistence::{
    Stored, decode_pairing_record, decode_stored_pairing_record, encode_pairing_record,
    is_superseded,
};
use crate::store::{PairingRecord, PairingStore, StoreError};

/// File extension of one stored pairing.
const RECORD_EXTENSION: &str = "pair";
/// File extension of a record being written.
const TEMPORARY_EXTENSION: &str = "tmp";
/// The Snap user-common directory variable.
const SNAP_USER_COMMON: &str = "SNAP_USER_COMMON";
/// The XDG base-directory configuration variable.
const XDG_CONFIG_HOME: &str = "XDG_CONFIG_HOME";
/// The home directory variable.
const HOME: &str = "HOME";
/// The configuration directory under a home directory.
const CONFIG_DIRECTORY: &str = ".config";
/// The application's directory under the configuration directory.
const APPLICATION_DIRECTORY: &str = "refineid";
/// The store's directory under the application's.
const STORE_DIRECTORY: &str = "rapp-pairs";
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
    /// Loaded records, oldest first, identifier order breaking
    /// timestamp ties.
    records: Vec<PairingRecord>,
}

impl FilePairingStore {
    /// The per-user directory: `$XDG_CONFIG_HOME/refineid/rapp-pairs`, or
    /// `$HOME/.config/refineid/rapp-pairs`. Under a Snap the user-common
    /// directory replaces the home directory. A variable that is unset,
    /// empty or relative does not count; `None` when none counts.
    #[must_use]
    pub fn default_directory() -> Option<PathBuf> {
        directory_from(|name| std::env::var_os(name))
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
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIRECTORY_MODE)
            .create(directory)
            .map_err(|_| StoreError::WriteRefused)?;
        Self::load(directory, Sweep::Remove)
    }

    /// Opens the store in `directory` and loads every usable record,
    /// leaving the files of other records in place: a program that reads
    /// the store beside the one that owns it opens it this way, and never
    /// deletes a record; it does rewrite a record that held a certificate.
    /// A directory that does not exist is an empty store and is not created.
    ///
    /// # Errors
    /// [`StoreError::WriteRefused`] when the directory exists but cannot
    /// be read.
    pub fn open_without_sweep(directory: &Path) -> Result<Self, StoreError> {
        if fs::metadata(directory).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(Self {
                directory: directory.to_path_buf(),
                records: Vec::new(),
            });
        }
        Self::load(directory, Sweep::Keep)
    }

    fn load(directory: &Path, sweep: Sweep) -> Result<Self, StoreError> {
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
            let Ok((record, stored)) = decode_stored_pairing_record(&bytes) else {
                if sweep == Sweep::Remove && is_superseded(&bytes) {
                    // A pairing from an earlier protocol version: its
                    // holder pairs again, so the record goes.
                    let _ = fs::remove_file(&path);
                }
                continue;
            };
            if stored == Stored::Rewrite
                && let Err(error) = rewrite_keeping_age(directory, &record)
            {
                refineid_dev_errors::report!(Rapp, "stored certificate not erased", error);
            }
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok();
            loaded.push((modified, record));
        }
        loaded.sort_by_key(|(modified, record)| (*modified, record.pair_id()));
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
    /// [`StoreError::NoUserDirectory`] when no per-user directory
    /// resolves; otherwise as [`Self::open`].
    pub fn open_default() -> Result<Self, StoreError> {
        Self::open(&Self::default_directory().ok_or(StoreError::NoUserDirectory)?)
    }
}

/// [`FilePairingStore::default_directory`] over the environment `variable`
/// reads.
fn directory_from(variable: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let absolute = |name: &str| {
        variable(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    let config = absolute(SNAP_USER_COMMON)
        .map(|common| common.join(CONFIG_DIRECTORY))
        .or_else(|| absolute(XDG_CONFIG_HOME))
        .or_else(|| absolute(HOME).map(|home| home.join(CONFIG_DIRECTORY)))?;
    Some(config.join(APPLICATION_DIRECTORY).join(STORE_DIRECTORY))
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

/// The record of `pair_id` as its file holds it now, if it reads: what
/// another program on this computer wrote since this store read it, or
/// nothing when the pairing is gone.
pub(crate) fn read_record(directory: &Path, pair_id: PairId) -> Option<PairingRecord> {
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

/// Rewrites `record`'s file at this build's revision, which holds no
/// certificate. The file keeps its age: a rewrite says nothing of how
/// recent the pairing is, which is what the store's order follows. Another
/// user's file is left as it is.
///
/// # Errors
/// [`StoreError::WriteRefused`] when the file cannot be rewritten; the next
/// load tries again.
fn rewrite_keeping_age(directory: &Path, record: &PairingRecord) -> Result<(), StoreError> {
    let path = path_for(directory, record.pair_id());
    let metadata = fs::metadata(&path).map_err(|_| StoreError::WriteRefused)?;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Ok(());
    }
    write_record(directory, record)?;
    if let Ok(modified) = metadata.modified() {
        let _ = File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(modified));
    }
    Ok(())
}

/// Deletes `pair_id`'s file, its key with it, any temporary a stopped write
/// left, and the addresses kept beside it.
///
/// # Errors
/// [`StoreError::WriteRefused`] when the file cannot be deleted.
fn delete_record(directory: &Path, pair_id: PairId) -> Result<(), StoreError> {
    let path = path_for(directory, pair_id);
    fs::remove_file(&path).map_err(|_| StoreError::WriteRefused)?;
    let _ = fs::remove_file(path.with_extension(TEMPORARY_EXTENSION));
    crate::addresses::forget(directory, pair_id);
    Ok(())
}

impl FilePairingStore {
    /// Applies `change` to `pair_id`'s record as the disk holds it now,
    /// handing it the writer of the whole record: another program may have
    /// rewritten the file since this store read it, and a record the disk
    /// no longer holds readably is gone.
    fn change_in_place<Outcome>(
        &mut self,
        pair_id: PairId,
        change: impl FnOnce(
            &mut PairingRecord,
            &dyn Fn(&[u8]) -> Result<(), StoreError>,
        ) -> Result<Outcome, RecordStoreError<StoreError>>,
    ) -> Result<Outcome, RecordStoreError<StoreError>> {
        let unknown = RecordStoreError::Store(StoreError::Unknown);
        let position = self
            .records
            .iter()
            .position(|entry| entry.pair_id() == pair_id)
            .ok_or(unknown)?;
        let Some(mut current) = read_record(&self.directory, pair_id) else {
            self.records.remove(position);
            return Err(unknown);
        };
        let directory = &self.directory;
        let outcome = change(&mut current, &|blob| write_blob(directory, pair_id, blob));
        // Changed or refused, `current` is what the disk holds.
        if let Some(entry) = self.records.get_mut(position) {
            *entry = current;
        }
        outcome
    }
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
    ) -> Result<SweepOutcome, RecordStoreError<StoreError>> {
        self.change_in_place(pair_id, |current, write| {
            current.sweep(now_ms, session_established, write)
        })
    }

    fn rename_peer(
        &mut self,
        pair_id: PairId,
        name: &DisplayName,
    ) -> Result<bool, RecordStoreError<StoreError>> {
        self.change_in_place(pair_id, |current, write| current.rename_peer(name, write))
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

    use refineid_rapp::{
        PAIRING_IDLE_EXPIRY_MS, PairingState, RecordStoreError, SweepOutcome, decode_pair_record,
        encode_pair_record,
    };

    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use super::{
        APPLICATION_DIRECTORY, CONFIG_DIRECTORY, FilePairingStore, HOME, SNAP_USER_COMMON,
        STORE_DIRECTORY, Sweep, TEMPORARY_EXTENSION, XDG_CONFIG_HOME, directory_from, path_for,
    };
    use crate::ids::PairId;
    use crate::persistence::{
        CERTIFICATE_REVISION, PAIRING_BLOB_MAGIC, PAIRING_BLOB_VERSION, frame_certificate_revision,
    };
    use crate::store::fixtures::{CREATED_AT_MS, record};
    use crate::store::{PairingStore, StoreError};

    /// Whether any file in `directory` holds `needle`.
    fn any_file_holds(directory: &Path, needle: &[u8]) -> bool {
        std::fs::read_dir(directory).unwrap().any(|entry| {
            std::fs::read(entry.unwrap().path())
                .unwrap()
                .windows(needle.len())
                .any(|window| window == needle)
        })
    }

    /// A store in `directory` holding `pair_id`'s usable record as an
    /// earlier build stored it, with the holder's certificate. Opening the
    /// store has already rewritten it; the caller asserts that.
    fn store_after_certificate(directory: &Path, pair_id: PairId) -> FilePairingStore {
        write_certificate_revision(directory, pair_id);
        FilePairingStore::open(directory).unwrap()
    }

    /// Writes `pair_id`'s usable record in `directory` as an earlier build
    /// stored it, with the holder's certificate.
    fn write_certificate_revision(directory: &Path, pair_id: PairId) {
        std::fs::create_dir_all(directory).unwrap();
        let blob = frame_certificate_revision(&record(pair_id), CERTIFICATE);
        std::fs::write(path_for(directory, pair_id), blob).unwrap();
        assert!(any_file_holds(directory, CERTIFICATE));
    }

    /// The encoding revision of `pair_id`'s file in `directory`.
    fn revision_of(directory: &Path, pair_id: PairId) -> u8 {
        let blob = std::fs::read(path_for(directory, pair_id)).unwrap();
        *blob.get(PAIRING_BLOB_MAGIC.len()).unwrap()
    }

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
    /// A revision before the earliest one this build reads.
    const EARLIER_REVISION: u8 = CERTIFICATE_REVISION - 1;
    /// The body of a record of an earlier revision.
    const EARLIER_BODY: &[u8] = b"synthetic record of an earlier revision";
    /// The permission bits of a mode.
    const PERMISSION_BITS: u32 = 0o777;
    /// The mode of the store's directory.
    const DIRECTORY_MODE: u32 = 0o700;
    /// The mode of each record file.
    const FILE_MODE: u32 = 0o600;
    /// How far apart the recency test stamps its record files: wider
    /// than any filesystem timestamp tick.
    const STAMP_GAP_SECS: u64 = 3_600;

    /// Stamps `pair_id`'s record file in `directory` with `modified`.
    fn stamp(directory: &Path, pair_id: PairId, modified: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path_for(directory, pair_id))
            .unwrap()
            .set_modified(modified)
            .unwrap();
    }

    fn scratch() -> PathBuf {
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

    /// A synthetic home directory.
    const SYNTHETIC_HOME: &str = "/home/synthetic";
    /// A synthetic XDG configuration directory.
    const SYNTHETIC_CONFIG: &str = "/var/synthetic/config";
    /// A synthetic Snap user-common directory.
    const SYNTHETIC_SNAP: &str = "/var/synthetic/snap";
    /// A relative path, which no variable may name.
    const RELATIVE: &str = "synthetic";

    /// The directory resolved from the `(variable, value)` pairs.
    fn resolved(environment: &[(&str, &str)]) -> Option<PathBuf> {
        directory_from(|name| {
            environment
                .iter()
                .find(|(variable, _)| *variable == name)
                .map(|(_, value)| OsString::from(value))
        })
    }

    #[test]
    fn the_user_directory_resolves_from_absolute_variables_only() {
        let store = |config: PathBuf| config.join(APPLICATION_DIRECTORY).join(STORE_DIRECTORY);
        let home_config = || PathBuf::from(SYNTHETIC_HOME).join(CONFIG_DIRECTORY);
        let snap_config = PathBuf::from(SYNTHETIC_SNAP).join(CONFIG_DIRECTORY);
        assert_eq!(
            resolved(&[(HOME, SYNTHETIC_HOME)]),
            Some(store(home_config()))
        );
        assert_eq!(
            resolved(&[(HOME, SYNTHETIC_HOME), (XDG_CONFIG_HOME, SYNTHETIC_CONFIG)]),
            Some(store(PathBuf::from(SYNTHETIC_CONFIG)))
        );
        assert_eq!(
            resolved(&[
                (HOME, SYNTHETIC_HOME),
                (XDG_CONFIG_HOME, SYNTHETIC_CONFIG),
                (SNAP_USER_COMMON, SYNTHETIC_SNAP),
            ]),
            Some(store(snap_config))
        );
        assert_eq!(
            resolved(&[(HOME, SYNTHETIC_HOME), (XDG_CONFIG_HOME, RELATIVE)]),
            Some(store(home_config()))
        );
        assert_eq!(resolved(&[(HOME, RELATIVE)]), None);
        assert_eq!(resolved(&[(HOME, "")]), None);
        assert_eq!(resolved(&[]), None);
    }

    #[test]
    fn an_open_without_sweep_of_a_missing_directory_is_empty_and_creates_nothing() {
        let directory = scratch().join(APPLICATION_DIRECTORY).join(STORE_DIRECTORY);
        let store = FilePairingStore::open_without_sweep(&directory).unwrap();
        assert!(store.pair_ids().is_empty());
        assert!(!directory.exists());
        assert!(!directory.parent().unwrap().exists());
    }

    #[test]
    fn records_survive_reopening_in_owner_only_files() {
        let directory = scratch();
        {
            let mut store = FilePairingStore::open(&directory).unwrap();
            store.insert(record(PairId::from_array(FIRST))).unwrap();
            store.insert(record(PairId::from_array(SECOND))).unwrap();
        }
        // Timestamps can tie within one tick; stamp the order in explicitly.
        let now = SystemTime::now();
        stamp(
            &directory,
            PairId::from_array(SECOND),
            now - Duration::from_secs(STAMP_GAP_SECS),
        );
        stamp(&directory, PairId::from_array(FIRST), now);
        let store = FilePairingStore::open(&directory).unwrap();
        assert_eq!(
            store.pair_ids(),
            [PairId::from_array(FIRST), PairId::from_array(SECOND)]
        );
        let directory_mode = std::fs::metadata(&directory).unwrap().permissions().mode();
        assert_eq!(directory_mode & PERMISSION_BITS, DIRECTORY_MODE);
        for entry in std::fs::read_dir(&directory).unwrap() {
            let mode = entry.unwrap().metadata().unwrap().permissions().mode();
            assert_eq!(mode & PERMISSION_BITS, FILE_MODE);
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn records_with_tied_timestamps_reopen_in_descending_identifier_order() {
        let directory = scratch();
        {
            let mut store = FilePairingStore::open(&directory).unwrap();
            store.insert(record(PairId::from_array(SECOND))).unwrap();
            store.insert(record(PairId::from_array(FIRST))).unwrap();
        }
        let stamped = SystemTime::now();
        stamp(&directory, PairId::from_array(FIRST), stamped);
        stamp(&directory, PairId::from_array(SECOND), stamped);
        let store = FilePairingStore::open(&directory).unwrap();
        assert_eq!(
            store.pair_ids(),
            [PairId::from_array(SECOND), PairId::from_array(FIRST)]
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_forgotten_record_keeps_its_key_and_time_across_reopening() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut store = FilePairingStore::open(&directory).unwrap();
        store.insert(record(pair_id)).unwrap();
        let before = encode_pair_record(store.get(pair_id).unwrap().pairing()).unwrap();
        store
            .update(pair_id, &mut |entry| Some(entry.forgotten(FORGOTTEN_AT_MS)))
            .unwrap();
        let reopened = FilePairingStore::open(&directory).unwrap();
        let loaded = reopened.get(pair_id).unwrap();
        assert_eq!(loaded.state(), PairingState::Revoking);
        assert_eq!(loaded.pairing().forgotten_at_ms(), Some(FORGOTTEN_AT_MS));
        let expected = encode_pair_record(
            &decode_pair_record(&before)
                .unwrap()
                .forgotten(FORGOTTEN_AT_MS),
        )
        .unwrap();
        assert_eq!(
            encode_pair_record(loaded.pairing()).unwrap().as_bytes(),
            expected.as_bytes()
        );
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
        let blocked = path_for(&directory, pair_id).with_extension(TEMPORARY_EXTENSION);
        std::fs::create_dir(&blocked).unwrap();
        // A sweep that changes nothing writes nothing.
        assert_eq!(
            store.sweep(pair_id, CREATED_AT_MS, false),
            Ok(SweepOutcome::Kept)
        );
        assert_eq!(
            store.sweep(pair_id, IDLE_LIMIT_AT_MS, false),
            Err(RecordStoreError::Store(StoreError::WriteRefused))
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
            Err(RecordStoreError::Store(StoreError::Unknown))
        );
        assert!(stale.pair_ids().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn no_file_this_store_writes_holds_a_certificate() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut store = FilePairingStore::open(&directory).unwrap();
        store.insert(record(pair_id)).unwrap();
        store.sweep(pair_id, SESSION_AT_MS, true).unwrap();
        let renamed = refineid_rapp::DisplayName::parse("Beta Phone".to_owned()).unwrap();
        assert_eq!(store.rename_peer(pair_id, &renamed), Ok(true));
        assert_eq!(revision_of(&directory, pair_id), PAIRING_BLOB_VERSION);
        let reopened = FilePairingStore::open_without_sweep(&directory).unwrap();
        assert_eq!(
            reopened
                .get(pair_id)
                .unwrap()
                .pairing()
                .last_session_at_ms(),
            Some(SESSION_AT_MS)
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A certificate an earlier build stored goes at the first load, the
    /// day after it was stored as much as the week after, and by the
    /// module's reader as much as by the owner's open; the pairing stays.
    #[test]
    fn a_stored_certificate_goes_at_the_first_load_and_the_pairing_stays() {
        for sweep in [Sweep::Remove, Sweep::Keep] {
            let directory = scratch();
            let pair_id = PairId::from_array(FIRST);
            write_certificate_revision(&directory, pair_id);
            let store = FilePairingStore::load(&directory, sweep).unwrap();
            assert!(!any_file_holds(&directory, CERTIFICATE));
            assert_eq!(revision_of(&directory, pair_id), PAIRING_BLOB_VERSION);
            assert_eq!(
                store.get(pair_id).unwrap().state(),
                PairingState::PairedDisconnected
            );
            let reread = FilePairingStore::load(&directory, Sweep::Keep).unwrap();
            assert_eq!(
                reread.get(pair_id).unwrap().state(),
                PairingState::PairedDisconnected
            );
            std::fs::remove_dir_all(&directory).unwrap();
        }
    }

    #[test]
    fn a_session_after_a_stored_certificate_writes_none_back() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut store = store_after_certificate(&directory, pair_id);
        assert_eq!(
            store.sweep(pair_id, SESSION_AT_MS, true),
            Ok(SweepOutcome::Recorded)
        );
        assert!(!any_file_holds(&directory, CERTIFICATE));
        assert_eq!(
            store.get(pair_id).unwrap().pairing().last_session_at_ms(),
            Some(SESSION_AT_MS)
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_rewrite_keeps_the_files_age_and_so_the_stores_order() {
        let directory = scratch();
        let (older, newer) = (PairId::from_array(FIRST), PairId::from_array(SECOND));
        write_certificate_revision(&directory, older);
        FilePairingStore::open(&directory)
            .unwrap()
            .insert(record(newer))
            .unwrap();
        // The open above rewrote the older file; write it as it was.
        write_certificate_revision(&directory, older);
        let now = SystemTime::now();
        stamp(&directory, older, now - Duration::from_secs(STAMP_GAP_SECS));
        stamp(&directory, newer, now);
        let store = FilePairingStore::open(&directory).unwrap();
        assert!(!any_file_holds(&directory, CERTIFICATE));
        assert_eq!(store.pair_ids(), [newer, older]);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_refused_rewrite_keeps_no_certificate_in_memory_and_the_next_load_makes_it() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        write_certificate_revision(&directory, pair_id);
        let blocked = path_for(&directory, pair_id).with_extension(TEMPORARY_EXTENSION);
        std::fs::create_dir(&blocked).unwrap();
        let store = FilePairingStore::open_without_sweep(&directory).unwrap();
        assert_eq!(revision_of(&directory, pair_id), CERTIFICATE_REVISION);
        assert_eq!(
            store.get(pair_id).unwrap().state(),
            PairingState::PairedDisconnected
        );
        std::fs::remove_dir(&blocked).unwrap();
        drop(FilePairingStore::open_without_sweep(&directory).unwrap());
        assert!(!any_file_holds(&directory, CERTIFICATE));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn forgetting_keeps_the_key_and_no_certificate() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut store = store_after_certificate(&directory, pair_id);
        store
            .update(pair_id, &mut |entry| Some(entry.forgotten(CREATED_AT_MS)))
            .unwrap();
        assert!(path_for(&directory, pair_id).exists());
        assert!(!any_file_holds(&directory, CERTIFICATE));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn revoking_erases_the_file_and_any_temporary_a_stopped_write_left() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut store = store_after_certificate(&directory, pair_id);
        let leftover = path_for(&directory, pair_id).with_extension(TEMPORARY_EXTENSION);
        std::fs::write(&leftover, CERTIFICATE).unwrap();
        store.remove(pair_id).unwrap();
        assert!(!path_for(&directory, pair_id).exists());
        assert!(!leftover.exists());
        assert!(!any_file_holds(&directory, CERTIFICATE));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn expiring_writes_no_certificate_even_on_the_way_out() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut store = store_after_certificate(&directory, pair_id);
        assert_eq!(
            store.sweep(pair_id, IDLE_LIMIT_AT_MS, false),
            Ok(SweepOutcome::Expired)
        );
        assert!(path_for(&directory, pair_id).exists());
        assert!(!any_file_holds(&directory, CERTIFICATE));
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_refused_write_leaves_what_the_disk_holds() {
        let directory = scratch();
        let pair_id = PairId::from_array(FIRST);
        let mut store = FilePairingStore::open(&directory).unwrap();
        store.insert(record(pair_id)).unwrap();
        let blocked = path_for(&directory, pair_id).with_extension(TEMPORARY_EXTENSION);
        std::fs::create_dir(&blocked).unwrap();
        assert_eq!(
            store.update(pair_id, &mut |entry| Some(entry.forgotten(FORGOTTEN_AT_MS))),
            Err(StoreError::WriteRefused)
        );
        assert_eq!(
            store.get(pair_id).unwrap().state(),
            PairingState::PairedDisconnected
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
