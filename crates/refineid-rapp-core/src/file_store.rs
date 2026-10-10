//! A durable [`PairingStore`] in one owner-only directory.
//!
//! Each pairing is one file, written atomically (temporary file, `fsync`,
//! rename) with mode `0600` inside a `0700` directory. The file holds the
//! [`persistence`](crate::persistence) encoding, which includes the pair's
//! private key; nothing here prints or logs it.
//!
//! The store lives beside, not inside, the directory earlier releases used:
//! those records belong to an older protocol revision and cannot open a
//! v26.10.9 session, so they are left untouched rather than misread. A
//! record file of an earlier encoding revision in this directory is skipped
//! the same way, and its pairing is made again.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use crate::ids::PairId;
use crate::persistence::{decode_pairing_record, encode_pairing_record};
use crate::store::{PairingRecord, PairingStore, StoreError};

/// File extension of one stored pairing.
const RECORD_EXTENSION: &str = "pair";
/// Owner-only directory permissions.
const DIRECTORY_MODE: u32 = 0o700;
/// Owner-only file permissions.
const FILE_MODE: u32 = 0o600;

/// Pairings stored as files in one directory.
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
    /// readable record. A file that does not decode is skipped, never
    /// rewritten.
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
        let mut loaded = Vec::new();
        for entry in fs::read_dir(directory).map_err(|_| StoreError::WriteRefused)? {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some(RECORD_EXTENSION) {
                continue;
            }
            let Ok(bytes) = fs::read(&path).map(zeroize::Zeroizing::new) else {
                continue;
            };
            let Ok(record) = decode_pairing_record(&bytes) else {
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

    /// Opens the store in [`Self::default_directory`].
    ///
    /// # Errors
    /// As [`Self::open`].
    pub fn open_default() -> Result<Self, StoreError> {
        Self::open(&Self::default_directory())
    }

    fn path_for(&self, pair_id: PairId) -> PathBuf {
        let mut name = String::with_capacity(pair_id.as_bytes().len() * 2);
        for byte in pair_id.as_bytes() {
            use core::fmt::Write as _;
            let _ = write!(name, "{byte:02x}");
        }
        self.directory.join(name).with_extension(RECORD_EXTENSION)
    }

    fn write(&self, record: &PairingRecord) -> Result<(), StoreError> {
        let path = self.path_for(record.pair_id);
        let temporary = path.with_extension("tmp");
        let blob = encode_pairing_record(record);
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
}

impl PairingStore for FilePairingStore {
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        self.write(&record)?;
        self.records.retain(|entry| entry.pair_id != record.pair_id);
        self.records.push(record);
        Ok(())
    }

    fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError> {
        self.records
            .iter()
            .find(|entry| entry.pair_id == pair_id)
            .ok_or(StoreError::Unknown)
    }

    fn update(
        &mut self,
        pair_id: PairId,
        change: &mut dyn FnMut(&mut PairingRecord),
    ) -> Result<(), StoreError> {
        let index = self
            .records
            .iter()
            .position(|entry| entry.pair_id == pair_id)
            .ok_or(StoreError::Unknown)?;
        let mut next = self.records[index].clone();
        change(&mut next);
        self.write(&next)?;
        self.records[index] = next;
        Ok(())
    }

    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        let index = self
            .records
            .iter()
            .position(|entry| entry.pair_id == pair_id)
            .ok_or(StoreError::Unknown)?;
        fs::remove_file(self.path_for(pair_id)).map_err(|_| StoreError::WriteRefused)?;
        self.records.remove(index);
        Ok(())
    }

    fn pair_ids(&self) -> Vec<PairId> {
        self.records
            .iter()
            .rev()
            .map(|entry| entry.pair_id)
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

    use super::FilePairingStore;
    use crate::ids::{PairId, RendezvousToken};
    use crate::store::{PairingDisposition, PairingRecord, PairingStore};

    fn record(byte: u8) -> PairingRecord {
        PairingRecord {
            pair_id: PairId::from_array([byte; 16]),
            rendezvous_token: RendezvousToken::from_array([byte ^ 0xFF; 16]),
            local_private: zeroize::Zeroizing::new(vec![0x11; 32]),
            local_public: vec![0x22; 32],
            peer_public: vec![0x33; 32],
            granted_profiles: vec![crate::profiles::PROFILE_CARD_STATUS.to_owned()],
            grants_hash: [0x44; 32],
            peer_display_name: "Phone".into(),
            peer_platform: "iOS".into(),
            disposition: PairingDisposition::Paired,
            peer_initiated_termination: false,
            candidate_failures: 0,
            auth_cert: None,
            signature_cert: None,
            root_ca: None,
            intermediate_ca: None,
        }
    }

    fn scratch() -> std::path::PathBuf {
        let mut name = [0u8; 8];
        getrandom::fill(&mut name).unwrap();
        let suffix: String = name.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("refineid-rapp-store-{suffix}"))
    }

    #[test]
    fn records_survive_reopening_with_owner_only_files() {
        let directory = scratch();
        {
            let mut store = FilePairingStore::open(&directory).unwrap();
            store.insert(record(1)).unwrap();
            store.insert(record(2)).unwrap();
            store
                .update(PairId::from_array([1; 16]), &mut |entry| {
                    entry.auth_cert = Some(vec![0x30, 0x00]);
                })
                .unwrap();
        }
        let store = FilePairingStore::open(&directory).unwrap();
        assert_eq!(store.pair_ids().len(), 2);
        let first = store.get(PairId::from_array([1; 16])).unwrap();
        assert_eq!(first.auth_cert.as_deref(), Some(&[0x30, 0x00][..]));
        for entry in std::fs::read_dir(&directory).unwrap() {
            let mode = entry.unwrap().metadata().unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn removal_deletes_the_file_and_unreadable_files_are_skipped() {
        let directory = scratch();
        let mut store = FilePairingStore::open(&directory).unwrap();
        store.insert(record(3)).unwrap();
        std::fs::write(directory.join("garbage.pair"), b"not a record").unwrap();
        store.remove(PairId::from_array([3; 16])).unwrap();
        let reopened = FilePairingStore::open(&directory).unwrap();
        assert!(reopened.pair_ids().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
