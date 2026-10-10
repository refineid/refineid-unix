//! The requester operation journal as owner-only files.
//!
//! RAPP v26.10.9 section 8.3 reconciles an interrupted operation after the
//! requester reconnects, by `operation.status_request` with the operation's
//! identifier. That needs the identifier and request hash to outlive the
//! process, so each operation is one file, written atomically before the
//! request leaves. Opening the journal after a restart settles every entry
//! the last process left in flight: a consequential request the custodian
//! may have executed becomes ambiguous with retry forbidden, and a safe read
//! is cancelled. Entries hold no credential value and no message plaintext.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use crate::ids::{OperationId, PairId};
use crate::store::{JournalEntry, OperationJournal, OperationState, StoreError};

/// File extension of one journaled operation.
const ENTRY_EXTENSION: &str = "op";
/// Owner-only directory permissions.
const DIRECTORY_MODE: u32 = 0o700;
/// Owner-only file permissions.
const FILE_MODE: u32 = 0o600;

/// Format tag identifying a journal entry file.
const ENTRY_MAGIC: &[u8] = b"RAPP-op-journal";
/// The one encoding revision this build reads and writes.
const ENTRY_VERSION: u8 = 1;
/// Boolean false on disk.
const BOOLEAN_FALSE: u8 = 0;
/// Boolean true on disk.
const BOOLEAN_TRUE: u8 = 1;
/// Absent optional text on disk.
const ABSENT: u8 = 0;
/// Present optional text on disk.
const PRESENT: u8 = 1;

/// Actions that may consume a credential attempt or use a private key
/// (section 9); an unanswered one is ambiguous, never cancelled.
const CONSEQUENTIAL_ACTIONS: [&str; 3] = [
    "browser_authenticate",
    "sign_document",
    "batch_sign_documents",
];

/// The requester journal stored as one owner-only file per operation.
#[derive(Debug)]
pub struct FileOperationJournal {
    directory: PathBuf,
    entries: Vec<JournalEntry>,
}

impl FileOperationJournal {
    /// The per-user directory: `$XDG_CONFIG_HOME/refineid/rapp-journal`, or
    /// `$HOME/.config/refineid/rapp-journal`, beside the pairing store.
    #[must_use]
    pub fn default_directory() -> PathBuf {
        crate::file_store::FilePairingStore::default_directory().with_file_name("rapp-journal")
    }

    /// Opens (creating if needed) the journal in `directory`, loads every
    /// readable entry, and settles each entry a previous process left in
    /// flight. A file that does not decode is skipped, never rewritten.
    ///
    /// # Errors
    /// [`StoreError::WriteRefused`] when the directory cannot be created or
    /// read, or a settled entry cannot be written back.
    pub fn open(directory: &Path) -> Result<Self, StoreError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIRECTORY_MODE)
            .create(directory)
            .map_err(|_| StoreError::WriteRefused)?;
        let mut journal = Self {
            directory: directory.to_path_buf(),
            entries: Vec::new(),
        };
        for entry in fs::read_dir(directory).map_err(|_| StoreError::WriteRefused)? {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some(ENTRY_EXTENSION) {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else { continue };
            let Ok(decoded) = decode_entry(&bytes) else {
                continue;
            };
            journal.entries.push(decoded);
        }
        let interrupted: Vec<JournalEntry> = journal
            .entries
            .iter()
            .filter(|entry| !entry.state.is_terminal())
            .cloned()
            .collect();
        for mut entry in interrupted {
            if CONSEQUENTIAL_ACTIONS.contains(&entry.action.as_str()) {
                entry.state = OperationState::Ambiguous;
                entry.retry_prohibited = true;
            } else {
                entry.state = OperationState::Cancelled;
            }
            journal.record(entry)?;
        }
        Ok(journal)
    }

    /// Opens the journal in [`Self::default_directory`].
    ///
    /// # Errors
    /// As [`Self::open`].
    pub fn open_default() -> Result<Self, StoreError> {
        Self::open(&Self::default_directory())
    }

    /// Ambiguous entries of `pair_id` that no status answer annotated yet,
    /// oldest first: the operations section 8.3 reconciliation is for.
    #[must_use]
    pub fn unreconciled(&self, pair_id: PairId) -> Vec<&JournalEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.pair_id == pair_id
                    && entry.state == OperationState::Ambiguous
                    && entry.reconciled_proxy_state.is_none()
            })
            .collect()
    }

    /// Removes every entry of `pair_id`, for a forgotten pairing.
    ///
    /// # Errors
    /// [`StoreError::WriteRefused`] when a file cannot be removed.
    pub fn forget_pair(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        for entry in self.entries.iter().filter(|entry| entry.pair_id == pair_id) {
            match fs::remove_file(self.path_for(entry.operation_id)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(StoreError::WriteRefused),
            }
        }
        self.entries.retain(|entry| entry.pair_id != pair_id);
        Ok(())
    }

    fn path_for(&self, operation_id: OperationId) -> PathBuf {
        let mut name = String::with_capacity(operation_id.as_bytes().len() * 2);
        for byte in operation_id.as_bytes() {
            use core::fmt::Write as _;
            let _ = write!(name, "{byte:02x}");
        }
        self.directory.join(name).with_extension(ENTRY_EXTENSION)
    }

    fn write(&self, entry: &JournalEntry) -> Result<(), StoreError> {
        let path = self.path_for(entry.operation_id);
        let temporary = path.with_extension("tmp");
        let blob = encode_entry(entry);
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

impl OperationJournal for FileOperationJournal {
    fn record(&mut self, entry: JournalEntry) -> Result<(), StoreError> {
        self.write(&entry)?;
        self.entries
            .retain(|existing| existing.operation_id != entry.operation_id);
        self.entries.push(entry);
        Ok(())
    }

    fn get(&self, operation_id: OperationId) -> Result<&JournalEntry, StoreError> {
        self.entries
            .iter()
            .find(|entry| entry.operation_id == operation_id)
            .ok_or(StoreError::Unknown)
    }

    fn open_entries(&self) -> Vec<&JournalEntry> {
        self.entries
            .iter()
            .filter(|entry| !entry.state.is_terminal())
            .collect()
    }
}

/// Every journal state, in its on-disk tag order.
const STATES: [OperationState; 14] = [
    OperationState::None,
    OperationState::Requested,
    OperationState::AwaitingConsent,
    OperationState::Prepared,
    OperationState::Committed,
    OperationState::Executing,
    OperationState::ResultPending,
    OperationState::Completed,
    OperationState::Denied,
    OperationState::Cancelled,
    OperationState::Rejected,
    OperationState::CredentialRejected,
    OperationState::Ambiguous,
    OperationState::DeliveryUncertain,
];

fn state_tag(state: OperationState) -> u8 {
    let index = STATES
        .iter()
        .position(|candidate| *candidate == state)
        .unwrap_or_default();
    u8::try_from(index).unwrap_or_default()
}

fn encode_entry(entry: &JournalEntry) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ENTRY_MAGIC);
    out.push(ENTRY_VERSION);
    out.extend_from_slice(entry.operation_id.as_bytes());
    out.extend_from_slice(entry.pair_id.as_bytes());
    out.extend_from_slice(&entry.request_hash);
    out.push(state_tag(entry.state));
    out.push(if entry.retry_prohibited {
        BOOLEAN_TRUE
    } else {
        BOOLEAN_FALSE
    });
    put_text(&mut out, &entry.profile);
    put_text(&mut out, &entry.action);
    match &entry.reconciled_proxy_state {
        Some(state) => {
            out.push(PRESENT);
            put_text(&mut out, state);
        }
        None => out.push(ABSENT),
    }
    out
}

fn put_text(out: &mut Vec<u8>, text: &str) {
    let length = u32::try_from(text.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(text.as_bytes());
}

/// Why a journal entry file could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecodeError {
    Malformed,
}

fn decode_entry(bytes: &[u8]) -> Result<JournalEntry, DecodeError> {
    let mut reader = Reader { bytes, offset: 0 };
    if reader.take(ENTRY_MAGIC.len())? != ENTRY_MAGIC || reader.byte()? != ENTRY_VERSION {
        return Err(DecodeError::Malformed);
    }
    let operation_id = OperationId::from_array(reader.array()?);
    let pair_id = PairId::from_array(reader.array()?);
    let request_hash = reader.array()?;
    let state = *STATES
        .get(usize::from(reader.byte()?))
        .ok_or(DecodeError::Malformed)?;
    let retry_prohibited = match reader.byte()? {
        BOOLEAN_FALSE => false,
        BOOLEAN_TRUE => true,
        _ => return Err(DecodeError::Malformed),
    };
    let profile = reader.text()?;
    let action = reader.text()?;
    let reconciled_proxy_state = match reader.byte()? {
        ABSENT => None,
        PRESENT => Some(reader.text()?),
        _ => return Err(DecodeError::Malformed),
    };
    if reader.offset != bytes.len() {
        return Err(DecodeError::Malformed);
    }
    Ok(JournalEntry {
        operation_id,
        pair_id,
        request_hash,
        profile,
        action,
        state,
        retry_prohibited,
        reconciled_proxy_state,
    })
}

struct Reader<'bytes> {
    bytes: &'bytes [u8],
    offset: usize,
}

impl<'bytes> Reader<'bytes> {
    fn take(&mut self, length: usize) -> Result<&'bytes [u8], DecodeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DecodeError::Malformed)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(DecodeError::Malformed)?;
        self.offset = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], DecodeError> {
        self.take(LENGTH)?
            .try_into()
            .map_err(|_| DecodeError::Malformed)
    }

    fn text(&mut self) -> Result<String, DecodeError> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| DecodeError::Malformed)?;
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::Malformed)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::{FileOperationJournal, decode_entry, encode_entry};
    use crate::ids::{OperationId, PairId};
    use crate::store::{JournalEntry, OperationJournal, OperationState};

    fn scratch(label: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "refineid-journal-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        directory
    }

    fn entry(byte: u8, action: &str, state: OperationState) -> JournalEntry {
        JournalEntry {
            operation_id: OperationId::from_array([byte; 16]),
            pair_id: PairId::from_array([0x11; 16]),
            request_hash: [byte; 32],
            profile: "fi.refineid.authentication.v1".to_owned(),
            action: action.to_owned(),
            state,
            retry_prohibited: false,
            reconciled_proxy_state: None,
        }
    }

    #[test]
    fn entries_round_trip_and_reject_damage() {
        let mut original = entry(3, "sign_document", OperationState::Completed);
        original.reconciled_proxy_state = Some("Completed".to_owned());
        let bytes = encode_entry(&original);
        let decoded = decode_entry(&bytes).unwrap();
        assert_eq!(decoded.operation_id, original.operation_id);
        assert_eq!(decoded.state, original.state);
        assert_eq!(
            decoded.reconciled_proxy_state,
            original.reconciled_proxy_state
        );
        assert!(decode_entry(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_entry(&trailing).is_err());
    }

    #[test]
    fn an_interrupted_consequential_request_survives_restart_as_ambiguous() {
        let directory = scratch("restart");
        {
            let mut journal = FileOperationJournal::open(&directory).unwrap();
            journal
                .record(entry(1, "browser_authenticate", OperationState::Committed))
                .unwrap();
            journal
                .record(entry(2, "inspect_card", OperationState::Requested))
                .unwrap();
            journal
                .record(entry(4, "sign_document", OperationState::Completed))
                .unwrap();
        }
        let journal = FileOperationJournal::open(&directory).unwrap();
        let signed = journal.get(OperationId::from_array([1; 16])).unwrap();
        assert_eq!(signed.state, OperationState::Ambiguous);
        assert!(signed.retry_prohibited);
        assert_eq!(
            journal.get(OperationId::from_array([2; 16])).unwrap().state,
            OperationState::Cancelled
        );
        assert_eq!(
            journal.get(OperationId::from_array([4; 16])).unwrap().state,
            OperationState::Completed
        );
        assert!(journal.open_entries().is_empty());
        let unreconciled = journal.unreconciled(PairId::from_array([0x11; 16]));
        assert_eq!(unreconciled.len(), 1);
        assert_eq!(
            unreconciled[0].operation_id,
            OperationId::from_array([1; 16])
        );

        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&directory), 0o700);
        for file in std::fs::read_dir(&directory).unwrap() {
            assert_eq!(mode(&file.unwrap().path()), 0o600);
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn forgetting_a_pair_removes_its_entries() {
        let directory = scratch("forget");
        let mut journal = FileOperationJournal::open(&directory).unwrap();
        journal
            .record(entry(5, "sign_document", OperationState::Ambiguous))
            .unwrap();
        journal.forget_pair(PairId::from_array([0x11; 16])).unwrap();
        assert!(journal.get(OperationId::from_array([5; 16])).is_err());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
        let reopened = FileOperationJournal::open(&directory).unwrap();
        assert!(reopened.get(OperationId::from_array([5; 16])).is_err());
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
