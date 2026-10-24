//! One program at a time on a phone: an advisory lock beside the pairing
//! records.
//!
//! A pairing has one key and the phone serves one stream for it, so two
//! programs on this computer cannot both hold a session to the same
//! phone. The lock is a file next to the pairing record, held with the
//! operating system's advisory file lock for as long as the session is
//! open, and released when the holder drops it or exits. A pairing
//! ceremony holds one lock for the whole store, since its pairing has no
//! identifier until the ceremony ends.

use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use crate::ids::PairId;

/// The extension of a lock file.
const LOCK_EXTENSION: &str = "lock";
/// The name of the lock a pairing ceremony holds.
const CEREMONY_LOCK_NAME: &str = "pairing";
/// Owner-only file permissions.
const LOCK_FILE_MODE: u32 = 0o600;

/// Why a lock could not be taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockError {
    /// Another program on this computer holds the lock.
    Held,
    /// The lock file could not be created or opened.
    Unavailable,
}

/// An advisory lock held for one session or one pairing ceremony; the
/// lock is released when the value is dropped.
#[derive(Debug)]
pub struct SessionLock {
    _file: File,
}

impl SessionLock {
    /// Takes the lock at `path` without waiting.
    ///
    /// # Errors
    /// [`LockError::Held`] when another holder has it, and
    /// [`LockError::Unavailable`] when the file cannot be opened.
    pub fn acquire(path: &Path) -> Result<Self, LockError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(LOCK_FILE_MODE)
            .open(path)
            .map_err(|_| LockError::Unavailable)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => Err(LockError::Held),
            Err(TryLockError::Error(_)) => Err(LockError::Unavailable),
        }
    }
}

/// The lock file of the session to `pair_id`, beside its record in
/// `directory`.
#[must_use]
pub fn session_lock_path(directory: &Path, pair_id: PairId) -> PathBuf {
    let mut name = String::with_capacity(pair_id.as_bytes().len() * 2);
    for byte in pair_id.as_bytes() {
        use core::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    directory.join(name).with_extension(LOCK_EXTENSION)
}

/// The lock file of a pairing ceremony in `directory`.
#[must_use]
pub fn ceremony_lock_path(directory: &Path) -> PathBuf {
    directory
        .join(CEREMONY_LOCK_NAME)
        .with_extension(LOCK_EXTENSION)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::time::Duration;

    use super::{LockError, SessionLock, ceremony_lock_path, session_lock_path};
    use crate::ids::PairId;

    /// The pause between looks at a lock its holder has dropped.
    const RELEASE_STEP: Duration = Duration::from_millis(5);
    /// How many looks a dropped lock is given before it counts as held.
    const RELEASE_LOOKS: usize = 50;

    fn scratch() -> std::path::PathBuf {
        let mut name = [0u8; 8];
        getrandom::fill(&mut name).unwrap();
        let suffix: String = name.iter().map(|b| format!("{b:02x}")).collect();
        let directory = std::env::temp_dir().join(format!("refineid-rapp-lock-{suffix}"));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    /// Takes the lock at `path` once the kernel has released it. A child
    /// another test forks inherits the open file description until it
    /// execs, so the release can trail the drop by a moment.
    fn acquire_eventually(path: &Path) -> Result<SessionLock, LockError> {
        let mut outcome = SessionLock::acquire(path);
        for _ in 1..RELEASE_LOOKS {
            if !matches!(outcome, Err(LockError::Held)) {
                break;
            }
            std::thread::sleep(RELEASE_STEP);
            outcome = SessionLock::acquire(path);
        }
        outcome
    }

    #[test]
    fn a_held_lock_refuses_a_second_holder_until_it_is_dropped() {
        let directory = scratch();
        let path = session_lock_path(&directory, PairId::from_array([0x5A; 16]));
        let first = SessionLock::acquire(&path).unwrap();
        assert_eq!(SessionLock::acquire(&path).err(), Some(LockError::Held));
        drop(first);
        assert!(acquire_eventually(&path).is_ok());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn the_lock_file_is_owner_only_and_named_after_the_pairing() {
        let directory = scratch();
        let path = session_lock_path(&directory, PairId::from_array([0xAB; 16]));
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("abababababababababababababababab.lock")
        );
        let _held = SessionLock::acquire(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            ceremony_lock_path(&directory)
                .file_name()
                .and_then(|name| name.to_str()),
            Some("pairing.lock")
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_lock_in_a_missing_directory_is_unavailable() {
        let path = scratch().join("missing").join("x.lock");
        assert_eq!(
            SessionLock::acquire(&path).err(),
            Some(LockError::Unavailable)
        );
    }
}
