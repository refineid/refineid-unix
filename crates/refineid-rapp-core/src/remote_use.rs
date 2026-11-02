//! The position of this computer's remote-use switch, stored beside the
//! pairing records (RAPP transport and discovery hierarchy specification
//! section 5.2).
//!
//! Only the holder's own click moves the switch. Its position survives a
//! quit, a restart and an update, and a launch restores it; a pairing that
//! ends without the holder's word leaves it as it is. The switch is on
//! while its marker file exists in the store's directory.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;

/// The marker file whose presence says the switch is on.
const SWITCH_ON_FILE: &str = "remote-use-on";
/// Owner-only, like the records.
const FILE_MODE: u32 = 0o600;
/// Owner-only, like the store.
const DIRECTORY_MODE: u32 = 0o700;

/// Whether the switch stored in `directory` is on; a directory that does
/// not exist or cannot be read says off.
#[must_use]
pub fn is_on(directory: &Path) -> bool {
    directory.join(SWITCH_ON_FILE).is_file()
}

/// Stores the switch in `directory` as the holder set it.
///
/// # Errors
/// The file system's error when the marker cannot be written or removed.
pub fn store(directory: &Path, on: bool) -> std::io::Result<()> {
    let marker = directory.join(SWITCH_ON_FILE);
    if on {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIRECTORY_MODE)
            .create(directory)?;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(marker)
            .map(drop)
    } else {
        match fs::remove_file(marker) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use super::{is_on, store};

    #[test]
    fn the_switch_keeps_the_position_it_was_given() {
        let directory = std::env::temp_dir().join(format!(
            "refineid-remote-use-{}-{}",
            std::process::id(),
            line!()
        ));
        assert!(!is_on(&directory));
        store(&directory, true).unwrap();
        assert!(is_on(&directory));
        store(&directory, true).unwrap();
        assert!(is_on(&directory));
        store(&directory, false).unwrap();
        assert!(!is_on(&directory));
        store(&directory, false).unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
