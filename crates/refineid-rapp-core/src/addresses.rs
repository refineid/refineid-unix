//! The addresses a paired phone last answered from, remembered beside its
//! pairing record.
//!
//! Discovery asks the local network for the phone by multicast, which a
//! wireless network delivers unreliably: a phone in power save misses
//! many of the queries a computer on the same network sends. A query sent
//! to the phone's own address is answered whenever the phone is reachable
//! at all, so every browse for a pairing also asks the addresses the phone
//! answered from before. The addresses are a cache: losing them costs a
//! slower discovery, never a pairing.

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::ids::PairId;

/// File name extension beside the pairing record.
const ADDRESSES_EXTENSION: &str = "addresses";
/// Owner-only, like the records.
const FILE_MODE: u32 = 0o600;
/// How many addresses are kept per pairing, most recent first.
const REMEMBERED_ADDRESSES: usize = 3;

/// The addresses the phone holding `pair_id` last answered from, most
/// recent first; empty when none is remembered or the file is unreadable.
#[must_use]
pub fn remembered(directory: &Path, pair_id: PairId) -> Vec<Ipv4Addr> {
    let Ok(text) = fs::read_to_string(path_for(directory, pair_id)) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| line.trim().parse().ok())
        .take(REMEMBERED_ADDRESSES)
        .collect()
}

/// Records `address` as the latest the phone holding `pair_id` answered
/// from. A write the file system refuses leaves the cache as it was.
pub fn remember(directory: &Path, pair_id: PairId, address: Ipv4Addr) {
    let mut addresses = remembered(directory, pair_id);
    addresses.retain(|known| *known != address);
    addresses.insert(0, address);
    addresses.truncate(REMEMBERED_ADDRESSES);
    let path = path_for(directory, pair_id);
    let text: String = addresses
        .iter()
        .map(|address| format!("{address}\n"))
        .collect();
    let _ = crate::file_store::write_atomically(&path, text.as_bytes(), FILE_MODE);
}

/// Drops what is remembered for `pair_id`.
pub fn forget(directory: &Path, pair_id: PairId) {
    let _ = fs::remove_file(path_for(directory, pair_id));
}

fn path_for(directory: &Path, pair_id: PairId) -> PathBuf {
    let mut name = String::with_capacity(pair_id.as_bytes().len() * 2);
    for byte in pair_id.as_bytes() {
        use core::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    directory.join(name).with_extension(ADDRESSES_EXTENSION)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{forget, remember, remembered};
    use crate::ids::PairId;

    fn scratch() -> std::path::PathBuf {
        let mut name = [0u8; 8];
        getrandom::fill(&mut name).unwrap();
        let suffix: String = name.iter().map(|b| format!("{b:02x}")).collect();
        let directory = std::env::temp_dir().join(format!("refineid-rapp-addresses-{suffix}"));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn the_latest_address_comes_first_and_the_list_stays_short() {
        let directory = scratch();
        let pair_id = PairId::from_array([7; 16]);
        assert!(remembered(&directory, pair_id).is_empty());
        for last in 1..=5u8 {
            remember(&directory, pair_id, Ipv4Addr::new(192, 0, 2, last));
        }
        remember(&directory, pair_id, Ipv4Addr::new(192, 0, 2, 4));
        assert_eq!(
            remembered(&directory, pair_id),
            vec![
                Ipv4Addr::new(192, 0, 2, 4),
                Ipv4Addr::new(192, 0, 2, 5),
                Ipv4Addr::new(192, 0, 2, 3),
            ]
        );
        forget(&directory, pair_id);
        assert!(remembered(&directory, pair_id).is_empty());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_record_for_another_pairing_is_not_read() {
        let directory = scratch();
        remember(
            &directory,
            PairId::from_array([1; 16]),
            Ipv4Addr::new(192, 0, 2, 1),
        );
        assert!(remembered(&directory, PairId::from_array([2; 16])).is_empty());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn remember_does_not_follow_or_truncate_a_planted_tmp_symlink() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = scratch();
        let pair_id = PairId::from_array([9; 16]);
        let victim = directory.join("victim.txt");
        std::fs::write(&victim, b"untouched").unwrap();
        let planted = super::path_for(&directory, pair_id).with_extension("tmp");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        remember(&directory, pair_id, Ipv4Addr::new(192, 0, 2, 42));

        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(std::fs::symlink_metadata(&planted).is_ok());
        assert_eq!(
            remembered(&directory, pair_id),
            vec![Ipv4Addr::new(192, 0, 2, 42)]
        );
        let mode = std::fs::metadata(super::path_for(&directory, pair_id))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
