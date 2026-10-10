//! Pair private keys in the desktop's secret store.
//!
//! RAPP v26.10.9 section 4.3.4 keeps each pairing's static private key in
//! platform-encrypted secure storage. On Linux and the BSDs that is the
//! freedesktop Secret Service (GNOME Keyring, `KWallet`, `KeePassXC`). This
//! module reaches it through `secret-tool`, the libsecret command-line
//! client, instead of a D-Bus client library: the workspace gains no
//! dependency, and the key crosses only the tool's standard input and
//! output pipes, never its argument list. Without a reachable Secret
//! Service every call fails closed; no key ever falls back to a file.

use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

use crate::ids::PairId;

/// Bytes in one pair-specific X25519 private key.
pub const PAIR_PRIVATE_KEY_SIZE: usize = 32;

/// The Secret Service attribute naming the application.
const APPLICATION_ATTRIBUTE: &str = "application";
/// The application attribute value.
const APPLICATION: &str = "fi.refineid.rapp";
/// The Secret Service attribute naming the pairing.
const PAIR_ATTRIBUTE: &str = "pair_id";
/// The label the desktop's keyring manager shows.
const ITEM_LABEL: &str = "RefineID paired phone key";
/// The libsecret command-line client.
const SECRET_TOOL: &str = "secret-tool";

/// Why the secret store refused a key operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyVaultError {
    /// No Secret Service is reachable, or it refused the request (for
    /// example a locked keyring the user did not unlock).
    Unavailable,
    /// The store holds no key for the pairing.
    Missing,
    /// The stored value is not a key.
    Malformed,
}

/// Where pair private keys live.
pub trait KeyVault: core::fmt::Debug {
    /// Stores `key` for `pair_id`, replacing any earlier key.
    ///
    /// # Errors
    /// [`KeyVaultError::Unavailable`] when the store refuses the write.
    fn store(
        &self,
        pair_id: PairId,
        key: &[u8; PAIR_PRIVATE_KEY_SIZE],
    ) -> Result<(), KeyVaultError>;

    /// Loads the key for `pair_id`.
    ///
    /// # Errors
    /// [`KeyVaultError`] when the store is unreachable, holds no key, or
    /// holds something else.
    fn load(
        &self,
        pair_id: PairId,
    ) -> Result<Zeroizing<[u8; PAIR_PRIVATE_KEY_SIZE]>, KeyVaultError>;

    /// Removes the key for `pair_id`; a missing key is not an error.
    ///
    /// # Errors
    /// [`KeyVaultError::Unavailable`] when the store refuses the request.
    fn remove(&self, pair_id: PairId) -> Result<(), KeyVaultError>;
}

impl<Vault: KeyVault + ?Sized> KeyVault for std::sync::Arc<Vault> {
    fn store(
        &self,
        pair_id: PairId,
        key: &[u8; PAIR_PRIVATE_KEY_SIZE],
    ) -> Result<(), KeyVaultError> {
        (**self).store(pair_id, key)
    }

    fn load(
        &self,
        pair_id: PairId,
    ) -> Result<Zeroizing<[u8; PAIR_PRIVATE_KEY_SIZE]>, KeyVaultError> {
        (**self).load(pair_id)
    }

    fn remove(&self, pair_id: PairId) -> Result<(), KeyVaultError> {
        (**self).remove(pair_id)
    }
}

/// The freedesktop Secret Service, through `secret-tool`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretServiceVault;

impl SecretServiceVault {
    fn command(pair_id: PairId) -> (Command, String) {
        let mut command = Command::new(SECRET_TOOL);
        command.stderr(Stdio::null());
        (command, hex(pair_id.as_bytes()))
    }
}

impl KeyVault for SecretServiceVault {
    fn store(
        &self,
        pair_id: PairId,
        key: &[u8; PAIR_PRIVATE_KEY_SIZE],
    ) -> Result<(), KeyVaultError> {
        let (mut command, pair) = Self::command(pair_id);
        let mut child = command
            .args([
                "store",
                "--label",
                ITEM_LABEL,
                APPLICATION_ATTRIBUTE,
                APPLICATION,
                PAIR_ATTRIBUTE,
                &pair,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .map_err(|_| KeyVaultError::Unavailable)?;
        let encoded = Zeroizing::new(hex(key));
        let written = child
            .stdin
            .take()
            .ok_or(KeyVaultError::Unavailable)
            .and_then(|mut input| {
                input
                    .write_all(encoded.as_bytes())
                    .map_err(|_| KeyVaultError::Unavailable)
            });
        let status = child.wait().map_err(|_| KeyVaultError::Unavailable)?;
        written?;
        if status.success() {
            Ok(())
        } else {
            Err(KeyVaultError::Unavailable)
        }
    }

    fn load(
        &self,
        pair_id: PairId,
    ) -> Result<Zeroizing<[u8; PAIR_PRIVATE_KEY_SIZE]>, KeyVaultError> {
        let (mut command, pair) = Self::command(pair_id);
        let mut child = command
            .args([
                "lookup",
                APPLICATION_ATTRIBUTE,
                APPLICATION,
                PAIR_ATTRIBUTE,
                &pair,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| KeyVaultError::Unavailable)?;
        let mut output = Zeroizing::new(Vec::new());
        let read = child
            .stdout
            .take()
            .ok_or(KeyVaultError::Unavailable)
            .and_then(|mut stdout| {
                stdout
                    .read_to_end(&mut output)
                    .map_err(|_| KeyVaultError::Unavailable)
            });
        let status = child.wait().map_err(|_| KeyVaultError::Unavailable)?;
        read?;
        if !status.success() {
            // secret-tool exits non-zero both when nothing matches and when
            // the service is unreachable; an empty answer is the former.
            return Err(if output.is_empty() {
                KeyVaultError::Missing
            } else {
                KeyVaultError::Unavailable
            });
        }
        decode_key(&output)
    }

    fn remove(&self, pair_id: PairId) -> Result<(), KeyVaultError> {
        let (mut command, pair) = Self::command(pair_id);
        let status = command
            .args([
                "clear",
                APPLICATION_ATTRIBUTE,
                APPLICATION,
                PAIR_ATTRIBUTE,
                &pair,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .map_err(|_| KeyVaultError::Unavailable)?;
        if status.success() {
            return Ok(());
        }
        // secret-tool also exits non-zero when nothing matched; a key that
        // is already gone is removed.
        match self.load(pair_id) {
            Err(KeyVaultError::Missing) => Ok(()),
            _ => Err(KeyVaultError::Unavailable),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Reads the stored lowercase hex, tolerating one trailing newline.
fn decode_key(output: &[u8]) -> Result<Zeroizing<[u8; PAIR_PRIVATE_KEY_SIZE]>, KeyVaultError> {
    let text = output.strip_suffix(b"\n").unwrap_or(output);
    if text.len() != 2 * PAIR_PRIVATE_KEY_SIZE {
        return Err(KeyVaultError::Malformed);
    }
    let mut key = Zeroizing::new([0_u8; PAIR_PRIVATE_KEY_SIZE]);
    for (index, byte) in key.iter_mut().enumerate() {
        let pair = text
            .get(2 * index..2 * index + 2)
            .ok_or(KeyVaultError::Malformed)?;
        let digits = core::str::from_utf8(pair).map_err(|_| KeyVaultError::Malformed)?;
        if !digits
            .bytes()
            .all(|digit| digit.is_ascii_digit() || (b'a'..=b'f').contains(&digit))
        {
            return Err(KeyVaultError::Malformed);
        }
        *byte = u8::from_str_radix(digits, 16).map_err(|_| KeyVaultError::Malformed)?;
    }
    Ok(key)
}

/// The keys one [`MemoryKeyVault`] holds.
type HeldKeys = Vec<(PairId, Zeroizing<[u8; PAIR_PRIVATE_KEY_SIZE]>)>;

/// An in-process vault for tests and for composing stores without a
/// desktop session. Keys live only as long as the value.
#[derive(Debug, Default)]
pub struct MemoryKeyVault {
    keys: std::sync::Mutex<HeldKeys>,
    unavailable: bool,
}

impl MemoryKeyVault {
    /// A vault that refuses every call, as an unreachable Secret Service
    /// does.
    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            keys: std::sync::Mutex::default(),
            unavailable: true,
        }
    }

    fn keys(&self) -> Result<std::sync::MutexGuard<'_, HeldKeys>, KeyVaultError> {
        if self.unavailable {
            return Err(KeyVaultError::Unavailable);
        }
        self.keys.lock().map_err(|_| KeyVaultError::Unavailable)
    }
}

impl KeyVault for MemoryKeyVault {
    fn store(
        &self,
        pair_id: PairId,
        key: &[u8; PAIR_PRIVATE_KEY_SIZE],
    ) -> Result<(), KeyVaultError> {
        let mut keys = self.keys()?;
        keys.retain(|(stored, _)| *stored != pair_id);
        keys.push((pair_id, Zeroizing::new(*key)));
        Ok(())
    }

    fn load(
        &self,
        pair_id: PairId,
    ) -> Result<Zeroizing<[u8; PAIR_PRIVATE_KEY_SIZE]>, KeyVaultError> {
        self.keys()?
            .iter()
            .find(|(stored, _)| *stored == pair_id)
            .map(|(_, key)| key.clone())
            .ok_or(KeyVaultError::Missing)
    }

    fn remove(&self, pair_id: PairId) -> Result<(), KeyVaultError> {
        self.keys()?.retain(|(stored, _)| *stored != pair_id);
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use super::{KeyVault, KeyVaultError, MemoryKeyVault, decode_key, hex};
    use crate::ids::PairId;

    #[test]
    fn stored_hex_decodes_and_damage_is_refused() {
        let key = [0xa5_u8; 32];
        let mut text = hex(&key).into_bytes();
        assert_eq!(*decode_key(&text).unwrap(), key);
        text.push(b'\n');
        assert_eq!(*decode_key(&text).unwrap(), key);
        assert_eq!(decode_key(b"a5").unwrap_err(), KeyVaultError::Malformed);
        let upper = hex(&key).to_ascii_uppercase();
        assert_eq!(
            decode_key(upper.as_bytes()).unwrap_err(),
            KeyVaultError::Malformed
        );
    }

    #[test]
    fn the_memory_vault_stores_replaces_and_removes() {
        let vault = MemoryKeyVault::default();
        let pair = PairId::from_array([3; 16]);
        assert_eq!(vault.load(pair).unwrap_err(), KeyVaultError::Missing);
        vault.store(pair, &[1; 32]).unwrap();
        vault.store(pair, &[2; 32]).unwrap();
        assert_eq!(*vault.load(pair).unwrap(), [2; 32]);
        vault.remove(pair).unwrap();
        assert_eq!(vault.load(pair).unwrap_err(), KeyVaultError::Missing);
        let refusing = MemoryKeyVault::unavailable();
        assert_eq!(
            refusing.store(pair, &[1; 32]).unwrap_err(),
            KeyVaultError::Unavailable
        );
    }

    /// Runs against the desktop's real Secret Service: `cargo test -p
    /// refineid-rapp-core -- --ignored secret_service`. It uses a random
    /// pair identifier and removes its item, so stored pairings are
    /// untouched.
    #[test]
    #[ignore = "needs secret-tool and an unlocked Secret Service keyring"]
    fn the_secret_service_round_trips_a_key() {
        let vault = super::SecretServiceVault;
        let mut pair = [0_u8; 16];
        getrandom::fill(&mut pair).unwrap();
        let pair = PairId::from_array(pair);
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).unwrap();
        assert_eq!(vault.load(pair).unwrap_err(), KeyVaultError::Missing);
        vault.store(pair, &key).unwrap();
        assert_eq!(*vault.load(pair).unwrap(), key);
        let mut replacement = key;
        replacement[0] ^= 0xff;
        vault.store(pair, &replacement).unwrap();
        assert_eq!(*vault.load(pair).unwrap(), replacement);
        vault.remove(pair).unwrap();
        assert_eq!(vault.load(pair).unwrap_err(), KeyVaultError::Missing);
        vault.remove(pair).unwrap();
    }
}
