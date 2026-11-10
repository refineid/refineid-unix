// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The SCS localhost TLS identity: a P-256 key and its self-signed
//! certificate, generated once and reused so browser trust survives
//! restarts.
//!
//! Each file is written atomically (temporary file, `fsync`, rename)
//! with mode `0600` inside a `0700` directory. Nothing here prints or
//! logs the key; the certificate's fingerprint is shown once, when the
//! identity is generated, so the operator knows which certificate the
//! browser must be told to trust.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

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
/// The identity's directory under the application's.
const STORE_DIRECTORY: &str = "scs-identity";
/// The private key file: PKCS#8 DER.
const KEY_FILE: &str = "key.p8";
/// The certificate file: DER.
const CERT_FILE: &str = "cert.der";
/// Suffix of a file being written.
const TEMPORARY_SUFFIX: &str = ".tmp";
/// Owner-only directory permissions.
const DIRECTORY_MODE: u32 = 0o700;
/// Owner-only file permissions.
const FILE_MODE: u32 = 0o600;
/// Length of a P-256 secret, in bytes.
const SECRET_LENGTH: usize = 32;
/// Length of the certificate serial number, in bytes.
const SERIAL_LENGTH: usize = 8;
/// Bytes per group in a printed fingerprint.
const FINGERPRINT_GROUP_BYTES: usize = 4;

/// The localhost identity: the TLS key and certificate.
pub struct ScsIdentity {
    /// The DER certificate the server presents.
    pub cert_der: Vec<u8>,
    /// The P-256 signing key.
    pub key: p256::ecdsa::SigningKey,
}

impl core::fmt::Debug for ScsIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ScsIdentity").finish_non_exhaustive()
    }
}

/// An obtained identity and whether it was just generated.
pub struct ObtainedIdentity {
    /// The identity.
    pub identity: ScsIdentity,
    /// Whether this call generated the identity rather than loading
    /// it; the caller tells the operator on a first generation.
    pub generated: bool,
    /// The directory holding the identity files.
    pub directory: PathBuf,
}

impl core::fmt::Debug for ObtainedIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObtainedIdentity")
            .field("generated", &self.generated)
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

/// Why the identity cannot be obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// No home directory to store the identity under.
    NoHome,
    /// The store cannot be read or written.
    StoreUnusable(String),
    /// The stored key does not parse.
    KeyUnusable,
    /// The system clock cannot be read.
    ClockUnusable,
    /// Randomness cannot be drawn.
    RandomUnusable,
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoHome => f.write_str("no home directory for the SCS identity"),
            Self::StoreUnusable(detail) => write!(f, "SCS identity store unusable: {detail}"),
            Self::KeyUnusable => f.write_str("SCS identity key does not parse"),
            Self::ClockUnusable => f.write_str("system clock cannot be read"),
            Self::RandomUnusable => f.write_str("randomness unavailable"),
        }
    }
}

impl core::error::Error for IdentityError {}

/// The per-user directory: `$XDG_CONFIG_HOME/refineid/scs-identity`,
/// or `$HOME/.config/refineid/scs-identity`. Under a Snap the
/// user-common directory replaces the home directory. A variable that
/// is unset, empty or relative does not count; `None` when none
/// counts.
#[must_use]
pub fn default_directory() -> Option<PathBuf> {
    directory_from(|name| std::env::var_os(name))
}

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

/// Load the identity from the default directory, generating and
/// storing one when none is there.
///
/// # Errors
/// [`IdentityError`] when no home exists, the store cannot be read or
/// written, the stored key does not parse, the clock cannot be read,
/// or randomness cannot be drawn.
pub fn obtain() -> Result<ObtainedIdentity, IdentityError> {
    let Some(directory) = default_directory() else {
        return Err(IdentityError::NoHome);
    };
    obtain_in(&directory)
}

/// Load the identity from `directory`, generating and storing one
/// when none is there.
///
/// # Errors
/// [`IdentityError`] when the store cannot be read or written, the
/// stored key does not parse, the clock cannot be read, or randomness
/// cannot be drawn.
pub fn obtain_in(directory: &Path) -> Result<ObtainedIdentity, IdentityError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIRECTORY_MODE)
        .create(directory)
        .map_err(|error| IdentityError::StoreUnusable(format!("create directory: {error}")))?;
    if let Some(identity) = load(directory)? {
        return Ok(ObtainedIdentity {
            identity,
            generated: false,
            directory: directory.to_path_buf(),
        });
    }
    let identity = generate()?;
    let encoded_key = {
        use pkcs8::EncodePrivateKey as _;
        identity
            .key
            .to_pkcs8_der()
            .map_err(|_| IdentityError::StoreUnusable("encode private key".to_owned()))?
    };
    write_blob(directory, KEY_FILE, encoded_key.as_bytes())?;
    write_blob(directory, CERT_FILE, &identity.cert_der)?;
    Ok(ObtainedIdentity {
        identity,
        generated: true,
        directory: directory.to_path_buf(),
    })
}

/// Load the stored identity, or `None` when either file is missing.
///
/// # Errors
/// [`IdentityError::KeyUnusable`] when the files are present but the
/// key does not parse; [`IdentityError::StoreUnusable`] when a file
/// cannot be read.
fn load(directory: &Path) -> Result<Option<ScsIdentity>, IdentityError> {
    use pkcs8::DecodePrivateKey as _;
    let key_path = directory.join(KEY_FILE);
    let cert_path = directory.join(CERT_FILE);
    if !key_path.is_file() || !cert_path.is_file() {
        return Ok(None);
    }
    let key_der = fs::read(&key_path)
        .map_err(|error| IdentityError::StoreUnusable(format!("read key: {error}")))?;
    let cert_der = fs::read(&cert_path)
        .map_err(|error| IdentityError::StoreUnusable(format!("read certificate: {error}")))?;
    if cert_der.is_empty() {
        return Err(IdentityError::KeyUnusable);
    }
    let key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_der)
        .map_err(|_| IdentityError::KeyUnusable)?;
    Ok(Some(ScsIdentity { cert_der, key }))
}

/// Generate a fresh identity.
fn generate() -> Result<ScsIdentity, IdentityError> {
    let mut secret = Zeroizing::new([0_u8; SECRET_LENGTH]);
    let key = loop {
        getrandom::fill(&mut *secret).map_err(|_| IdentityError::RandomUnusable)?;
        if let Ok(key) = p256::ecdsa::SigningKey::from_slice(secret.as_slice()) {
            break key;
        }
    };
    let mut serial = [0_u8; SERIAL_LENGTH];
    getrandom::fill(&mut serial).map_err(|_| IdentityError::RandomUnusable)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IdentityError::ClockUnusable)?;
    let not_before = i64::try_from(now.as_secs()).map_err(|_| IdentityError::ClockUnusable)?;
    let point = key.verifying_key().to_sec1_point(false);
    let spki = refineid_scs::localhost::subject_public_key_info(point.as_bytes())
        .map_err(|_| IdentityError::StoreUnusable("encode public key".to_owned()))?;
    let cert_der = refineid_scs::localhost::make(&spki, &serial, not_before, |tbs| {
        use p256::ecdsa::signature::Signer as _;
        let signature: p256::ecdsa::Signature = key.sign(tbs);
        Ok(signature.to_der().as_bytes().to_vec())
    })
    .map_err(|_| IdentityError::StoreUnusable("build certificate".to_owned()))?;
    Ok(ScsIdentity { cert_der, key })
}

/// Write `blob` as `file` in `directory`, atomically.
fn write_blob(directory: &Path, file: &str, blob: &[u8]) -> Result<(), IdentityError> {
    let path = directory.join(file);
    let temporary = directory.join(file.to_owned() + TEMPORARY_SUFFIX);
    let mut handle = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(&temporary)
        .map_err(|error| IdentityError::StoreUnusable(format!("write {file}: {error}")))?;
    handle
        .write_all(blob)
        .and_then(|()| handle.sync_all())
        .map_err(|error| IdentityError::StoreUnusable(format!("write {file}: {error}")))?;
    drop(handle);
    fs::rename(&temporary, &path)
        .map_err(|error| IdentityError::StoreUnusable(format!("write {file}: {error}")))?;
    Ok(())
}

/// The SHA-256 fingerprint of `cert_der` as spaced lowercase hex,
/// grouped for reading.
#[must_use]
pub fn fingerprint_hex(cert_der: &[u8]) -> String {
    grouped_hex(refineid_lib_core::crypto::digest::Sha256::of(cert_der).as_bytes())
}

/// Bytes as spaced lowercase hex, grouped for reading.
pub(crate) fn grouped_hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (index, chunk) in bytes.chunks(FINGERPRINT_GROUP_BYTES).enumerate() {
        if index > 0 {
            out.push(' ');
        }
        for byte in chunk {
            out.push_str(&format!("{byte:02x}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{default_directory, fingerprint_hex, grouped_hex, obtain_in};
    use crate::test_util::{TestResult, check, check_true};

    /// An obtained identity persists: the second obtain loads the
    /// first one's files.
    #[test]
    fn obtain_generates_then_loads() -> TestResult {
        let directory = crate::test_util::TempDir::new("scs-identity")?;
        let first = obtain_in(directory.path())?;
        check_true(first.generated, "first generates")?;
        let second = obtain_in(directory.path())?;
        check_true(!second.generated, "second loads")?;
        check(
            &second.identity.cert_der,
            &first.identity.cert_der,
            "same certificate",
        )?;
        check(
            &second.identity.key.to_bytes(),
            &first.identity.key.to_bytes(),
            "same key",
        )
    }

    /// A corrupt key file refuses the obtain rather than silently
    /// minting a second identity.
    #[test]
    fn corrupt_key_refuses() -> TestResult {
        let directory = crate::test_util::TempDir::new("scs-identity")?;
        let first = obtain_in(directory.path())?;
        check_true(first.generated, "generates")?;
        std::fs::write(directory.path().join("key.p8"), b"not-a-key")?;
        check_true(obtain_in(directory.path()).is_err(), "corrupt key refuses")
    }

    /// The fingerprint prints grouped lowercase hex.
    #[test]
    fn fingerprint_groups() -> TestResult {
        check(
            &grouped_hex(b"abcdefgh"),
            &"61626364 65666768".to_owned(),
            "grouped",
        )?;
        check_true(
            fingerprint_hex(b"certificate").len() > "certificate".len(),
            "SHA-256 is longer than the input",
        )
    }

    /// The default directory resolves under a home.
    #[test]
    fn default_directory_needs_absolute_home() -> TestResult {
        check_true(
            default_directory().is_some() || std::env::var_os("HOME").is_none(),
            "home",
        )?;
        Ok(())
    }
}
