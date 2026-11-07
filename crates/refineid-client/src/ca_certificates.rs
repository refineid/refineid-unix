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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! The card's CA certificates, kept until they expire.
//!
//! refineid-core's `doc/security/certificate-custody.md` rules that
//! the issuing CA (`EF.4336`) and the root (`EF.4334`) a card carries
//! are cached per user until their own validity ends, in storage only
//! the owner can read, and read from the card only when the cache
//! holds no unexpired issuer. Nothing in them is personal.
//!
//! The cache is the directory core's PKCS#11 module already keeps:
//! `$REFINEID_CA_CACHE_DIR` when set, else
//! `$XDG_CACHE_HOME/refineid/ca-certificates/`, else
//! `$HOME/.cache/refineid/ca-certificates/`. One file per certificate,
//! named by the lowercase hex SHA-256 of its DER with the extension
//! `der`, holding the DER alone; the directory is created `0700` and
//! each file `0600`, written to a temporary name and renamed into
//! place. A file that does not parse, is not a CA certificate, is
//! expired or exceeds [`MAX_CERTIFICATE_BYTES`] is removed when found.
//! Core keeps that code private to `crates/pkcs11/src/token.rs`, so
//! the format is mirrored here rather than called: either side reads
//! what the other wrote.
//!
//! A privileged process (effective user root, or one whose effective
//! user or group differs from the real one) has no cache: it may have
//! inherited the environment of an unprivileged caller and must not
//! create or remove files where that caller chose.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use refineid_doc_sign::x509::{Certificate, DateTime, OwnedCert, extract_basic_constraints};
use sha2::{Digest as _, Sha256};

/// The variable that names the cache directory outright.
const CACHE_DIRECTORY_VARIABLE: &str = "REFINEID_CA_CACHE_DIR";
/// The XDG base-directory cache variable.
const XDG_CACHE_HOME: &str = "XDG_CACHE_HOME";
/// The home directory variable.
const HOME: &str = "HOME";
/// The cache directory under a home directory.
const CACHE_DIRECTORY: &str = ".cache";
/// The application's directory under the cache directory.
const APPLICATION_DIRECTORY: &str = "refineid";
/// The certificates' directory under the application's.
const CERTIFICATES_DIRECTORY: &str = "ca-certificates";
/// File extension of one stored certificate.
const CERTIFICATE_EXTENSION: &str = "der";
/// Owner-only directory permissions.
const DIRECTORY_MODE: u32 = 0o700;
/// Owner-only file permissions.
const FILE_MODE: u32 = 0o600;
/// Most certificates read back from the cache.
const MAX_CERTIFICATES: usize = 16;
/// Most directory entries examined to find them.
const MAX_ENTRIES: usize = MAX_CERTIFICATES * 4;
/// Largest file read back as a certificate.
pub const MAX_CERTIFICATE_BYTES: u64 = 65_536;

/// The CA certificates' cache directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaCache {
    /// The directory.
    directory: PathBuf,
}

impl CaCache {
    /// The cache in `directory`.
    #[must_use]
    pub const fn at(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// The per-user cache, or `None` for a privileged process or
    /// when no variable names a directory.
    #[must_use]
    pub fn user() -> Option<Self> {
        if process_is_privileged() {
            return None;
        }
        directory_from(|name| std::env::var_os(name).filter(|value| !value.is_empty()))
            .map(Self::at)
    }

    /// Every stored certificate that is a CA certificate valid at
    /// `now`; a file that is not one is removed.
    #[must_use]
    pub fn load(&self, now: DateTime) -> Vec<OwnedCert> {
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case(CERTIFICATE_EXTENSION))
            })
            .take(MAX_ENTRIES)
            .collect();
        paths.sort();
        let mut certificates = Vec::new();
        for path in paths {
            if certificates.len() >= MAX_CERTIFICATES {
                break;
            }
            match read_certificate(&path, now) {
                Some(certificate) => certificates.push(certificate),
                None => {
                    let _removed = fs::remove_file(&path);
                }
            }
        }
        certificates
    }

    /// Store `certificates`, each under its fingerprint; one already
    /// stored is left as it is.
    ///
    /// # Errors
    /// The I/O error of the first file that could not be written.
    pub fn store(&self, certificates: &[OwnedCert]) -> std::io::Result<()> {
        if certificates.is_empty() {
            return Ok(());
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIRECTORY_MODE)
            .create(&self.directory)?;
        for certificate in certificates {
            let der = certificate.as_der();
            let name = hex::encode(Sha256::digest(der));
            let path = self
                .directory
                .join(name)
                .with_extension(CERTIFICATE_EXTENSION);
            if path.exists() {
                continue;
            }
            write_atomically(&path, der)?;
        }
        Ok(())
    }
}

/// The CA certificates a card supplied that the custody rule admits
/// to the cache: the issuing CA when it is a CA certificate valid at
/// `now`, and the root when it is one too, self-signed, and the
/// verified issuer of that issuing CA.
#[must_use]
pub fn admit(issuing_ca: Option<&[u8]>, root: Option<&[u8]>, now: DateTime) -> Vec<OwnedCert> {
    let mut admitted = Vec::new();
    let Some(issuing_ca) = issuing_ca.and_then(|der| ca_certificate(der, now)) else {
        return admitted;
    };
    if let Some(root) = root.and_then(|der| ca_certificate(der, now)) {
        let root_view = root.view();
        let self_signed = root_view.issuer.as_der() == root_view.subject.as_der()
            && root_view.verify_signed_by(root_view).is_ok();
        if self_signed && issuing_ca.view().verify_signed_by(root_view).is_ok() {
            admitted.push(root);
        }
    }
    admitted.insert(0, issuing_ca);
    admitted
}

/// `der` as a CA certificate valid at `now`, or nothing.
fn ca_certificate(der: &[u8], now: DateTime) -> Option<OwnedCert> {
    let certificate = OwnedCert::from_der(der).ok()?;
    is_ca_valid_at(certificate.view(), now).then_some(certificate)
}

/// Whether `certificate` asserts `basicConstraints` CA and `now` lies
/// in its validity, both ends inclusive (RFC 5280 clauses 4.1.2.5 and
/// 4.2.1.9).
fn is_ca_valid_at(certificate: Certificate<'_>, now: DateTime) -> bool {
    let ca = certificate
        .extensions
        .is_some_and(|extensions| extract_basic_constraints(extensions).ca);
    ca && certificate.not_before <= now && now <= certificate.not_after
}

/// The certificate at `path` when it is a CA certificate valid at
/// `now` in a regular file of admissible size.
fn read_certificate(path: &Path, now: DateTime) -> Option<OwnedCert> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || metadata.len() > MAX_CERTIFICATE_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    ca_certificate(&bytes, now)
}

/// [`CaCache::user`] over the environment `variable` reads.
fn directory_from(variable: impl Fn(&str) -> Option<std::ffi::OsString>) -> Option<PathBuf> {
    if let Some(named) = variable(CACHE_DIRECTORY_VARIABLE) {
        return Some(PathBuf::from(named));
    }
    let cache = variable(XDG_CACHE_HOME)
        .map(PathBuf::from)
        .or_else(|| variable(HOME).map(|home| PathBuf::from(home).join(CACHE_DIRECTORY)))?;
    Some(
        cache
            .join(APPLICATION_DIRECTORY)
            .join(CERTIFICATES_DIRECTORY),
    )
}

/// Whether this process runs as root or with an effective user or
/// group other than its real one.
fn process_is_privileged() -> bool {
    use rustix::process::{getegid, geteuid, getgid, getuid};
    geteuid().is_root() || geteuid() != getuid() || getegid() != getgid()
}

/// Write `bytes` to `path` atomically, owner-only.
///
/// # Errors
/// The I/O error of the write; the temporary file is removed.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "certificate file name",
        ));
    };
    let temporary = path.with_file_name(format!(".{name}.tmp.{}", std::process::id()));
    let written = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _removed = fs::remove_file(&temporary);
    }
    written
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::test_util::{TempDir, TestResult, check, check_true};

    /// The public DVV G3 ECC root: a self-signed CA certificate.
    const ROOT_ECC_DER: &[u8] = include_bytes!("../test-vectors/dvv-gov-root-ca-g3-ecc.der");
    /// The public DVV G3 RSA root: a self-signed CA certificate that
    /// did not issue the G4E intermediate.
    const ROOT_RSA_DER: &[u8] = include_bytes!("../test-vectors/dvv-gov-root-ca-g3-rsa.der");
    /// The DVV G4E issuing CA, issued by the ECC root.
    const ISSUING_CA_DER: &[u8] =
        include_bytes!("../test-vectors/fineid-intermediate-01-citizen-g4e.der");
    /// A day inside every fixture's validity.
    const WITHIN: (u16, u8, u8) = (2026, 6, 1);
    /// A day after every fixture has expired.
    const AFTER: (u16, u8, u8) = (2099, 1, 1);
    /// The permission bits of a mode.
    const PERMISSION_BITS: u32 = 0o777;

    fn at((year, month, day): (u16, u8, u8)) -> Result<DateTime, String> {
        DateTime::new(year, month, day, 0, 0, 0).map_err(|e| format!("date: {e}"))
    }

    fn parse(der: &[u8]) -> Result<OwnedCert, String> {
        OwnedCert::from_der(der).map_err(|e| format!("parse: {e}"))
    }

    #[test]
    fn the_issuing_ca_and_its_root_are_admitted() -> TestResult {
        let admitted = admit(Some(ISSUING_CA_DER), Some(ROOT_ECC_DER), at(WITHIN)?);
        check(&admitted.len(), &2, "both admitted")?;
        check_true(
            admitted
                .first()
                .is_some_and(|c| c.as_der() == ISSUING_CA_DER),
            "the issuing CA first",
        )?;
        check_true(
            admitted.get(1).is_some_and(|c| c.as_der() == ROOT_ECC_DER),
            "its root second",
        )
    }

    #[test]
    fn a_root_that_did_not_issue_the_issuing_ca_is_not_admitted() -> TestResult {
        let admitted = admit(Some(ISSUING_CA_DER), Some(ROOT_RSA_DER), at(WITHIN)?);
        check(&admitted.len(), &1, "the issuing CA alone")?;
        check_true(
            admitted
                .first()
                .is_some_and(|c| c.as_der() == ISSUING_CA_DER),
            "the issuing CA",
        )
    }

    #[test]
    fn a_root_without_an_issuing_ca_beside_it_is_not_admitted() -> TestResult {
        check_true(
            admit(None, Some(ROOT_ECC_DER), at(WITHIN)?).is_empty(),
            "nothing admitted",
        )
    }

    #[test]
    fn an_expired_certificate_is_not_admitted() -> TestResult {
        check_true(
            admit(Some(ISSUING_CA_DER), Some(ROOT_ECC_DER), at(AFTER)?).is_empty(),
            "nothing admitted",
        )
    }

    #[test]
    fn stored_certificates_load_back_under_owner_only_modes() -> TestResult {
        let dir = TempDir::new("ca-certificates-store")?;
        let cache = CaCache::at(dir.path().join(CERTIFICATES_DIRECTORY));
        let certificates = vec![parse(ISSUING_CA_DER)?, parse(ROOT_ECC_DER)?];
        cache.store(&certificates)?;
        cache.store(&certificates)?;
        let directory = dir.path().join(CERTIFICATES_DIRECTORY);
        check(
            &(fs::metadata(&directory)?.permissions().mode() & PERMISSION_BITS),
            &DIRECTORY_MODE,
            "directory mode",
        )?;
        let mut files: Vec<PathBuf> = fs::read_dir(&directory)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        files.sort();
        check(&files.len(), &2, "one file per certificate")?;
        for file in &files {
            check(
                &(fs::metadata(file)?.permissions().mode() & PERMISSION_BITS),
                &FILE_MODE,
                "file mode",
            )?;
            let expected = format!(
                "{}.{CERTIFICATE_EXTENSION}",
                hex::encode(Sha256::digest(fs::read(file)?))
            );
            check(
                &file
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default(),
                &expected.as_str(),
                "named by the DER's SHA-256",
            )?;
        }
        let loaded = cache.load(at(WITHIN)?);
        check(&loaded.len(), &2, "both load back")
    }

    #[test]
    fn an_expired_or_foreign_file_is_purged_on_load() -> TestResult {
        let dir = TempDir::new("ca-certificates-purge")?;
        let cache = CaCache::at(dir.path().to_path_buf());
        cache.store(&[parse(ROOT_ECC_DER)?])?;
        let foreign = dir
            .path()
            .join("notes")
            .with_extension(CERTIFICATE_EXTENSION);
        fs::write(&foreign, b"synthetic notes")?;
        check_true(cache.load(at(WITHIN)?).len() == 1, "the root loads")?;
        check_true(!foreign.exists(), "the foreign file is removed")?;
        check_true(cache.load(at(AFTER)?).is_empty(), "nothing after expiry")?;
        check_true(
            fs::read_dir(dir.path())?.next().is_none(),
            "the expired root is removed",
        )
    }

    #[test]
    fn the_directory_follows_the_variables() -> TestResult {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| std::ffi::OsString::from(value))
            }
        };
        check(
            &directory_from(env(&[(
                CACHE_DIRECTORY_VARIABLE,
                "/var/cache/refineid-test",
            )])),
            &Some(PathBuf::from("/var/cache/refineid-test")),
            "the named directory as it is",
        )?;
        check(
            &directory_from(env(&[
                (XDG_CACHE_HOME, "/cache"),
                (HOME, "/home/custodian-1"),
            ])),
            &Some(PathBuf::from("/cache/refineid/ca-certificates")),
            "XDG_CACHE_HOME first",
        )?;
        check(
            &directory_from(env(&[(HOME, "/home/custodian-1")])),
            &Some(PathBuf::from(
                "/home/custodian-1/.cache/refineid/ca-certificates",
            )),
            "HOME/.cache next",
        )?;
        check(
            &directory_from(env(&[])),
            &None,
            "nothing without a variable",
        )
    }
}
