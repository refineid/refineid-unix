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

//! Owned certificate DER provenance wrapper.
//!
//! [`CertDer`] marks owned bytes read from a PKCS#15 certificate slot
//! or bundled certificate store before X.509 parsing. Keeping the
//! unvalidated card-read buffer in a dedicated type separates raw
//! certificate DER from arbitrary `Vec<u8>` buffers and requires an
//! explicit parse step via [`crate::x509::OwnedCert::from_der`] or
//! `Certificate::from_der` before certificate fields are inspected.
//!
//! Canonical docs:
//! [`doc/typing-discipline.md`](../../../../doc/typing-discipline.md),
//! [`doc/security/der-trust-boundary.md`](../../../../doc/security/der-trust-boundary.md).

/// Owned certificate DER bytes read from a card slot or trust bundle.
///
/// Distinct from arbitrary `Vec<u8>`: the wrapper records certificate
/// DER provenance without claiming syntactic or cryptographic
/// validity. Callers parse the borrowed bytes through [`crate::x509`]
/// before inspecting fields or verifying signatures.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertDer {
    /// Raw DER-encoded certificate bytes.
    bytes: Vec<u8>,
}

impl CertDer {
    /// Wrap raw certificate DER bytes without syntactic validation.
    #[must_use]
    #[inline]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the underlying DER bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume the wrapper and return the owned DER bytes.
    #[must_use]
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of the DER buffer in bytes.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when the DER buffer is empty.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::CertDer;

    const SAMPLE_CERT_BYTES: &[u8] = b"refineid-cert-der-sample";

    #[test]
    fn cert_der_roundtrips_owned_bytes_and_length() {
        let cert = CertDer::new(SAMPLE_CERT_BYTES.to_vec());
        assert!(!cert.is_empty());
        assert_eq!(cert.len(), SAMPLE_CERT_BYTES.len());
        assert_eq!(cert.as_bytes(), SAMPLE_CERT_BYTES);
        assert_eq!(cert.into_bytes(), SAMPLE_CERT_BYTES);
    }

    #[test]
    fn cert_der_reports_empty_buffer() {
        let empty = CertDer::new(Vec::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.as_bytes().is_empty());
        assert!(empty.into_bytes().is_empty());
    }
}
