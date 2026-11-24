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

//! Phantom-typed containers for cryptographic outputs.
//!
//! Re-exports the shared algorithm markers and containers from
//! [`refineid_cms::container`] and adds the card-decryption marker
//! ([`RsaPkcs1`]) and zeroizing [`Plaintext`] container used by
//! `PSO:DECIPHER`.

#![expect(
    clippy::pub_use,
    reason = "library-facade pattern: re-exports shared containers alongside local card-decryption containers"
)]

use core::fmt;
use core::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use refineid_cms::container::*;

/// Marker: RSA PKCS#1 v1.5 encryption (no hash).
///
/// Distinct from the `RsaPkcs1Sha*` signature markers: encryption pads
/// raw plaintext, signing pads a pre-computed hash digest. The FINEID
/// auth key decrypts with this scheme via `PSO:DECIPHER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RsaPkcs1;

/// Cleartext bytes recovered from a specific decryption / unpad
/// operation.
///
/// `Alg` records which algorithm produced the plaintext, so the
/// compiler refuses to pass a value recovered from
/// `Plaintext<RsaPkcs1>` (already-unpadded) to a function that
/// expected the raw cipher-block output of `Plaintext<AesCbc>`.
///
/// No derived `Debug` / `PartialEq`: the bytes are live decryption
/// output, so `Debug` is redacted and equality is deliberately absent.
#[derive(Clone)]
pub struct Plaintext<Alg> {
    /// Unpadded plaintext bytes recovered from a decrypt of `Alg`.
    bytes: Vec<u8>,
    /// Type-level tag binding the value to the decrypting algorithm.
    _phantom: PhantomData<Alg>,
}

impl<Alg> Plaintext<Alg> {
    /// Wrap raw plaintext bytes recovered from `Alg`.
    #[inline]
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _phantom: PhantomData,
        }
    }

    /// Borrow the underlying plaintext bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume the container and return the owned plaintext bytes.
    ///
    /// Moving the bytes out transfers ownership out of [`Plaintext`]'s
    /// drop-time zeroization; callers handling sensitive decryption output
    /// should zeroize the returned buffer once no longer needed.
    #[inline]
    #[must_use]
    pub fn into_bytes(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }

    /// Length of the plaintext in bytes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the plaintext is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl<Alg> Zeroize for Plaintext<Alg> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<Alg> ZeroizeOnDrop for Plaintext<Alg> {}

impl<Alg> Drop for Plaintext<Alg> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<Alg> fmt::Display for Plaintext<Alg> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plaintext({} bytes)", self.bytes.len())
    }
}

/// Manual redacted `Debug`: a derived impl would print the raw
/// decryption output byte-for-byte, defeating the redacted `Display`.
impl<Alg> fmt::Debug for Plaintext<Alg> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plaintext")
            .field("bytes", &format_args!("[redacted; {}]", self.bytes.len()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Plaintext, RsaPkcs1, Zeroize as _};

    const SAMPLE_BYTE_A: u8 = 0xAA;
    const SAMPLE_BYTE_B: u8 = 0xBB;
    const SAMPLE_BYTE_REDACT: u8 = 0xDE;
    const SAMPLE_LEN_32: usize = 32;
    const SAMPLE_LEN_24: usize = 24;
    const SAMPLE_LEN_48: usize = 48;

    #[test]
    fn plaintext_carries_algorithm_at_type_level() {
        let rsa: Plaintext<RsaPkcs1> = Plaintext::new(vec![SAMPLE_BYTE_A; SAMPLE_LEN_32]);
        assert_eq!(rsa.len(), SAMPLE_LEN_32);
        assert_eq!(rsa.as_bytes().first().copied(), Some(SAMPLE_BYTE_A));
        let owned = rsa.into_bytes();
        assert_eq!(owned.len(), SAMPLE_LEN_32);
    }

    #[test]
    fn plaintext_display_does_not_leak_bytes() {
        let plain: Plaintext<RsaPkcs1> = Plaintext::new(vec![SAMPLE_BYTE_REDACT; SAMPLE_LEN_24]);
        let rendered = format!("{plain}");
        assert!(rendered.contains("24 bytes"));
        assert!(!rendered.contains("DE"));
        assert!(!rendered.contains("de"));
    }

    #[test]
    fn plaintext_debug_and_display_do_not_leak_bytes() {
        let plain: Plaintext<RsaPkcs1> = Plaintext::new(vec![SAMPLE_BYTE_REDACT; SAMPLE_LEN_48]);
        let decimal_marker = SAMPLE_BYTE_REDACT.to_string();
        for rendered in [format!("{plain}"), format!("{plain:?}")] {
            assert!(rendered.contains("48"), "got: {rendered}");
            assert!(!rendered.contains("DE"), "got: {rendered}");
            assert!(!rendered.contains("de"), "got: {rendered}");
            assert!(!rendered.contains(&decimal_marker), "got: {rendered}");
        }
    }

    #[test]
    fn plaintext_zeroize_clears_heap_bytes() {
        let mut plain: Plaintext<RsaPkcs1> = Plaintext::new(vec![SAMPLE_BYTE_A; SAMPLE_LEN_32]);
        assert_eq!(plain.len(), SAMPLE_LEN_32);
        plain.zeroize();
        assert_eq!(plain.len(), 0);
        assert!(plain.is_empty());
    }

    #[test]
    fn plaintext_drop_zeroizes_internal_storage() {
        let plain: Plaintext<RsaPkcs1> = Plaintext::new(vec![SAMPLE_BYTE_B; SAMPLE_LEN_32]);
        drop(plain);
    }
}
