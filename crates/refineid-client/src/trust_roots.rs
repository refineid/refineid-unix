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

//! Pinned trust anchors for cert-chain verification.
//!
//! Pin tables hold typed [`Sha256`] values rather than raw
//! `[u8; 32]` so the type system enforces "compare a SHA-256
//! against a SHA-256 pin" -- mixing a different-shape hash
//! against a pin won't compile. See
//! [`doc/typing-discipline.md`][typing] and
//! [`doc/fineid-s2-cert-profile.md`][s2] for the broader
//! framing.
//!
//! The on-card root cert at `EF.4334` is the proximate trust
//! source for the chain check (leaf -> AIA-fetched intermediate
//! -> on-card root). We pin its SHA-256 here so that a card with
//! a substituted root cert can't fool the verifier.
//!
//! DVV runs **two parallel G3 roots** since 2021-05-06, one
//! per key family (RSA / ECC). Both are pinned: an RSA-keyed
//! citizen card chains to `DVV Gov. Root CA - G3 RSA`, an
//! ECC-keyed card chains to `DVV Gov. Root CA - G3 ECC`, and
//! the two roots have different SHA-256 fingerprints.
//! Refusing one would silently break half the in-field
//! citizen-card population.
//!
//! [typing]: ../../../../doc/typing-discipline.md
//! [s2]: ../../../../doc/fineid-s2-cert-profile.md

use refineid_lib_core::crypto::digest::Sha256;

/// Accepted on-card root certs as `(label, sha256)` pairs.
///
/// The label is the DVV-published canonical name and is
/// surfaced in trust attestations / audit events. Empty list
/// = "trust whatever the card publishes" -- never the
/// production default.
///
/// Fingerprints sourced from FINEID S2 v5.2 §8.2 (Root and
/// CA Certificate Fingerprints). Cross-checked against a
/// live OMNIKEY card (G3 RSA root) on 2026-05-23.
pub const PINNED_ROOT_SHA256: &[(&str, Sha256)] = &[
    (
        "DVV Gov. Root CA - G3 RSA",
        Sha256::from_bytes([
            0xD3, 0xED, 0x3F, 0xC4, 0x0A, 0xD2, 0x6B, 0x52, 0xE0, 0x01, 0xE1, 0xE1, 0x8F, 0x4B,
            0x94, 0x49, 0x52, 0x9D, 0xEB, 0x75, 0xA8, 0x1D, 0x5E, 0xB6, 0x80, 0xD7, 0xB6, 0x2D,
            0xB2, 0x3B, 0xA9, 0x6D,
        ]),
    ),
    (
        "DVV Gov. Root CA - G3 ECC",
        Sha256::from_bytes([
            0x55, 0x46, 0xA5, 0x25, 0x04, 0xFB, 0xA7, 0x4F, 0x61, 0xFF, 0xD4, 0x89, 0x00, 0x67,
            0x52, 0x9A, 0xDE, 0x3B, 0x9C, 0x9D, 0x07, 0xE5, 0x02, 0x59, 0x28, 0x31, 0xCC, 0xDA,
            0x9B, 0x36, 0x9F, 0xD3,
        ]),
    ),
];

/// `true` if `fingerprint` matches one of the pinned roots. Only the
/// compiled-in pins are a source of trust; nothing read from a card
/// is ever added to them.
#[must_use]
pub fn is_pinned_root(fingerprint: Sha256) -> bool {
    PINNED_ROOT_SHA256
        .iter()
        .any(|(_, pinned)| *pinned == fingerprint)
}

/// Return the label of the pinned root matching
/// `fingerprint`, or `None` if no pin matches.
#[must_use]
pub fn pinned_root_label(fingerprint: Sha256) -> Option<&'static str> {
    PINNED_ROOT_SHA256
        .iter()
        .find(|(_, fp)| *fp == fingerprint)
        .map(|(label, _)| *label)
}

/// Embedded DER bytes for every pinned DVV root CA.
///
/// `PINNED_ROOT_SHA256` carries the fingerprint pins (one-way
/// hash); this table additionally embeds the actual cert DER so
/// the cert-chain walker can use any pinned root as a trust
/// anchor when the relevant on-card root is missing or carries
/// the wrong algorithm.
///
/// Motivating case: FINEID S4-1 v4.2 §4.5 says **both** the G3
/// ECC and G3 RSA roots should be stored on the card, but DVV's
/// in-field 2026-vintage citizen cards ship with only the
/// primary G3 ECC root in EF.4334. The RSA-3072 backup cert in
/// EF.4333 chains to the G3 RSA root which is *not* on the
/// card. Without this embedded DER, the chain walker would
/// fail at the intermediate->root hop ("issuer SPKI shape
/// doesn't match the signature alg") because it tried to verify
/// an RSA-signed intermediate against the on-card ECC root.
///
/// Both DERs are public DVV CA certs sourced from
/// `proxy.fineid.fi/ca/dvvroot3ec.crt` and
/// `proxy.fineid.fi/ca/dvvroot3rc.crt` (FINEID S2 v5.2 §8.5
/// canonical URLs). Bit-identical to the on-card EF.4334 copy
/// for the ECC root, verified 2026-05-28. Fingerprints
/// cross-checked against [`PINNED_ROOT_SHA256`] at test time.
pub const PINNED_ROOT_DER: &[(&str, &[u8])] = &[
    (
        "DVV Gov. Root CA - G3 RSA",
        include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-rsa.der"),
    ),
    (
        "DVV Gov. Root CA - G3 ECC",
        include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-ecc.der"),
    ),
];

/// Return the embedded DER bytes of the pinned root with the
/// given SHA-256 fingerprint, or `None` if no pin matches.
///
/// Used by the cert-chain walker as a fallback trust anchor
/// when the on-card root cert isn't the right one for the
/// chain under verification (e.g. an RSA intermediate signed
/// by the G3 RSA root on a card that only carries the G3 ECC
/// root in EF.4334).
#[must_use]
pub fn pinned_root_der_by_fingerprint(fingerprint: Sha256) -> Option<&'static [u8]> {
    PINNED_ROOT_SHA256
        .iter()
        .zip(PINNED_ROOT_DER.iter())
        .find(|((_, fp), _)| *fp == fingerprint)
        .map(|(_, (_, der))| *der)
}

#[cfg(test)]
mod tests {
    use super::{PINNED_ROOT_DER, PINNED_ROOT_SHA256, pinned_root_der_by_fingerprint};
    use crate::test_util::{TestResult, check, check_true};
    use refineid_lib_core::crypto::digest::Sha256;

    /// The embedded DER bytes for each pinned root must hash to
    /// the fingerprint stated in `PINNED_ROOT_SHA256`. A mismatch
    /// means somebody swapped the file in `trust-anchors/`
    /// without updating the pin (or vice versa); the chain
    /// walker would then verify against an unpinned anchor.
    #[test]
    fn pinned_der_fingerprints_match_pins() -> TestResult {
        check(
            &PINNED_ROOT_DER.len(),
            &PINNED_ROOT_SHA256.len(),
            "PINNED_ROOT_DER and PINNED_ROOT_SHA256 must have the same length",
        )?;
        for ((label_der, der), (label_pin, pin)) in
            PINNED_ROOT_DER.iter().zip(PINNED_ROOT_SHA256.iter())
        {
            check(label_der, label_pin, "label order must match")?;
            let computed = Sha256::of(der);
            check(
                &computed,
                pin,
                &format!("fingerprint mismatch for {label_der}"),
            )?;
        }
        Ok(())
    }

    /// `pinned_root_der_by_fingerprint` returns the right DER
    /// for a known pin and `None` for an unknown one.
    #[test]
    fn lookup_by_fingerprint_round_trips() -> TestResult {
        for (label, pin) in PINNED_ROOT_SHA256 {
            let der = pinned_root_der_by_fingerprint(*pin)
                .ok_or_else(|| format!("DER missing for pin labelled {label}"))?;
            let recomputed = Sha256::of(der);
            check(&recomputed, pin, &format!("recompute for {label}"))?;
        }
        let bogus = Sha256::from_bytes([0_u8; 32]);
        check_true(
            pinned_root_der_by_fingerprint(bogus).is_none(),
            "bogus pin returns None",
        )
    }
}
