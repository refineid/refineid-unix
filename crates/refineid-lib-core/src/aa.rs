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

//! Active Authentication (ICAO 9303-11 §6.1).
//!
//! Anti-cloning round-trip for v3.1-era eMRTDs that carry an AA
//! private key on chip and the matching public key in DG15. The
//! reader generates an 8-byte challenge, sends it via the
//! `INTERNAL AUTHENTICATE` APDU, and the chip signs
//! `F = 6A || M1 || H(M1 || RND.IFD) || T` per ISO/IEC 9796-2
//! Digital Signature Scheme 1. The reader RSA-recovers `F`,
//! decodes the trailer to learn the hash algorithm, extracts
//! `M1` and the embedded hash, and verifies the chip used a
//! private key matching DG15's public key.
//!
//! Successful AA proves the chip itself produced the signature
//! -- a clone with only the public DGs (which are signed by the
//! CSCA but not chip-bound) couldn't produce the response. AA
//! is mutually exclusive with Chip Authentication (CA, the v4.0
//! replacement) but a card may publish either or both; FINEID
//! v3.1 cards publish AA via DG15, v4.0 cards publish CA via
//! DG14.
//!
//! AA must run after PACE on a FINEID card -- the eMRTD applet
//! refuses the INTERNAL AUTHENTICATE APDU outside Secure
//! Messaging. Callers pass an already-SM-wrapped transport.

use crate::apdu::iso7816::APDU_HEADER_LEN;
use crate::crypto::digest::HashAlg;
use crate::crypto::rsa::{RsaPublicKey, RsaVerifyError};
use crate::transport::{CardTransport, CommandApdu, TransportDispatchError};

/// Length of the Active Authentication host challenge in bytes (ICAO 9303-11).
const AA_CHALLENGE_LEN: usize = 8;

/// ISO 7816-4 `INTERNAL AUTHENTICATE` command with an eight-byte host challenge.
///
/// Used by Active Authentication (ICAO 9303-11) until the eMRTD driver moves to
/// `refineid-emrtd`.
#[derive(Debug, Clone, Copy)]
struct InternalAuthenticate {
    /// Eight-byte host-supplied challenge.
    challenge: [u8; AA_CHALLENGE_LEN],
}

impl InternalAuthenticate {
    /// ISO 7816-4 plain class byte.
    const CLA: u8 = 0x00;
    /// ISO 7816-4 `INTERNAL AUTHENTICATE` instruction byte.
    const INS: u8 = 0x88;
    /// P1: reserved.
    const P1: u8 = 0x00;
    /// P2: reserved.
    const P2: u8 = 0x00;
    /// Lc: byte length of the host challenge.
    const LC: u8 = 0x08;
    /// Le: request all available signature bytes.
    const LE_ANY: u8 = 0x00;
    /// Wire length: header, Lc, challenge, and Le.
    const WIRE_LEN: usize = APDU_HEADER_LEN + 1 + AA_CHALLENGE_LEN + 1;

    /// Serialise into the wire command APDU.
    #[inline]
    #[must_use]
    fn into_apdu(self) -> CommandApdu {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(&[Self::CLA, Self::INS, Self::P1, Self::P2, Self::LC]);
        out.extend_from_slice(&self.challenge);
        out.push(Self::LE_ANY);
        CommandApdu::new(out)
    }
}

/// Outcome of an AA round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AaOutcome {
    /// Chip's signature verified against the DG15 public key
    /// -- the chip is the genuine card, not a clone of the DGs.
    Verified {
        /// Hash function the chip used (decoded from the
        /// ISO 9796-2 trailer).
        hash: HashAlg,
        /// Length of the recovered `M1` (random padding from
        /// the chip). Surfaced for inspection; not load-bearing.
        m1_len: usize,
    },
    /// Card refused the `INTERNAL AUTHENTICATE` APDU. Typical
    /// causes: AA disabled on this chip, applet doesn't
    /// implement AA, SM session not yet established.
    CardRejected {
        /// Card-returned status word per ISO 7816-4 §5.1.3.
        sw: u16,
    },
    /// Card responded but the signature didn't verify. Either
    /// the chip's private key doesn't match DG15 (the card has
    /// been tampered with) or our verifier rejected the padding
    /// shape.
    SignatureInvalid {
        /// Human-readable detail naming the verifier rejection
        /// (padding shape, trailer byte, recovered-hash
        /// mismatch). Tier 0 `String`; presentational.
        detail: String,
    },
}

/// Errors that abort the round-trip before the verifier sees a
/// response.
#[derive(Debug)]
pub enum AaError<TE>
where
    TE: core::fmt::Debug + core::fmt::Display,
{
    /// Transport / SM I/O failure.
    Transport(TransportDispatchError<TE>),
    /// The DG15 `SubjectPublicKeyInfo` didn't parse as an RSA
    /// public key. ECC AA keys are also valid per ICAO 9303-11
    /// but FINEID v3.1 cards in scope use RSA; ECDSA-AA
    /// support is a future addition.
    UnsupportedKey,
    /// The OS random source failed -- shouldn't happen on a
    /// healthy host, surfaced rather than silently retried.
    Random(crate::rng::Failure),
}

impl<TE> core::fmt::Display for AaError<TE>
where
    TE: core::fmt::Debug + core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "AA transport: {e}"),
            Self::UnsupportedKey => write!(
                f,
                "AA pubkey isn't RSA (only RSA AA keys currently supported)"
            ),
            Self::Random(e) => write!(f, "AA random: {e}"),
        }
    }
}

impl<TE> core::error::Error for AaError<TE> where TE: core::fmt::Debug + core::fmt::Display + 'static
{}

/// Run an Active Authentication round-trip against `transport`
/// using the supplied `dg15_pubkey`.
///
/// Generates a fresh 8-byte challenge, sends `INTERNAL
/// AUTHENTICATE` (`CLA=00 INS=88 P1=00 P2=00 Lc=08
/// Data=challenge Le=00`), and verifies the chip's
/// ISO/IEC 9796-2 DS1 signature against the public key.
///
/// `transport` must already be running Secure Messaging post-
/// PACE -- the eMRTD applet refuses unprotected APDUs.
///
/// # Errors
/// [`AaError`] for transport / key-parse / RNG failures. The
/// returned [`AaOutcome`] distinguishes successful verification
/// from card-rejected and signature-invalid cases, so callers
/// can render the right diagnostic.
pub(crate) fn run_active_authentication<T: CardTransport>(
    transport: &mut T,
    dg15_pubkey: &RsaPublicKey,
) -> Result<AaOutcome, AaError<T::Error>> {
    let mut rnd_ifd = [0_u8; 8];
    crate::rng::fill(&mut rnd_ifd).map_err(AaError::Random)?;

    let apdu = InternalAuthenticate { challenge: rnd_ifd }.into_apdu();
    let response = transport
        .transmit(apdu.as_bytes())
        .map_err(AaError::Transport)?;
    if !response.is_ok() {
        return Ok(AaOutcome::CardRejected {
            sw: response.status_word().as_u16(),
        });
    }
    let signature = response.body;
    match dg15_pubkey.verify_iso9796_2_ds1(&rnd_ifd, &signature) {
        Ok(recovered) => Ok(AaOutcome::Verified {
            hash: recovered.hash,
            m1_len: recovered.m1.len(),
        }),
        Err(e) => Ok(AaOutcome::SignatureInvalid {
            detail: format!("{e}"),
        }),
    }
}

/// Wire the `RsaVerifyError` enum into the AA outcome's
/// `SignatureInvalid` carrier without forcing the outcome enum
/// to depend on the crypto error type.
impl From<RsaVerifyError> for AaOutcome {
    fn from(e: RsaVerifyError) -> Self {
        Self::SignatureInvalid {
            detail: format!("{e}"),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{AaError, AaOutcome, run_active_authentication};
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use crate::crypto::digest::HashAlg;
    use crate::crypto::rsa::{RsaPublicKey, RsaVerifyError};
    use crate::transport::{
        CardTransport, CommandApdu, ResponseApdu, TransportDispatchError, TransportOutcome,
    };
    use crate::x509::extract_rsa_public_key;
    use refineid_cms::testkit::TestKey;

    /// `INTERNAL AUTHENTICATE` instruction byte (ISO 7816-4).
    const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
    /// Expected length in bytes of the ISO 7816-4 AA APDU:
    /// header + Lc + 8-byte challenge + Le.
    const AA_APDU_LEN: usize = 14;
    /// Byte offset of `INS` within the APDU header.
    const APDU_INS_INDEX: usize = 1;
    /// Byte offset of `Lc` within the APDU header.
    const APDU_LC_INDEX: usize = 4;
    /// Expected `Lc` byte for the 8-byte host challenge.
    const AA_CHALLENGE_LC: u8 = 0x08;
    /// Byte range of the challenge data within the APDU.
    const CHALLENGE_START: usize = 5;
    const CHALLENGE_END: usize = 13;
    /// ISO/IEC 9796-2 DS1 leading byte width.
    const DS1_LEADING_LEN: usize = 1;
    /// Implicit SHA-1 trailer width.
    const DS1_IMPLICIT_TRAILER_LEN: usize = 1;
    /// Explicit two-byte trailer width (`HFI || CC`).
    const DS1_EXPLICIT_TRAILER_LEN: usize = 2;
    /// ISO 7816-4 normal-processing status word high byte.
    const SW_OK_1: u8 = 0x90;
    /// ISO 7816-4 normal-processing status word low byte.
    const SW_OK_2: u8 = 0x00;
    /// Single-bit XOR mask used to mutate the challenge in negative tests.
    const BIT_FLIP_MASK: u8 = 0x01;

    // MARK: - Fixture builders

    /// The RFC 9500 2048-bit RSA test key playing the PICC half of AA.
    fn chip_key() -> TestKey {
        TestKey::rsa_2048()
    }

    /// The DG15 public key the driver verifies against.
    fn dg15_pubkey() -> RsaPublicKey {
        extract_rsa_public_key(&chip_key().spki()).expect("RFC 9500 RSA SPKI parses")
    }

    /// Expected recovered-`M1` length for the RFC 9500 2048-bit key under `hash`.
    fn expected_m1_len(hash: HashAlg) -> usize {
        let k = dg15_pubkey().modulus.byte_len();
        let trailer_len = match hash {
            HashAlg::Sha1 => DS1_IMPLICIT_TRAILER_LEN,
            HashAlg::Sha256 | HashAlg::Sha384 | HashAlg::Sha512 => DS1_EXPLICIT_TRAILER_LEN,
        };
        k - DS1_LEADING_LEN - hash.digest_len() - trailer_len
    }

    /// Build a valid ISO 9796-2 DS1 signature over `challenge` using the
    /// RFC 9500 test RSA key.
    fn ds1_signature(hash: HashAlg, challenge: &[u8]) -> Vec<u8> {
        chip_key()
            .sign_iso9796_2_ds1(hash, challenge)
            .expect("RSA test key signs ISO 9796-2 DS1")
    }

    // MARK: - Chip-side mock

    /// What the in-memory chip does when it receives `INTERNAL
    /// AUTHENTICATE`.
    enum ChipBehavior {
        /// Sign the received challenge correctly with the given hash.
        Sign(HashAlg),
        /// Sign a *mutated* challenge -- structurally valid DS1, wrong
        /// digest. Models a response not bound to *this* nonce.
        SignWrongChallenge(HashAlg),
        /// Reply with a non-success status word (AA disabled / not in SM).
        Reject(u16),
        /// Reply 9000 but with a body that isn't a `k`-byte signature.
        MalformedBody(Vec<u8>),
        /// Backend transport failure before any response arrives.
        TransportFail,
    }

    /// In-memory chip that plays the PICC half of an AA round-trip: it
    /// reads the reader's 8-byte challenge straight out of the APDU
    /// and reacts per its [`ChipBehavior`].
    struct AaChip {
        behavior: ChipBehavior,
    }

    impl AaChip {
        fn new(behavior: ChipBehavior) -> Self {
            Self { behavior }
        }
    }

    impl CardTransport for AaChip {
        type Error = String;

        fn transmit_outcome(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, String> {
            let bytes = apdu.as_bytes();
            assert_eq!(bytes.len(), AA_APDU_LEN, "AA APDU length mismatch");
            assert_eq!(
                bytes[APDU_INS_INDEX], INS_INTERNAL_AUTHENTICATE,
                "INS is INTERNAL AUTHENTICATE"
            );
            assert_eq!(
                bytes[APDU_LC_INDEX], AA_CHALLENGE_LC,
                "Lc announces an 8-byte challenge"
            );
            let challenge = &bytes[CHALLENGE_START..CHALLENGE_END];

            let response = match &self.behavior {
                ChipBehavior::TransportFail => {
                    return Err("simulated reader I/O failure".to_owned());
                }
                ChipBehavior::Reject(sw) => {
                    let [sw1, sw2] = sw.to_be_bytes();
                    ResponseApdu {
                        body: Vec::new(),
                        sw1,
                        sw2,
                    }
                }
                ChipBehavior::MalformedBody(body) => ResponseApdu {
                    body: body.clone(),
                    sw1: SW_OK_1,
                    sw2: SW_OK_2,
                },
                ChipBehavior::Sign(hash) => ResponseApdu {
                    body: ds1_signature(*hash, challenge),
                    sw1: SW_OK_1,
                    sw2: SW_OK_2,
                },
                ChipBehavior::SignWrongChallenge(hash) => {
                    let mut wrong = challenge.to_vec();
                    if let Some(first) = wrong.first_mut() {
                        *first ^= BIT_FLIP_MASK;
                    }
                    ResponseApdu {
                        body: ds1_signature(*hash, &wrong),
                        sw1: SW_OK_1,
                        sw2: SW_OK_2,
                    }
                }
            };
            Ok(TransportOutcome::Response(response))
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    // MARK: - Driver outcome tests (against the chip mock)

    /// Drive a full round-trip against a chip that signs correctly with
    /// `hash` and assert the `Verified` outcome carries that hash plus
    /// the expected recovered-`M1` length.
    fn assert_verified_for(hash: HashAlg) {
        let mut transport = AaChip::new(ChipBehavior::Sign(hash));
        let outcome =
            run_active_authentication(&mut transport, &dg15_pubkey()).expect("no transport error");
        assert_eq!(
            outcome,
            AaOutcome::Verified {
                hash,
                m1_len: expected_m1_len(hash),
            },
            "hash={hash:?}"
        );
    }

    #[test]
    fn verified_round_trip_sha256() {
        assert_verified_for(HashAlg::Sha256);
    }

    #[test]
    fn verified_round_trip_sha1_implicit_trailer() {
        assert_verified_for(HashAlg::Sha1);
    }

    #[test]
    fn verified_round_trip_sha384_and_sha512() {
        assert_verified_for(HashAlg::Sha384);
        assert_verified_for(HashAlg::Sha512);
    }

    #[test]
    fn card_rejected_surfaces_status_word() {
        // 0x6982 "security status not satisfied" -- e.g. AA attempted
        // outside an established SM session.
        let mut transport = AaChip::new(ChipBehavior::Reject(0x6982));
        let outcome = run_active_authentication(&mut transport, &dg15_pubkey())
            .expect("card refusal is an outcome, not an error");
        assert_eq!(outcome, AaOutcome::CardRejected { sw: 0x6982 });
    }

    #[test]
    fn signature_invalid_on_challenge_mismatch() {
        // The chip signs a different challenge than the reader sent. The
        // DS1 structure recovers cleanly, but H(M1 || wrong) != H(M1 ||
        // RND.IFD), so the verifier rejects with a digest mismatch. This
        // is AA's anti-cloning core: a response not cryptographically
        // bound to *this* fresh nonce is refused.
        let mut transport = AaChip::new(ChipBehavior::SignWrongChallenge(HashAlg::Sha256));
        let outcome = run_active_authentication(&mut transport, &dg15_pubkey())
            .expect("verification failure is an outcome, not an error");
        let AaOutcome::SignatureInvalid { detail } = outcome else {
            panic!("expected SignatureInvalid, got {outcome:?}");
        };
        assert!(detail.contains("digest"), "{detail}");
    }

    #[test]
    fn signature_invalid_on_malformed_body() {
        // Card answers 9000 but the body is too short to be a k-byte RSA
        // signature -- the verifier's length guard fires.
        let mut transport = AaChip::new(ChipBehavior::MalformedBody(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        let outcome = run_active_authentication(&mut transport, &dg15_pubkey())
            .expect("verification failure is an outcome, not an error");
        let AaOutcome::SignatureInvalid { detail } = outcome else {
            panic!("expected SignatureInvalid, got {outcome:?}");
        };
        assert!(detail.contains("range"), "{detail}");
    }

    #[test]
    fn transport_error_aborts_round_trip() {
        let mut transport = AaChip::new(ChipBehavior::TransportFail);
        let err = run_active_authentication(&mut transport, &dg15_pubkey())
            .expect_err("a backend I/O failure aborts the round-trip");
        let AaError::Transport(_) = err else {
            panic!("expected AaError::Transport, got {err:?}");
        };
    }

    // MARK: - Pure unit tests (no card)

    #[test]
    fn rsa_verify_error_maps_to_signature_invalid() {
        let outcome: AaOutcome = RsaVerifyError::BadDigest.into();
        let AaOutcome::SignatureInvalid { detail } = outcome else {
            panic!("From<RsaVerifyError> must produce SignatureInvalid, got {outcome:?}");
        };
        assert_eq!(detail, format!("{}", RsaVerifyError::BadDigest));
    }

    #[test]
    fn aa_error_display_arms() {
        let transport: AaError<String> =
            AaError::Transport(TransportDispatchError::Outcome(TransportOutcome::NoCard));
        assert!(
            format!("{transport}").contains("AA transport"),
            "{transport}"
        );

        let unsupported: AaError<String> = AaError::UnsupportedKey;
        assert!(format!("{unsupported}").contains("RSA"), "{unsupported}");

        let random: AaError<String> = AaError::Random(crate::rng::Failure::UNSUPPORTED);
        assert!(format!("{random}").starts_with("AA random"), "{random}");
    }

    #[test]
    fn internal_authenticate_wire_layout_and_no_wrong_le_retry() {
        use super::{AA_CHALLENGE_LEN, InternalAuthenticate};

        const CHALLENGE: [u8; AA_CHALLENGE_LEN] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        const RETRY_LE: u8 = 0x10;

        let apdu = InternalAuthenticate {
            challenge: CHALLENGE,
        }
        .into_apdu();
        let mut expected = vec![
            InternalAuthenticate::CLA,
            InternalAuthenticate::INS,
            InternalAuthenticate::P1,
            InternalAuthenticate::P2,
            InternalAuthenticate::LC,
        ];
        expected.extend_from_slice(&CHALLENGE);
        expected.push(InternalAuthenticate::LE_ANY);

        assert_eq!(apdu.as_bytes().len(), InternalAuthenticate::WIRE_LEN);
        assert_eq!(apdu.as_bytes(), expected.as_slice());
        assert!(
            apdu.corrected_wrong_le(RETRY_LE).is_none(),
            "INTERNAL AUTHENTICATE must not opt into wrong-Le retry"
        );
    }
}
