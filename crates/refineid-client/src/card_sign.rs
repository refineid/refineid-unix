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

//! `refineid card sign-auth` + `refineid card sign-qualified`.
//!
//! SHA-256 the input file, VERIFY the appropriate PIN, drive the
//! SHA-256+RSA-PKCS1v15 sign chain against the chosen FINEID key
//! slot, write the raw 384-byte RSA signature to disk, and
//! locally verify it against the public key in the on-card cert.
//!
//! - `sign-auth`: VERIFY PIN1, sign with the **auth key** (key
//!   ref `0x01`), verify against the EF.4331 cert.
//! - `sign-qualified`: VERIFY PIN2, sign with the **qualified-
//!   signature key** (key ref `0x02`), verify against the
//!   EF.4332 cert. PIN2 has a 6-digit floor (FINEID S1 v4.2 §3.5).
//!
//! Both paths share the same option / report / error types and a
//! shared internal driver (`sign_with_slot`) so the wire
//! choreography stays in lockstep. Signed documents are made by
//! `refineid_doc_sign` (`document sign`), not here.

use alloc::fmt;
use std::path::PathBuf;

use refineid_lib_core::apdu::status_word::StatusWord;
use refineid_lib_core::auth::{
    AuthError, PinOps as _, PinPolicyReason, PinReferenceScheme, PinSlot, RetryFloorRefusal,
    VerifyOutcome, check_retry_floor,
};
use refineid_lib_core::backend::{
    ReaderAccessCap, ReaderBackend, ReaderBackendOps as _, ReaderPickError,
};
use refineid_lib_core::can::Can;
use refineid_lib_core::cert_state::CertDer;
use refineid_lib_core::crypto::digest::{Sha256, Sha384};
use refineid_lib_core::identity::{CommonName, TokenSerial, render_token_serial};
use refineid_lib_core::pace;
use refineid_lib_core::pkcs15::Pkcs15Ops as _;
use refineid_lib_core::pkcs15::{CertSlot, Pkcs15Error};
use refineid_lib_core::secure_messaging::SmTransport;
use refineid_lib_core::sign::{KeyRef, SignError, SignOps as _};
use refineid_lib_core::transport::CardTransport;
use refineid_lib_core::x509::{
    Certificate, EcCurve, OwnedCert, PublicKeyAlgorithm, extract_rsa_public_key,
};
use refineid_lib_pcsc::{PcscBackend, PcscCard, PcscError};

use crate::pin_source::{PinEntryError, PinSource};

/// Which on-card key slot to sign with.
///
/// The choice picks PIN (1 vs 2), key reference byte (0x01 vs
/// 0x02), and the cert slot (EF.4331 vs EF.4332) used for the
/// local verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignSlot {
    /// **Auth key** -- TLS client-cert / SSH / agent identity.
    /// PIN1-gated, key ref 0x01, EF.4331 cert.
    Auth,
    /// **Qualified-signature key** -- non-repudiation per eIDAS
    /// QES. PIN2-gated, key ref 0x02, EF.4332 cert.
    Qualified,
}

impl SignSlot {
    /// PKCS#15 key reference for this signing slot.
    ///
    /// FINEID S1 v4.2 §3.5 -- auth key uses `KeyRef::Auth`
    /// (ref `0x01`), qualified-signature key uses
    /// `KeyRef::Sign` (ref `0x02`). Used as the `MSE:SET DST`
    /// data byte.
    const fn key_ref(self) -> KeyRef {
        match self {
            Self::Auth => KeyRef::Auth,
            Self::Qualified => KeyRef::Sign,
        }
    }
    /// PIN slot that gates use of this signing key.
    ///
    /// FINEID S1 v4.2 §3.5 -- PIN1 -> auth key, PIN2 ->
    /// qualified-signature key. Used so the verify-PIN step
    /// before the signing APDU pulls the right slot's
    /// counter.
    const fn pin_slot(self) -> PinSlot {
        match self {
            Self::Auth => PinSlot::Pin1,
            Self::Qualified => PinSlot::Pin2,
        }
    }
    /// PKCS#15 certificate slot whose public key pairs with
    /// this signing key for the verify-after-sign step
    /// (Rule E7).
    ///
    /// EF.4331 for auth, EF.4332 for qualified. The cert is
    /// read once at session start and reused by the local
    /// verify before the signature is handed back.
    const fn cert_slot(self) -> CertSlot {
        match self {
            Self::Auth => CertSlot::Authentication,
            Self::Qualified => CertSlot::Signature,
        }
    }
    /// Human label for the PIN slot, used in CLI prompts and
    /// the `Display` impl. `"PIN1"` / `"PIN2"` -- matches the
    /// labels printed on FINEID activation letters so the
    /// cardholder sees the same wording in both places.
    const fn pin_label(self) -> &'static str {
        match self {
            Self::Auth => "PIN1",
            Self::Qualified => "PIN2",
        }
    }
    /// Human label for the signing slot itself, used in the
    /// report header (`"auth"` / `"qualified-signature"`).
    /// Distinct from [`Self::pin_label`] because the PIN and
    /// slot labels appear on different lines.
    const fn slot_label(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Qualified => "qualified-signature",
        }
    }
}

/// Inputs.
#[derive(Debug)]
pub struct SignOptions {
    /// Filesystem path to the message bytes to sign. Loaded
    /// whole-file; the SHA-256 hash is computed inside refineid
    /// and sent to the card via `PSO:HASH` per FINEID S1
    /// v4.2 §3.5.
    pub input: PathBuf,
    /// Where the raw signature is written, created or replaced.
    pub output: PathBuf,
    /// The targeted slot's PIN, obtained after the card is found and
    /// checked, right before VERIFY. Zeroized at function return.
    pub pin: PinSource,
    /// Optional output path for the DER bytes of the on-card cert
    /// that produced the signature. Pairs the signature with the
    /// cert it can be verified against -- enables offline
    /// third-party verify with no card.
    pub save_cert: Option<PathBuf>,
    /// Optional substring match against reader names. Required
    /// when more than one card is present; the picker errors
    /// out rather than guess.
    pub reader_filter: Option<String>,
    /// Card Access Number for the contactless interface, where
    /// the card seals PKCS#15 behind PACE. `None` on the contact
    /// interface. When the seal is hit and this is `None`, the
    /// flow fails with [`SignErrorKind::NeedCan`] so the CLI can
    /// prompt and retry. Never logged.
    pub can: Option<Can>,
}

/// One reader's worth of sign output.
#[derive(Debug, Clone)]
pub struct SignReport {
    /// PC/SC reader name the sign APDU chain landed against.
    /// Tier 0 `String` from `ReaderId::as_str().to_owned()`.
    pub reader: String,
    /// Which sign slot the operation targeted (auth key /
    /// non-repudiation key).
    pub slot: SignSlot,
    /// Length of the input file in bytes.
    pub input_len: u64,
    /// SHA-256 of the input.
    pub input_sha256: Sha256,
    /// Where the signature was written.
    pub signature_path: PathBuf,
    /// Where the cert DER was written, when `save_cert` was set.
    pub cert_path: Option<PathBuf>,
    /// Signature length in bytes (384 for RSA-3072, 96 for P-384).
    pub signature_len: usize,
    /// Subject CN of the on-card cert, when we could parse it.
    pub cert_subject_cn: Option<CommonName>,
    /// PIN retries reported by the card when VERIFY succeeded
    /// without an explicit retry counter. `None` means the card
    /// returned plain `0x9000` (no count surfaced).
    pub pin_retries_after: Option<u8>,
    /// Local-verify outcome.
    ///
    /// Whether refineid re-verified the card-produced signature
    /// against the on-card cert's public key before returning.
    /// Distinguishes "verified ok", "verified failed", and
    /// "skipped" (e.g. ECDSA local verify not yet wired) so the
    /// CLI exit-status and the human report don't conflate the
    /// three.
    pub local_verify: LocalVerifyOutcome,
}

/// Whether refineid re-verified the on-card signature against
/// the cert's public key before reporting success.
#[derive(Debug, Clone)]
pub enum LocalVerifyOutcome {
    /// `verify_pkcs1v15_sha256(pubkey, input, signature)` (RSA
    /// path) or the equivalent ECDSA verify returned `Ok(())`.
    Ok,
    /// Local verify ran and rejected the signature. The carried
    /// string is the diagnostic from the lower-level verifier.
    Failed(String),
    /// Local verify was not performed for this signature. Used
    /// today for the ECDSA-P384 chain (the raw-r||s -> DER
    /// conversion + pub exposure of the verify primitives are
    /// the follow-on commit). Tier 0 `&'static str`; describes
    /// why the skip happened.
    Skipped(&'static str),
}

impl LocalVerifyOutcome {
    /// `true` iff the variant is [`LocalVerifyOutcome::Ok`].
    /// Used by the CLI to map the verify result onto an exit
    /// status without losing the distinction between Failed and
    /// Skipped (both are not-Ok, but only Failed is a sign-flow
    /// failure).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// `true` iff the variant is [`LocalVerifyOutcome::Failed`].
    /// Distinguishes the "verify rejected the signature" case
    /// from [`LocalVerifyOutcome::Skipped`] (verify not run).
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

impl fmt::Display for LocalVerifyOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Failed(s) => write!(f, "FAILED: {s}"),
            Self::Skipped(reason) => write!(f, "skipped ({reason})"),
        }
    }
}

/// Error returned from the sign entrypoints.
///
/// Card-side outcomes that don't preclude further action
/// (wrong-PIN with retries left, etc.) are folded into
/// `PinRejected`; cryptographic and transport failures use
/// the per-stage variants.
#[derive(Debug)]
pub enum SignErrorKind {
    /// Reader-selection failure (none / multiple / bad filter).
    ReaderPick(ReaderPickError),
    /// The card in the reader after the PIN prompt is not the card
    /// checked before it, or its serial could not be read again.
    DisplayedCard(String),
    /// PC/SC connect / transmit error.
    Pcsc(PcscError),
    /// Input file I/O failure (`NotFound`, `PermissionDenied`, ...).
    InputRead {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Signature output I/O failure.
    SignatureWrite {
        /// Filesystem path the write was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// VERIFY of the slot's PIN returned a non-Ok outcome.
    PinRejected {
        /// Which sign slot the VERIFY targeted.
        slot: SignSlot,
        /// Card-side outcome (`WrongPin{retries}`, `Locked`,
        /// `AuthenticationFailed`, ...).
        outcome: VerifyOutcome,
    },
    /// The retry floor refused the VERIFY: the card reports two, one or
    /// no tries left, the PIN blocked, or no readable counter. No APDU
    /// that can spend an attempt went out.
    RetryFloor(RetryFloorRefusal),
    /// PIN entry ended without a PIN; nothing was presented.
    PinEntry(PinEntryError),
    /// Local-policy rejection (PIN length / non-digit) before any
    /// APDU went out. Counter is unaffected.
    PinPolicy {
        /// Which sign slot the would-be VERIFY targeted.
        slot: SignSlot,
        /// Specific local-policy failure (e.g. `TooShort`,
        /// `NonDigit`).
        reason: PinPolicyReason,
    },
    /// Card returned an unexpected status word at one of the
    /// sign-chain stages.
    SignSw {
        /// Pipeline stage label (e.g. "MSE:SET DST",
        /// "PSO:HASH", "PSO:Compute Digital Signature"). Tier 0
        /// `&'static str` from a fixed compile-time set.
        stage: &'static str,
        /// Card-returned status word per ISO 7816-4 §5.1.3.
        /// Tier 0 `u16` -- the typed projection is `StatusWord`
        /// from `lib-core::apdu`; this field carries the raw
        /// wire value for the diagnostic.
        sw: u16,
    },
    /// Card returned a signature with the wrong length (e.g. an
    /// ECDSA card on this RSA-pinned path).
    UnexpectedSignatureLength(usize),
    /// Signing input cannot be represented by the card command.
    InputTooLong(usize),
    /// The on-card cert is missing or unparseable.
    CertUnavailable {
        /// Which sign slot the cert read targeted.
        slot: SignSlot,
        /// Human-readable detail from the cert reader / parser.
        /// Tier 0 `String`; presentational.
        detail: String,
    },
    /// Cert was readable but its public key type is not supported
    /// (not RSA, not ECDSA P-384, or uses explicit EC params).
    UnsupportedKeyType(SignSlot),
    /// Cert carries an EC key on a curve other than secp384r1.
    /// The Newer-scheme sign chain handles only secp384r1 + SHA-384
    /// (S4-1 v4.2 §4.2); the other supported curve OIDs land here
    /// rather than at the wire layer where the card would reject
    /// the algRef byte.
    UnsupportedCurve {
        /// Which sign slot's cert carried the unsupported curve.
        slot: SignSlot,
        /// Curve the cert was issued on.
        curve: EcCurve,
    },
    /// Cert + signature parsed but local PKCS1v15-SHA256 verify
    /// failed -- card returned a signature that doesn't match the
    /// on-card public key over our input.
    LocalVerifyFailed(String),
    /// Lower-level transport / APDU failure not covered by the
    /// per-stage variants. Tier 0 `String`; presentational copy
    /// of the upstream error.
    Transport(String),
    /// The card sealed PKCS#15 behind PACE (contactless
    /// interface) and no CAN was provided to open it.
    NeedCan,
    /// PACE failed with the wrong-CAN signature: card-reported
    /// authentication failure or a mutual-auth tag mismatch.
    BadCan,
    /// PACE establishment failed for a non-CAN reason. Tier 0
    /// `String`; presentational copy of the upstream error.
    Pace(String),
}

impl fmt::Display for SignErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReaderPick(e) => write!(f, "{e}"),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::DisplayedCard(detail) => write!(f, "displayed card: {detail}"),
            Self::InputRead { path, source } => {
                write!(f, "read input {}: {source}", path.display())
            }
            Self::SignatureWrite { path, source } => {
                write!(f, "write signature {}: {source}", path.display())
            }
            Self::PinRejected {
                slot,
                outcome: VerifyOutcome::WrongPin { retries_left },
            } => {
                write!(
                    f,
                    "{} rejected (wrong PIN, {retries_left} retries left)",
                    slot.pin_label()
                )
            }
            Self::PinRejected {
                slot,
                outcome: VerifyOutcome::Locked,
            } => {
                write!(
                    f,
                    "{} is blocked -- card needs a PUK unblock",
                    slot.pin_label()
                )
            }
            Self::PinRejected {
                slot,
                outcome: VerifyOutcome::Other(sw),
            } => {
                write!(f, "{} verify: unexpected SW={sw:#06X}", slot.pin_label())
            }
            Self::PinRejected {
                outcome: VerifyOutcome::Ok,
                ..
            } => write!(f, "internal: PinRejected(Ok) is not an error state"),
            Self::RetryFloor(refusal) => write!(f, "{refusal}"),
            Self::PinEntry(e) => write!(f, "{e}"),
            Self::PinPolicy { slot, reason } => {
                write!(f, "{} rejected locally: {reason}", slot.pin_label())
            }
            Self::SignSw { stage, sw } => {
                write!(f, "sign chain failed at {stage}: SW={sw:#06X}")
            }
            Self::UnexpectedSignatureLength(n) => {
                write!(
                    f,
                    "card returned {n}-byte signature; expected 384 (RSA-3072)"
                )
            }
            Self::InputTooLong(n) => {
                write!(f, "{n}-byte signing input exceeds the card command length")
            }
            Self::CertUnavailable { slot, detail } => {
                write!(
                    f,
                    "{} cert unavailable for local verify: {detail}",
                    slot.slot_label()
                )
            }
            Self::UnsupportedKeyType(slot) => {
                write!(
                    f,
                    "{} cert has an unsupported key type (not RSA, not ECDSA P-384, or explicit EC params)",
                    slot.slot_label()
                )
            }
            Self::UnsupportedCurve { slot, curve } => {
                write!(
                    f,
                    "{} cert is EC on {} ({}-bit); refineid currently only signs ECDSA on secp384r1",
                    slot.slot_label(),
                    curve.label(),
                    curve.bits()
                )
            }
            Self::LocalVerifyFailed(s) => write!(f, "local verify failed: {s}"),
            Self::Transport(s) => write!(f, "transport: {s}"),
            Self::NeedCan => write!(
                f,
                "contactless card: the PKCS#15 application is sealed behind \
                 PACE; provide the CAN (six digits printed on the card front) \
                 via --can or the prompt"
            ),
            Self::BadCan => write!(f, "PACE failed: the CAN did not match the card"),
            Self::Pace(s) => write!(f, "PACE: {s}"),
        }
    }
}

impl core::error::Error for SignErrorKind {}

impl From<PcscError> for SignErrorKind {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

impl From<ReaderPickError> for SignErrorKind {
    fn from(e: ReaderPickError) -> Self {
        Self::ReaderPick(e)
    }
}

/// A card transport that can power-cycle its card, which PACE needs
/// to start from a clean card.
pub(crate) trait CardReset {
    /// Reset the card in place.
    ///
    /// # Errors
    /// The backend's reset failure.
    fn reset_card(&mut self) -> Result<(), PcscError>;
}

impl CardReset for PcscCard {
    fn reset_card(&mut self) -> Result<(), PcscError> {
        self.reset()
    }
}

/// Dispatch the per-cert sign chain: RSA (PKCS#1 v1.5 SHA-256) or
/// ECDSA P-384 SHA-384, returning the raw signature bytes plus the
/// local-verify outcome. Unsupported curves / non-RSA SPKIs raise
/// the typed error kind without doing any APDU.
fn sign_dispatch_by_alg<T: CardTransport>(
    transport: &mut T,
    slot: SignSlot,
    scheme: PinReferenceScheme,
    cert: &Certificate<'_>,
    cert_algorithm: PublicKeyAlgorithm,
    input_bytes: &[u8],
    input_sha256: Sha256,
) -> Result<(Vec<u8>, LocalVerifyOutcome), SignErrorKind> {
    match cert_algorithm {
        PublicKeyAlgorithm::Rsa { .. } => {
            let pubkey = extract_rsa_public_key(cert.spki.as_der())
                .ok_or(SignErrorKind::UnsupportedKeyType(slot))?;
            // The organizational platform has no external-hash
            // PSO:HASH: the off-card digest rides in PSO:CDS's data
            // field there (organizational cards specification
            // §6.6.2.3).
            let signature = match scheme {
                PinReferenceScheme::Citizen => transport
                    .sign_pre_hashed_sha256_rsa(slot.key_ref(), input_sha256)
                    .map_err(sign_err_to_kind)?,
                PinReferenceScheme::Organizational => transport
                    .sign_pre_hashed_sha256_rsa_hash_in_command(slot.key_ref(), input_sha256)
                    .map_err(sign_err_to_kind)?,
            };
            let verify = match pubkey.verify_pkcs1v15_sha256(input_bytes, &signature) {
                Ok(()) => LocalVerifyOutcome::Ok,
                Err(e) => {
                    return Err(SignErrorKind::LocalVerifyFailed(format!("{e}")));
                }
            };
            Ok((signature.into_bytes(), verify))
        }
        PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => {
            let hash_sha384 = Sha384::of(input_bytes);
            let signature = transport
                .sign_pre_hashed_sha384_ecdsa_p384(slot.key_ref(), hash_sha384)
                .map_err(sign_err_to_kind)?;
            let pubkey =
                cert.spki
                    .ec_public_key_point()
                    .ok_or_else(|| SignErrorKind::CertUnavailable {
                        slot,
                        detail: "EC public-key point unavailable from cert SPKI".to_owned(),
                    })?;
            let verify = match pubkey.verify_p384_sha384_raw(signature.clone(), hash_sha384) {
                Ok(()) => LocalVerifyOutcome::Ok,
                Err(e) => {
                    return Err(SignErrorKind::LocalVerifyFailed(format!("{e}")));
                }
            };
            Ok((signature.into_bytes(), verify))
        }
        PublicKeyAlgorithm::Ec(curve) => Err(SignErrorKind::UnsupportedCurve { slot, curve }),
        PublicKeyAlgorithm::EcExplicit { .. } | PublicKeyAlgorithm::Other => {
            Err(SignErrorKind::UnsupportedKeyType(slot))
        }
    }
}

/// Drive the full sign flow for one [`SignSlot`].
///
/// FINEID S1 v4.2 §3.5 + §3.6 + §3.7. Steps:
///
///   1. Open a transport against the picked reader.
///   2. Select the FINEID PKCS#15 application, then the slot's
///      cert; read the SPKI for the local verify step.
///   3. Check the retry floor, obtain the PIN from
///      `options.pin`, VERIFY it; the PIN zeroizes on return
///      (Rule E1).
///   4. MSE:SET DST -> PSO:HASH -> PSO:CDS chain.
///   5. Local verify against the SPKI (Rule E7); refuse to
///      hand back a signature that doesn't verify.
///
/// Returns a [`SignReport`] carrying the signature bytes,
/// local-verify outcome, and audit metadata. Errors surface
/// as [`SignErrorKind`] -- the function never panics across
/// the FFI / CLI boundary.
pub(crate) fn sign_with_slot<B>(
    backend: B,
    slot: SignSlot,
    mut options: SignOptions,
) -> Result<SignReport, SignErrorKind>
where
    B: ReaderBackend<Error = PcscError>,
    B::Transport: CardReset,
{
    let reader_id = backend.pick_single_reader(
        options
            .reader_filter
            .clone()
            .map(refineid_lib_core::backend::ReaderFilter::new),
    )?;

    let input_bytes = std::fs::read(&options.input).map_err(|source| SignErrorKind::InputRead {
        path: options.input.clone(),
        source,
    })?;
    // `Vec<u8>::len()` is bounded by available RAM; `usize`-to-`u64`
    // is a widening conversion on every target we ship (32-bit
    // `usize` fits in `u64`; 64-bit `usize` IS `u64`).
    let input_len: u64 = u64::try_from(input_bytes.len()).unwrap_or(u64::MAX);
    let input_sha256 = Sha256::of(&input_bytes);

    let mut transport = backend.open_session(&reader_id, ReaderAccessCap::Read)?;

    // SELECT the FINEID PKCS#15 application first. The qualified-
    // signature cert (EF.4332) lives under DF.5016 and the card
    // needs the PKCS#15 application active before we can navigate
    // there from the post-ATR state. Without this the SELECT
    // chain on EF.4332 returns SW=6A82 ("file not found"). For
    // the auth slot the read_certificate path does its own SELECT
    // PKCS#15, so this is a no-op-with-extra-APDU there.
    //
    // Over the contactless interface the card refuses every
    // pre-PACE command with SW 6982 -- PKCS#15 only opens inside
    // a PACE secure channel keyed from the CAN. On that answer,
    // establish PACE and run the identical chain through the SM
    // wrapper: the ops traits are generic over `CardTransport`
    // and `SmTransport` is one, so the chain code is shared. The
    // sign key's access condition is plain CHV with no interface
    // restriction (FINEID S4-1 v4.2 s8.1.7-9), which is what
    // licenses contactless signing at all.
    let chain = match transport.select_pkcs15_application() {
        Ok(()) => sign_chain(
            &mut transport,
            slot,
            &mut options,
            &input_bytes,
            input_sha256,
        )?,
        Err(Pkcs15Error::Sw(sw))
            if StatusWord::from_u16(sw) == StatusWord::SecurityNotSatisfied =>
        {
            let Some(can) = options.can else {
                return Err(SignErrorKind::NeedCan);
            };
            // Start PACE from a clean card. The reset clears two
            // states that otherwise make PACE fail for reasons
            // that have nothing to do with the CAN the operator
            // typed: the probe SELECT above (which left the card
            // outside MF, so MSE:Set AT answers SW=0x6999), and a
            // CAN suspended by an earlier failed PACE, which the
            // card reports exactly like a wrong CAN until it is
            // reset (BSI TR-03110-3 §2.4). Both observed on a
            // production card over an ACR1581 PICC slot,
            // 2026-07-24.
            transport
                .reset_card()
                .map_err(|e| SignErrorKind::Pace(format!("reset before PACE: {e}")))?;
            // PACE's MSE:Set AT is only accepted in MF context.
            // The reset lands the card there already; this makes
            // the requirement explicit and survives a backend
            // whose reset leaves selection elsewhere. The proven
            // contactless flow in refineid-lib-ffi does the same.
            transport
                .select_mf()
                .map_err(|e| SignErrorKind::Pace(format!("SELECT MF before PACE: {e}")))?;
            let session =
                pace::run_pace_with_can(&mut transport, can).map_err(|e| pace_err_to_kind(&e))?;
            let mut sm = SmTransport::new(transport, session);
            sm.select_pkcs15_application()
                .map_err(|e| SignErrorKind::CertUnavailable {
                    slot,
                    detail: format!("select pkcs15 app under SM: {e}"),
                })?;
            sign_chain(&mut sm, slot, &mut options, &input_bytes, input_sha256)?
        }
        Err(e) => {
            return Err(SignErrorKind::CertUnavailable {
                slot,
                detail: format!("select pkcs15 app: {e}"),
            });
        }
    };

    let signature_len = chain.signature_bytes.len();
    std::fs::write(&options.output, &chain.signature_bytes).map_err(|source| {
        SignErrorKind::SignatureWrite {
            path: options.output.clone(),
            source,
        }
    })?;

    let cert_path = if let Some(path) = &options.save_cert {
        std::fs::write(path, chain.cert_der.as_bytes()).map_err(|source| {
            SignErrorKind::SignatureWrite {
                path: path.clone(),
                source,
            }
        })?;
        Some(path.clone())
    } else {
        None
    };

    Ok(SignReport {
        reader: reader_id.as_str().to_owned(),
        slot,
        input_len,
        input_sha256,
        signature_path: options.output,
        cert_path,
        signature_len,
        cert_subject_cn: chain.cert_subject_cn,
        pin_retries_after: chain.pin_retries_after,
        local_verify: chain.local_verify,
    })
}

/// Output of [`sign_chain`]: what `sign_with_slot` still needs
/// once the card-facing work is done.
struct SignChainOutput {
    /// DER of the slot cert that produced the signature.
    cert_der: CertDer,
    /// Subject CN for the report.
    cert_subject_cn: Option<CommonName>,
    /// Retry count surfaced by a non-Ok VERIFY status word; see
    /// [`SignReport::pin_retries_after`].
    pin_retries_after: Option<u8>,
    /// Raw signature bytes off the card.
    signature_bytes: Vec<u8>,
    /// Rule E7 local-verify outcome.
    local_verify: LocalVerifyOutcome,
}

/// The card-facing sign chain both interface paths share once
/// the PKCS#15 application is selected on `transport`: cert
/// read + parse, VERIFY of the slot PIN, and the MSE/PSO sign
/// dispatch with its local verify. Generic over
/// [`CardTransport`] so the same code runs on the plain contact
/// channel and inside the PACE [`SmTransport`] on contactless.
fn sign_chain<T: CardTransport>(
    transport: &mut T,
    slot: SignSlot,
    options: &mut SignOptions,
    input_bytes: &[u8],
    input_sha256: Sha256,
) -> Result<SignChainOutput, SignErrorKind> {
    let cert_der = transport
        .read_certificate(slot.cert_slot())
        .or_else(|_| {
            let alt = match slot.cert_slot() {
                CertSlot::Authentication => CertSlot::AuthenticationAlt,
                CertSlot::Signature => CertSlot::SignatureAlt,
                other => other,
            };
            transport.read_certificate(alt)
        })
        .map_err(|e| SignErrorKind::CertUnavailable {
            slot,
            detail: format!("read: {e}"),
        })?;
    let cert_owned =
        OwnedCert::from_der(cert_der.as_bytes()).map_err(|e| SignErrorKind::CertUnavailable {
            slot,
            detail: format!("parse: {e}"),
        })?;
    // Bind the view once: `view()` re-parses the DER on each call.
    let cert = cert_owned.view();
    let cert_subject_cn = cert.subject.common_name();
    let cert_algorithm = cert.spki.algorithm();

    // The reference numbering is the card's to declare (citizen
    // S1 v4.2 vs organizational S4-2 v4.0), resolved by
    // counter-safe probes before the typed PIN is spent.
    let scheme = transport
        .resolve_pin_reference_scheme()
        .map_err(|e| match e {
            AuthError::Transport(t) => SignErrorKind::Transport(format!("{t}")),
            AuthError::PinPolicy(reason) => SignErrorKind::PinPolicy { slot, reason },
        })?;
    let status = transport
        .pin_status_with_scheme(slot.pin_slot(), scheme)
        .map_err(|e| match e {
            AuthError::Transport(t) => SignErrorKind::Transport(format!("{t}")),
            AuthError::PinPolicy(reason) => SignErrorKind::PinPolicy { slot, reason },
        })?;
    check_retry_floor(slot.pin_slot(), status).map_err(SignErrorKind::RetryFloor)?;
    // The prompt is the one moment the card is out of the flow's hands,
    // so the card that answers VERIFY must be the card that was checked.
    let bound = live_token_serial(transport)?;
    let pin = options.pin.obtain().map_err(SignErrorKind::PinEntry)?;
    if live_token_serial(transport)? != bound {
        return Err(SignErrorKind::DisplayedCard(
            CARD_CHANGED_DURING_PROMPT.to_owned(),
        ));
    }
    let outcome = transport
        .verify_pin_with_scheme(slot.pin_slot(), scheme, pin)
        .map_err(|e| match e {
            AuthError::Transport(t) => SignErrorKind::Transport(format!("{t}")),
            AuthError::PinPolicy(reason) => SignErrorKind::PinPolicy { slot, reason },
        })?;
    let pin_retries_after = match outcome {
        VerifyOutcome::Ok => None,
        rejected @ (VerifyOutcome::WrongPin { .. }
        | VerifyOutcome::Locked
        | VerifyOutcome::Other(_)) => {
            return Err(SignErrorKind::PinRejected {
                slot,
                outcome: rejected,
            });
        }
    };

    // Branch on cert public-key shape per FINEID S4-1 v4.2 §4.2:
    // Older-scheme cards have an RSA-3072 auth key; Newer-scheme
    // cards have ECC P-384 (secp384r1) + SHA-384. The PSO chain
    // selects the right algRef, the right PSO:HASH hash size,
    // and the right signature-length expectation for each.
    let (signature_bytes, local_verify) = sign_dispatch_by_alg(
        transport,
        slot,
        scheme,
        &cert,
        cert_algorithm,
        input_bytes,
        input_sha256,
    )?;

    Ok(SignChainOutput {
        cert_der,
        cert_subject_cn,
        pin_retries_after,
        signature_bytes,
        local_verify,
    })
}

/// The refusal when the card in the reader is not the one the PIN was
/// entered for.
pub(crate) const CARD_CHANGED_DURING_PROMPT: &str = "the card changed while the PIN was entered";

/// The serial of the card in the reader, as EF.TokenInfo names it.
fn live_token_serial<T: CardTransport>(
    transport: &mut T,
) -> Result<Option<TokenSerial>, SignErrorKind> {
    let token = transport.read_token_info().map_err(|error| {
        SignErrorKind::DisplayedCard(format!("cannot re-read EF.TokenInfo: {error}"))
    })?;
    Ok(token.serial_number_hex.map(render_token_serial))
}

/// Hoist [`pace::PaceError`] onto [`SignErrorKind`], with the
/// same wrong-CAN classification `emrtd::read_personal_data`
/// applies: a card-reported authentication failure or a
/// mutual-auth tag mismatch both mean the CAN-derived key
/// disagreed with the card.
fn pace_err_to_kind<TE: fmt::Display>(e: &pace::PaceError<TE>) -> SignErrorKind {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "PaceError is #[non_exhaustive]; the fallback arm absorbs every non-CAN variant into the presentational Pace(String)"
    )]
    match e {
        pace::PaceError::Sw(_, sw)
            if StatusWord::from_u16(*sw) == StatusWord::AuthenticationFailed =>
        {
            SignErrorKind::BadCan
        }
        pace::PaceError::AuthMismatch => SignErrorKind::BadCan,
        _ => SignErrorKind::Pace(format!("{e}")),
    }
}

/// Hoist [`SignError`] (lib-core) variants onto
/// [`SignErrorKind`] (client). Kept as a single function so the
/// RSA and ECDSA branches of `sign_with_slot` use the same
/// mapping.
fn sign_err_to_kind<TE: fmt::Display>(e: SignError<TE>) -> SignErrorKind {
    match e {
        SignError::Transport(t) => SignErrorKind::Transport(format!("{t}")),
        SignError::Sw(stage, sw) => SignErrorKind::SignSw { stage, sw },
        SignError::UnexpectedSignatureLength(n) => SignErrorKind::UnexpectedSignatureLength(n),
        SignError::InputTooLong(n) => SignErrorKind::InputTooLong(n),
    }
}

/// Auth-slot wrapper kept for the existing CLI subcommand.
///
/// # Errors
/// See [`sign_with_slot`].
pub(crate) fn sign_auth_first(
    backend: PcscBackend,
    options: SignOptions,
) -> Result<SignReport, SignErrorKind> {
    sign_with_slot(backend, SignSlot::Auth, options)
}

/// Qualified-signature wrapper. PIN2-gated.
///
/// # Errors
/// See [`sign_with_slot`].
pub(crate) fn sign_qualified_first(
    backend: PcscBackend,
    options: SignOptions,
) -> Result<SignReport, SignErrorKind> {
    sign_with_slot(backend, SignSlot::Qualified, options)
}

impl fmt::Display for SignReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        writeln!(
            f,
            "slot: {} (key ref {:#04X})",
            self.slot.slot_label(),
            self.slot.key_ref().as_u8()
        )?;
        if let Some(cn) = &self.cert_subject_cn {
            writeln!(f, "cert subject CN: {cn}")?;
        }
        writeln!(f, "input length: {} bytes", self.input_len)?;
        writeln!(f, "input sha256: {}", self.input_sha256)?;
        writeln!(
            f,
            "output: {} ({} bytes)",
            self.signature_path.display(),
            self.signature_len
        )?;
        writeln!(f, "card signature: {} bytes", self.signature_len)?;
        if let Some(p) = &self.cert_path {
            writeln!(f, "cert DER: {}", p.display())?;
        }
        if let Some(r) = self.pin_retries_after {
            writeln!(f, "{} retries after verify: {r}", self.slot.pin_label())?;
        }
        writeln!(
            f,
            "local verify (against on-card {} cert pubkey): {}",
            self.slot.slot_label(),
            self.local_verify,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check, check_true};
    use refineid_lib_core::apdu::status_word::PinRetries;

    // ---- SignSlot: the FINEID slot -> {key ref, PIN, cert}
    // mapping (S1 v4.2 §3.5). Getting any of these wrong signs
    // with the wrong key or gates on the wrong PIN, so the table
    // is pinned explicitly. ----

    #[test]
    fn auth_slot_maps_to_pin1_keyref01_ef4331() -> TestResult {
        let s = SignSlot::Auth;
        check(&s.key_ref().as_u8(), &0x01_u8, "auth key ref")?;
        check_true(matches!(s.pin_slot(), PinSlot::Pin1), "auth pin slot")?;
        check_true(
            matches!(s.cert_slot(), CertSlot::Authentication),
            "auth cert slot",
        )?;
        check(&s.pin_label(), &"PIN1", "auth pin label")?;
        check(&s.slot_label(), &"auth", "auth slot label")
    }

    #[test]
    fn qualified_slot_maps_to_pin2_keyref02_ef4332() -> TestResult {
        let s = SignSlot::Qualified;
        check(&s.key_ref().as_u8(), &0x02_u8, "qualified key ref")?;
        check_true(matches!(s.pin_slot(), PinSlot::Pin2), "qualified pin slot")?;
        check_true(
            matches!(s.cert_slot(), CertSlot::Signature),
            "qualified cert slot",
        )?;
        check(&s.pin_label(), &"PIN2", "qualified pin label")?;
        check(
            &s.slot_label(),
            &"qualified-signature",
            "qualified slot label",
        )
    }

    #[test]
    fn local_verify_predicates_separate_ok_failed_skipped() -> TestResult {
        check_true(LocalVerifyOutcome::Ok.is_ok(), "Ok.is_ok")?;
        check_true(!LocalVerifyOutcome::Ok.is_failed(), "Ok.is_failed")?;

        let failed = LocalVerifyOutcome::Failed("nope".to_owned());
        check_true(!failed.is_ok(), "Failed.is_ok")?;
        check_true(failed.is_failed(), "Failed.is_failed")?;

        let skipped = LocalVerifyOutcome::Skipped("ECDSA verify not wired");
        check_true(!skipped.is_ok(), "Skipped.is_ok")?;
        check_true(!skipped.is_failed(), "Skipped.is_failed")
    }

    #[test]
    fn local_verify_display() -> TestResult {
        check(&LocalVerifyOutcome::Ok.to_string(), &"ok".to_owned(), "ok")?;
        check(
            &LocalVerifyOutcome::Failed("bad sig".to_owned()).to_string(),
            &"FAILED: bad sig".to_owned(),
            "failed",
        )?;
        check(
            &LocalVerifyOutcome::Skipped("p384").to_string(),
            &"skipped (p384)".to_owned(),
            "skipped",
        )
    }

    fn pin_retries(n: u8) -> Result<PinRetries, Box<dyn core::error::Error>> {
        PinRetries::from_nibble(n).ok_or_else(|| "bad nibble".into())
    }

    #[test]
    fn pin_rejected_display_renders_slot_and_outcome() -> TestResult {
        let wrong = SignErrorKind::PinRejected {
            slot: SignSlot::Auth,
            outcome: VerifyOutcome::WrongPin {
                retries_left: pin_retries(2)?,
            },
        }
        .to_string();
        check_true(wrong.contains("PIN1"), "wrong-pin slot label")?;
        check_true(wrong.contains("wrong PIN"), "wrong-pin reason")?;
        check_true(wrong.contains("retries left"), "wrong-pin counter")?;

        let locked = SignErrorKind::PinRejected {
            slot: SignSlot::Qualified,
            outcome: VerifyOutcome::Locked,
        }
        .to_string();
        check_true(locked.contains("PIN2"), "locked slot label")?;
        check_true(locked.contains("blocked"), "locked reason")?;

        let other = SignErrorKind::PinRejected {
            slot: SignSlot::Auth,
            outcome: VerifyOutcome::Other(0x6A88),
        }
        .to_string();
        check_true(other.contains("0x6A88"), "other sw rendered")?;

        // The internal "can't happen" arm still renders a line
        // rather than panicking.
        let internal = SignErrorKind::PinRejected {
            slot: SignSlot::Auth,
            outcome: VerifyOutcome::Ok,
        }
        .to_string();
        check_true(internal.contains("internal"), "ok-outcome guard")
    }

    #[test]
    fn sign_chain_and_crypto_error_display() -> TestResult {
        check_true(
            SignErrorKind::PinPolicy {
                slot: SignSlot::Auth,
                reason: PinPolicyReason::NonDigit,
            }
            .to_string()
            .contains("PIN1 rejected locally"),
            "pin policy",
        )?;
        check_true(
            SignErrorKind::SignSw {
                stage: "PSO:HASH",
                sw: 0x6A80,
            }
            .to_string()
            .contains("PSO:HASH: SW=0x6A80"),
            "sign sw stage + sw",
        )?;
        check_true(
            SignErrorKind::UnexpectedSignatureLength(256)
                .to_string()
                .contains("256-byte signature; expected 384"),
            "bad sig length",
        )?;
        check_true(
            SignErrorKind::CertUnavailable {
                slot: SignSlot::Auth,
                detail: "read: timeout".to_owned(),
            }
            .to_string()
            .contains("auth cert unavailable for local verify: read: timeout"),
            "cert unavailable",
        )?;
        check_true(
            SignErrorKind::UnsupportedKeyType(SignSlot::Qualified)
                .to_string()
                .contains("qualified-signature cert has an unsupported key type"),
            "unsupported key type",
        )?;
        check_true(
            SignErrorKind::UnsupportedCurve {
                slot: SignSlot::Auth,
                curve: EcCurve::Secp256r1,
            }
            .to_string()
            .contains("only signs ECDSA on secp384r1"),
            "unsupported curve",
        )?;
        check_true(
            SignErrorKind::LocalVerifyFailed("digest mismatch".to_owned())
                .to_string()
                .contains("local verify failed: digest mismatch"),
            "local verify failed",
        )?;
        check_true(
            SignErrorKind::Transport("reader vanished".to_owned())
                .to_string()
                .contains("transport: reader vanished"),
            "transport",
        )
    }

    #[test]
    fn io_error_display_includes_path() -> TestResult {
        let err = SignErrorKind::InputRead {
            path: PathBuf::from("/tmp/msg"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
        };
        let s = err.to_string();
        check_true(s.contains("/tmp/msg"), "io error path")?;
        check_true(s.contains("no such file"), "io error source")
    }

    // ---- sign_err_to_kind: lib-core SignError -> client
    // SignErrorKind, shared by the RSA and ECDSA branches. ----

    #[test]
    fn sign_err_to_kind_maps_each_variant() -> TestResult {
        check_true(
            matches!(
                sign_err_to_kind(SignError::<&str>::Transport("boom")),
                SignErrorKind::Transport(_)
            ),
            "transport",
        )?;
        check_true(
            matches!(
                sign_err_to_kind(SignError::<&str>::Sw("PSO:CDS", 0x6982)),
                SignErrorKind::SignSw {
                    stage: "PSO:CDS",
                    sw: 0x6982
                }
            ),
            "sw",
        )?;
        check_true(
            matches!(
                sign_err_to_kind(SignError::<&str>::UnexpectedSignatureLength(48)),
                SignErrorKind::UnexpectedSignatureLength(48)
            ),
            "unexpected length",
        )
    }

    // ---- SignReport Display ----

    fn sample_report(cn: Option<CommonName>) -> SignReport {
        SignReport {
            reader: "OMNIKEY 5422".to_owned(),
            slot: SignSlot::Auth,
            input_len: 11,
            input_sha256: Sha256::of(b"hello world"),
            signature_path: PathBuf::from("/tmp/out.sig"),
            cert_path: Some(PathBuf::from("/tmp/out.crt")),
            signature_len: 384,
            cert_subject_cn: cn,
            pin_retries_after: None,
            local_verify: LocalVerifyOutcome::Ok,
        }
    }

    #[test]
    fn sign_report_display_renders_all_present_fields() -> TestResult {
        // Pull a real CommonName off a bundled cert rather than
        // constructing one (the field is private to lib-core).
        let cert = OwnedCert::from_der(
            include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-rsa.der").as_slice(),
        )
        .map_err(|e| format!("parse anchor: {e}"))?;
        let cn = cert.view().subject.common_name();
        check_true(cn.is_some(), "anchor has a CN")?;

        let s = sample_report(cn).to_string();
        check_true(s.contains("reader: OMNIKEY 5422"), "reader line")?;
        check_true(
            s.contains("slot: auth (key ref 0x01)"),
            "slot line with key ref",
        )?;
        check_true(s.contains("cert subject CN: DVV"), "subject cn line")?;
        check_true(s.contains("input length: 11 bytes"), "input length")?;
        check_true(s.contains("input sha256: "), "input sha256")?;
        check_true(
            s.contains("output: /tmp/out.sig (384 bytes)"),
            "output line",
        )?;
        check_true(
            s.contains("card signature: 384 bytes"),
            "card signature line",
        )?;
        check_true(s.contains("cert DER: /tmp/out.crt"), "cert der line")?;
        check_true(
            s.contains("local verify (against on-card auth cert pubkey): ok"),
            "local verify line",
        )
    }

    #[test]
    fn sign_report_display_omits_absent_optionals() -> TestResult {
        // No CN, no saved cert, no retry counter -> those lines
        // are skipped entirely.
        let s = sample_report(None).to_string();
        check_true(!s.contains("cert subject CN:"), "no cn line")?;
        // cert_path is Some in sample_report; flip it for this case.
        let mut report = sample_report(None);
        report.cert_path = None;
        let s2 = report.to_string();
        check_true(!s2.contains("cert DER:"), "no cert der line")?;
        check_true(!s2.contains("retries after verify"), "no retry line")
    }

    // ---- The PIN is asked for only once the card is found and its
    // counter served. ----

    use crate::pin_source::test_support::{counting_source, prompts};
    use crate::test_card::{SyntheticBackend, SyntheticCard, TRIES_BELOW_FLOOR, TRIES_SERVED};
    use crate::test_util::TempDir;

    /// Synthetic message to sign.
    const MESSAGE: &[u8] = b"synthetic message";

    fn sign_on(
        backend: SyntheticBackend,
    ) -> Result<(Result<SignReport, SignErrorKind>, usize), Box<dyn core::error::Error>> {
        let dir = TempDir::new("sign-pin-late")?;
        let input = dir.write("message.txt", MESSAGE)?;
        let (pin, asked) = counting_source();
        let options = SignOptions {
            input,
            output: dir.path().join("signature.bin"),
            pin,
            save_cert: None,
            reader_filter: None,
            can: None,
        };
        let result = sign_with_slot(backend, SignSlot::Auth, options);
        Ok((result, prompts(&asked)))
    }

    #[test]
    fn no_reader_fails_before_the_pin_is_asked() -> TestResult {
        let backend = SyntheticBackend {
            readers: Vec::new(),
            card: SyntheticCard::with_tries(TRIES_SERVED)?,
        };
        let (result, asked) = sign_on(backend)?;
        check_true(
            matches!(
                result,
                Err(SignErrorKind::ReaderPick(ReaderPickError::NoReaders))
            ),
            "no readers",
        )?;
        check(&asked, &0, "prompts")
    }

    #[test]
    fn no_card_fails_before_the_pin_is_asked() -> TestResult {
        let backend = SyntheticBackend::one_reader(false, SyntheticCard::with_tries(TRIES_SERVED)?);
        let (result, asked) = sign_on(backend)?;
        check_true(
            matches!(
                result,
                Err(SignErrorKind::ReaderPick(ReaderPickError::NoCardPresent))
            ),
            "no card",
        )?;
        check(&asked, &0, "prompts")
    }

    #[test]
    fn retry_floor_refuses_before_the_pin_is_asked() -> TestResult {
        let backend =
            SyntheticBackend::one_reader(true, SyntheticCard::with_tries(TRIES_BELOW_FLOOR)?);
        let (result, asked) = sign_on(backend)?;
        check_true(
            matches!(result, Err(SignErrorKind::RetryFloor(_))),
            "retry floor",
        )?;
        check(&asked, &0, "prompts")
    }

    /// The synthetic card cannot make a signature that verifies, so the
    /// flow ends at local verify -- after the one VERIFY it asked for.
    #[test]
    fn a_served_card_asks_for_the_pin_once() -> TestResult {
        let backend = SyntheticBackend::one_reader(true, SyntheticCard::with_tries(TRIES_SERVED)?);
        let (result, asked) = sign_on(backend)?;
        check_true(
            matches!(
                result,
                Err(SignErrorKind::LocalVerifyFailed(_)
                    | SignErrorKind::UnexpectedSignatureLength(_))
            ),
            "flow passed VERIFY",
        )?;
        check(&asked, &1, "prompts")
    }
}
