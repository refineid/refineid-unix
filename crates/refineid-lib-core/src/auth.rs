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

//! VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, and counter-safe
//! PIN/PUK status probes, delegated to `refineid-auth`.
//!
//! Every credential-carrying command passes through `refineid-auth`, which
//! builds the wire APDU inside a zeroizing `CredentialCommand`, probes the
//! credential's retry counter before sending credential bytes, and enforces
//! the shared retry floor.

pub use refineid_auth::credentials::{
    FINEID_PIN1_MIN_LENGTH, FINEID_PIN2_MIN_LENGTH, PIN_MAX_LENGTH, PIN_MIN_LENGTH, PUK_MAX_LENGTH,
    PUK_MIN_LENGTH,
};
pub use refineid_auth::verify::VERIFY_INS;
pub use refineid_auth::{
    ActivationReport, ActivationScheme, CardActivationNeeds, CardPinLengths,
    CredentialHealthReport, CredentialLengths, FlooredCredential, ManageOutcome, PIN_STORED_LENGTH,
    PIN1_REFERENCE as PIN1_REFERENCE_PKCS15, PIN1_REFERENCE_ESTONIAN,
    PIN1_REFERENCE_ORGANIZATIONAL, PIN2_REFERENCE as PIN2_REFERENCE_PKCS15,
    PIN2_REFERENCE_ESTONIAN, PIN2_REFERENCE_ORGANIZATIONAL, PUK_REFERENCE as PUK_REFERENCE_PKCS15,
    PUK_REFERENCE_ESTONIAN, PUK_REFERENCE_ORGANIZATIONAL, PasswordLengthRange, PinChangeRecord,
    PinManageOps, PinReferenceScheme, PinSlot, PinStatus, RetryFloorRefusal, VerifyOutcome,
    classify_manage_sw, classify_pin_status_sw, classify_verify_sw,
    pin1_status_permits_reusable_cache, read_pin_change_record, read_puk_status_from_container,
};

use refineid_apdu::{ApduClass, CommandHeader};

use crate::apdu::status_word::{PinRetries, StatusWord};
use crate::pin::PinBytes;
use crate::pkcs15::Pkcs15Ops as _;
use crate::transport::{
    CardTransport, CommandApdu, TransportDispatchError, TransportErrorExt, TransportErrorKind,
    TransportOutcome,
};
use crate::x509::DateTime;

/// Shortened alias for the transport-error variant produced by a
/// dispatch on a `CardTransport`-implementing type.
type TxError<T> = TransportDispatchError<<T as CardTransport>::Error>;

/// FINEID stored-length for PIN1 (alias of [`PIN_STORED_LENGTH`]).
pub const PIN1_STORED_LENGTH: usize = PIN_STORED_LENGTH;
/// FINEID stored-length for PIN2 (alias of [`PIN_STORED_LENGTH`]).
pub const PIN2_STORED_LENGTH: usize = PIN_STORED_LENGTH;
/// FINEID stored-length for PUK (alias of [`PIN_STORED_LENGTH`]).
pub const PUK_STORED_LENGTH: usize = PIN_STORED_LENGTH;

/// Padding byte applied to the right of typed ASCII digits on citizen cards.
pub const PIN_PAD_BYTE: u8 = refineid_auth::verify::FINEID_PAD_OCTET;

/// The try limit PIN 1, PIN 2 and the PUK are personalized with on citizen
/// and organizational FINEID cards.
pub const PIN_TRY_LIMIT: u8 = PinReferenceScheme::Citizen.pin_retry_limit();

/// `SW1` of ISO 7816-4 §5.6 `6Cxx`: wrong `Le`, `SW2` the exact length
/// the card has.
const WRONG_LE_SW1: u8 = 0x6C;

/// FINEID S1 v4.2 §3.15.2 `GET DATA` instruction byte (odd variant).
const GET_DATA_INS: u8 = 0xCB;
/// FINEID S1 v4.2 §3.15.2 `GET DATA` P1 for the PIN container.
const GET_DATA_P1: u8 = 0x00;
/// FINEID S1 v4.2 §3.15.2 `GET DATA` P2 for the PIN container.
const GET_DATA_P2: u8 = 0xFF;
/// Expected response length byte requesting all available bytes.
const GET_DATA_LE: u8 = 0x00;
/// Constructed template tag in the PIN-container request (`A0 03 83 01 <ref>`).
const PIN_CONTAINER_TEMPLATE_TAG: u8 = 0xA0;
/// Length of the inner PIN-reference TLV inside the request template.
const PIN_CONTAINER_TEMPLATE_LEN: u8 = 0x03;
/// PIN-reference tag inside the PIN-container request template.
const PIN_CONTAINER_REF_TAG: u8 = 0x83;
/// Length of the single-byte PIN reference.
const PIN_CONTAINER_REF_LEN: u8 = 0x01;

/// `true` when `slot` under `scheme` is the PIN 2 local to `DF.ESIGN`:
/// the organizational card's qualified-signature PIN.
#[must_use]
pub const fn gates_esign_directory(scheme: PinReferenceScheme, slot: PinSlot) -> bool {
    matches!(
        (scheme, slot),
        (PinReferenceScheme::Organizational, PinSlot::Pin2)
    )
}

/// Decide the card's activation procedure (FINEID S4-1 v4.2 §4.6) from its
/// resolved credential numbering and authentication certificate validity start,
/// delegating to `refineid-auth`.
#[must_use]
pub fn activation_scheme_for_card(
    numbering: PinReferenceScheme,
    validity_start: Option<DateTime>,
) -> Option<ActivationScheme> {
    let validity_start_seconds =
        validity_start.and_then(|start| i64::try_from(start.unix_duration().as_secs()).ok());
    ActivationScheme::from_numbering_and_validity_start(numbering, validity_start_seconds)
}

/// Whether one PIN still awaits activation (FINEID S4-1 v4.2 §4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinReadiness {
    /// The PIN is in its factory state and awaits activation.
    AwaitsActivation,
    /// The holder has set the PIN.
    Activated,
    /// The card's answers decide neither. Every consumer treats it
    /// as [`Self::Activated`]: activation refuses it, a change meets
    /// only the retry floor.
    Undecided,
}

impl PinReadiness {
    /// Judge one PIN from its PIN changed flag (FINEID S1 v4.2
    /// §3.15.3) and its counter-safe status probe.
    ///
    /// Delegates the factory-activation decision to
    /// [`refineid_auth::pin_awaits_activation`] while distinguishing
    /// [`Self::Activated`] from [`Self::Undecided`] when the flag is absent.
    #[must_use]
    pub const fn judge(
        scheme: Option<ActivationScheme>,
        changed: Option<bool>,
        status: Option<PinStatus>,
    ) -> Self {
        match changed {
            Some(false) => Self::AwaitsActivation,
            Some(true) => Self::Activated,
            None => match (scheme, status) {
                (Some(scheme @ ActivationScheme::ActivationCodeIsPuk), Some(status)) => {
                    if refineid_auth::pin_awaits_activation(
                        scheme,
                        PinChangeRecord::Unreadable,
                        status,
                    ) {
                        Self::AwaitsActivation
                    } else if matches!(status, PinStatus::Remaining(_) | PinStatus::Verified) {
                        Self::Activated
                    } else {
                        Self::Undecided
                    }
                }
                (Some(ActivationScheme::ActivationCodeIsPuk), None)
                | (Some(ActivationScheme::PresetActivationPin) | None, _) => Self::Undecided,
            },
        }
    }
}

/// The retry floor from `refineid-auth`, applied to a status probed under
/// `scheme`: a command that can spend a `slot` attempt is sent only within
/// the card profile's safe retry counts, or when the PIN is already verified.
///
/// # Errors
/// [`RetryFloorRefusal`] naming the PIN and the state that refused it.
pub fn check_retry_floor(
    slot: PinSlot,
    status: PinStatus,
    scheme: PinReferenceScheme,
) -> Result<(), RetryFloorRefusal> {
    refineid_auth::check_retry_floor_with_scheme(slot.into(), status, scheme)
}

/// The same retry floor applied to the PUK's own counter under `scheme`.
///
/// # Errors
/// [`RetryFloorRefusal`] naming the PUK and the state that refused it.
pub fn check_puk_retry_floor(
    status: PukStatus,
    scheme: PinReferenceScheme,
) -> Result<(), RetryFloorRefusal> {
    refineid_auth::check_retry_floor_with_scheme(FlooredCredential::Puk, status.into(), scheme)
}

/// Outcome of the counter-safe PUK retry probe through the FINEID
/// PIN-container `GET DATA` command from S1 v4.2 section 3.15.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PukStatus {
    /// PIN-container attributes report X PUK presentations remain.
    Remaining(PinRetries),
    /// The card supplied no parseable retry-counter value.
    NoInfo,
    /// Blocked PUK (`AuthenticationBlocked`).
    Locked,
    /// Invalidated PUK or recovery data (`ReferenceDataInvalidated`).
    Invalidated,
    /// Any other status word, preserved for diagnostics.
    Other(u16),
}

impl From<PukStatus> for PinStatus {
    fn from(status: PukStatus) -> Self {
        match status {
            PukStatus::Remaining(retries) => Self::Remaining(retries),
            PukStatus::NoInfo => Self::NoInfo,
            PukStatus::Locked | PukStatus::Invalidated => Self::Locked,
            PukStatus::Other(sw) => Self::Other(StatusWord::from_u16(sw)),
        }
    }
}

/// Project a `refineid-auth` PUK [`PinStatus`] into [`PukStatus`].
const fn pin_status_to_puk_status(status: PinStatus) -> PukStatus {
    match status {
        PinStatus::Remaining(retries) => PukStatus::Remaining(retries),
        PinStatus::Verified | PinStatus::NoInfo => PukStatus::NoInfo,
        PinStatus::Locked => PukStatus::Locked,
        PinStatus::Other(sw) => PukStatus::Other(sw.as_u16()),
    }
}

/// Card-reported credential usage allowance from FINEID S1 v4.2
/// section 3.15.3, PIN attributes field 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageCounter {
    /// No successful uses remain.
    Exhausted,
    /// A finite number of successful uses remain.
    Limited(std::num::NonZeroU8),
    /// The card reports no usage limit.
    NoLimit,
}

/// Card-reported PIN recovery allowance from FINEID S1 v4.2
/// section 3.15.3, PIN attributes field 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnblockingCounter {
    /// No recoveries remain, or recovery is not applicable to this
    /// credential.
    Exhausted,
    /// A finite number of recoveries remain.
    Limited(std::num::NonZeroU8),
    /// The card reports no recovery limit.
    NoLimit,
}

/// Typed policy counters returned by the card's counter-safe PIN-info
/// `GET DATA` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialPolicyCounters {
    /// Successful-use allowance for the queried credential.
    pub usage: UsageCounter,
    /// Recovery allowance for the queried credential.
    pub unblocking: UnblockingCounter,
}

/// Reasons a PIN gets rejected locally, before any APDU goes out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinPolicyReason {
    /// Typed length is outside the lengths the credential accepts.
    WrongLength {
        /// Minimum length the slot accepts.
        min: usize,
        /// Maximum length the slot accepts.
        max: usize,
    },
    /// Non-digit ASCII byte encountered. PIN bytes must all
    /// be in `b'0'..=b'9'`.
    NonDigit,
    /// The card's range for the credential shares no length with
    /// what the credential's block carries, so no entry is accepted.
    NoAcceptedLength,
}

impl core::fmt::Display for PinPolicyReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength { min, max } => {
                write!(f, "pin length outside accepted range {min}..={max}")
            }
            Self::NonDigit => {
                write!(f, "pin must contain only ASCII digits")
            }
            Self::NoAcceptedLength => {
                write!(f, "this card lists no length that can be set")
            }
        }
    }
}

/// VERIFY and PIN-management path errors.
#[derive(Debug)]
pub enum AuthError<TE> {
    /// Transport-layer failure -- PC/SC error, reader removed,
    /// card reset, etc.
    Transport(TE),
    /// Locally-rejected PIN; no APDU was sent.
    PinPolicy(PinPolicyReason),
    /// The retry floor refused the credential before any credential-bearing
    /// command was sent.
    RetryFloor(RetryFloorRefusal),
    /// The requested PIN slot is not supported in this application
    /// context under `scheme`; no APDU was sent.
    UnsupportedSlot {
        /// Credential numbering resolved for the card.
        scheme: PinReferenceScheme,
        /// The PIN slot that cannot be addressed in this context.
        slot: PinSlot,
    },
    /// Internal command-assembly or read-only boundary violation; no
    /// credential command was sent.
    Command(&'static str),
}

impl<TE: core::fmt::Display> core::fmt::Display for AuthError<TE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "auth transport: {e}"),
            Self::PinPolicy(reason) => write!(f, "auth pin policy: {reason}"),
            Self::RetryFloor(refusal) => write!(f, "{refusal}"),
            Self::UnsupportedSlot { scheme, slot } => {
                write!(f, "auth: {slot:?} is not supported under {scheme:?}")
            }
            Self::Command(detail) => write!(f, "auth command: {detail}"),
        }
    }
}

impl<TE: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for AuthError<TE> {}

/// Outcome of a `CHANGE REFERENCE DATA` (PIN rotation) round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangePinOutcome {
    /// PIN replaced, retry counter reset, PIN presentation cleared.
    Ok,
    /// Current PIN was wrong, `retries_left` attempts remain.
    WrongCurrentPin {
        /// Number of attempts remaining before the slot locks.
        retries_left: PinRetries,
    },
    /// Card is blocked or PIN usage counter exhausted.
    Locked,
    /// Card rejected APDU length (`WrongLength`).
    LengthError,
    /// Anything else -- surfaced as opaque SW for the caller.
    Other(u16),
}

/// Outcome of a `RESET RETRY COUNTER` (PUK-driven unblock) round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnblockOutcome {
    /// PUK accepted, target PIN reset to the new value, retry counter reset.
    Ok,
    /// PUK was wrong, `retries_left` attempts remain on the PUK itself.
    WrongPuk {
        /// Number of PUK attempts remaining before permanent lockout.
        retries_left: PinRetries,
    },
    /// PUK itself is blocked; no software recovery.
    PukLocked,
    /// Target PIN's unblocking counter or PUK usage counter is exhausted.
    Invalidated,
    /// Card rejected APDU length (`WrongLength`).
    LengthError,
    /// Anything else -- surfaced as opaque SW for the caller.
    Other(u16),
}

/// Decode the RESET RETRY COUNTER response status word.
#[must_use]
pub const fn classify_reset_retry_sw(sw: StatusWord) -> UnblockOutcome {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "catch-and-wrap: UnblockOutcome::Other(u16) absorbs unenumerated card status words verbatim."
    )]
    match sw {
        StatusWord::Success => UnblockOutcome::Ok,
        StatusWord::PinIncorrect { retries } => UnblockOutcome::WrongPuk {
            retries_left: retries,
        },
        StatusWord::AuthenticationBlocked => UnblockOutcome::PukLocked,
        StatusWord::ReferenceDataInvalidated => UnblockOutcome::Invalidated,
        StatusWord::WrongLength => UnblockOutcome::LengthError,
        other => UnblockOutcome::Other(other.as_u16()),
    }
}

/// Decode the counter-safe PUK retry-query response.
#[must_use]
pub const fn classify_puk_status_sw(sw: StatusWord) -> PukStatus {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "PukStatus::Other preserves unenumerated card status words."
    )]
    match sw {
        StatusWord::PinIncorrect { retries } => PukStatus::Remaining(retries),
        StatusWord::AuthenticationFailed => PukStatus::NoInfo,
        StatusWord::AuthenticationBlocked => PukStatus::Locked,
        StatusWord::ReferenceDataInvalidated => PukStatus::Invalidated,
        other => PukStatus::Other(other.as_u16()),
    }
}

/// Decode the CHANGE REFERENCE DATA response status word.
#[must_use]
pub const fn classify_change_pin_sw(sw: StatusWord) -> ChangePinOutcome {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "catch-and-wrap: ChangePinOutcome::Other(u16) absorbs unenumerated card status words verbatim."
    )]
    match sw {
        StatusWord::Success => ChangePinOutcome::Ok,
        StatusWord::PinIncorrect { retries } => ChangePinOutcome::WrongCurrentPin {
            retries_left: retries,
        },
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            ChangePinOutcome::Locked
        }
        StatusWord::WrongLength => ChangePinOutcome::LengthError,
        other => ChangePinOutcome::Other(other.as_u16()),
    }
}

/// Project a `refineid-auth` [`ManageOutcome`] into [`ChangePinOutcome`].
const fn manage_to_change_outcome(outcome: ManageOutcome) -> ChangePinOutcome {
    match outcome {
        ManageOutcome::Ok => ChangePinOutcome::Ok,
        ManageOutcome::WrongCredential { retries_left } => {
            ChangePinOutcome::WrongCurrentPin { retries_left }
        }
        ManageOutcome::Locked => ChangePinOutcome::Locked,
        ManageOutcome::Other(StatusWord::WrongLength) => ChangePinOutcome::LengthError,
        ManageOutcome::Other(other) => ChangePinOutcome::Other(other.as_u16()),
    }
}

/// Project a `refineid-auth` [`ManageOutcome`] into [`UnblockOutcome`].
const fn manage_to_unblock_outcome(outcome: ManageOutcome) -> UnblockOutcome {
    match outcome {
        ManageOutcome::Ok => UnblockOutcome::Ok,
        ManageOutcome::WrongCredential { retries_left } => {
            UnblockOutcome::WrongPuk { retries_left }
        }
        ManageOutcome::Locked => UnblockOutcome::PukLocked,
        ManageOutcome::Other(StatusWord::WrongLength) => UnblockOutcome::LengthError,
        ManageOutcome::Other(other) => UnblockOutcome::Other(other.as_u16()),
    }
}

/// Map a `refineid-auth` credential input error into [`PinPolicyReason`].
const fn credential_input_to_policy(error: refineid_auth::CredentialInputError) -> PinPolicyReason {
    match error {
        refineid_auth::CredentialInputError::Empty { role } => match role {
            refineid_auth::CredentialRole::Puk => PinPolicyReason::WrongLength {
                min: PUK_MIN_LENGTH,
                max: PUK_MAX_LENGTH,
            },
            refineid_auth::CredentialRole::Pin1
            | refineid_auth::CredentialRole::Pin2
            | refineid_auth::CredentialRole::ActivationCode => PinPolicyReason::WrongLength {
                min: PIN_MIN_LENGTH,
                max: PIN_MAX_LENGTH,
            },
        },
        refineid_auth::CredentialInputError::WrongLength {
            expected_min,
            expected_max,
            ..
        } => PinPolicyReason::WrongLength {
            min: expected_min,
            max: expected_max,
        },
        refineid_auth::CredentialInputError::NonDigit { .. } => PinPolicyReason::NonDigit,
    }
}

/// Map a `refineid-auth` length refusal into [`PinPolicyReason`].
const fn pin_length_refusal_to_policy(refusal: refineid_auth::PinLengthRefusal) -> PinPolicyReason {
    match refusal {
        refineid_auth::PinLengthRefusal::OutsideAcceptedRange { accepted, .. } => {
            PinPolicyReason::WrongLength {
                min: accepted.min(),
                max: accepted.max(),
            }
        }
        refineid_auth::PinLengthRefusal::NoAcceptedLength { .. } => {
            PinPolicyReason::NoAcceptedLength
        }
    }
}

/// Map a `refineid-auth` error over [`CoreReads`] into this crate's [`AuthError`].
fn map_core_read_auth_error<E>(
    error: refineid_auth::AuthError<CoreReadError<E>>,
) -> AuthError<TransportDispatchError<E>> {
    match error {
        refineid_auth::AuthError::Transport(CoreReadError::Transport(err)) => {
            AuthError::Transport(TransportDispatchError::Error(err))
        }
        refineid_auth::AuthError::Transport(CoreReadError::CredentialCommand) => {
            AuthError::Command("credential command attempted on read-only path")
        }
        refineid_auth::AuthError::Outcome(outcome) => {
            AuthError::Transport(TransportDispatchError::Outcome(outcome))
        }
        refineid_auth::AuthError::Command(_) => {
            AuthError::Command("failed to assemble credential APDU")
        }
        refineid_auth::AuthError::RetryFloor(refusal) => AuthError::RetryFloor(refusal),
        refineid_auth::AuthError::PinLength(refusal) => {
            AuthError::PinPolicy(pin_length_refusal_to_policy(refusal))
        }
        refineid_auth::AuthError::UnsupportedSlot { scheme, slot } => {
            AuthError::UnsupportedSlot { scheme, slot }
        }
    }
}

/// Map a `refineid-auth` error over [`CoreSession`] into this crate's [`AuthError`].
fn map_core_session_auth_error<E>(
    error: refineid_auth::AuthError<E>,
) -> AuthError<TransportDispatchError<E>> {
    match error {
        refineid_auth::AuthError::Transport(err) => {
            AuthError::Transport(TransportDispatchError::Error(err))
        }
        refineid_auth::AuthError::Outcome(outcome) => {
            AuthError::Transport(TransportDispatchError::Outcome(outcome))
        }
        refineid_auth::AuthError::Command(_) => {
            AuthError::Command("failed to assemble credential APDU")
        }
        refineid_auth::AuthError::RetryFloor(refusal) => AuthError::RetryFloor(refusal),
        refineid_auth::AuthError::PinLength(refusal) => {
            AuthError::PinPolicy(pin_length_refusal_to_policy(refusal))
        }
        refineid_auth::AuthError::UnsupportedSlot { scheme, slot } => {
            AuthError::UnsupportedSlot { scheme, slot }
        }
    }
}

/// Fail closed when `slot` cannot be addressed in the current application
/// context under `scheme`.
const fn ensure_slot_supported<TE>(
    scheme: PinReferenceScheme,
    slot: PinSlot,
) -> Result<(), AuthError<TE>> {
    if matches!(
        (scheme, slot),
        (PinReferenceScheme::Estonian, PinSlot::Pin2)
    ) {
        return Err(AuthError::UnsupportedSlot { scheme, slot });
    }
    Ok(())
}

/// Build the FINEID S1 v4.2 §3.15.2 `GET DATA` query for `reference`'s PIN
/// container (`00 CB 00 FF 05 A0 03 83 01 <ref> 00`).
fn pin_container_query_apdu(reference: u8) -> Option<refineid_apdu::CommandApdu> {
    let header = CommandHeader {
        class: ApduClass::Plain,
        instruction: GET_DATA_INS,
        p1: GET_DATA_P1,
        p2: GET_DATA_P2,
    };
    let data = [
        PIN_CONTAINER_TEMPLATE_TAG,
        PIN_CONTAINER_TEMPLATE_LEN,
        PIN_CONTAINER_REF_TAG,
        PIN_CONTAINER_REF_LEN,
        reference,
    ];
    refineid_apdu::CommandApdu::case_4(header, &data, GET_DATA_LE).ok()
}

/// Extract usage and unblocking allowances from the `DF 21` PIN-attributes
/// BER-TLV element in a `GET DATA` PIN-container response body.
fn parse_policy_counters(body: &[u8]) -> Option<CredentialPolicyCounters> {
    const PIN_ATTRIBUTES_TAG: u16 = 0xDF21;
    const USAGE_NO_LIMIT: u8 = u8::MAX;
    const UNBLOCKING_NO_LIMIT: u8 = 0xA5;
    const UNBLOCKING_FINITE_MAX: u8 = 0x0F;

    let inner = match refineid_ber::BerTlvAny::parse(body) {
        Ok(template) if template.tag() == u16::from(PIN_CONTAINER_TEMPLATE_TAG) => template.value(),
        _ => body,
    };
    let attributes = refineid_ber::BerTlvIter::new(inner)
        .map_while(Result::ok)
        .find(|element| element.tag() == PIN_ATTRIBUTES_TAG)?;
    let [_, usage, unblocking, _] = *attributes.value() else {
        return None;
    };
    let usage = match usage {
        0 => UsageCounter::Exhausted,
        USAGE_NO_LIMIT => UsageCounter::NoLimit,
        finite => UsageCounter::Limited(std::num::NonZeroU8::new(finite)?),
    };
    let unblocking = match unblocking {
        0 => UnblockingCounter::Exhausted,
        UNBLOCKING_NO_LIMIT => UnblockingCounter::NoLimit,
        finite if finite <= UNBLOCKING_FINITE_MAX => {
            UnblockingCounter::Limited(std::num::NonZeroU8::new(finite)?)
        }
        _ => return None,
    };
    Some(CredentialPolicyCounters { usage, unblocking })
}

/// Query usage and recovery policy counters for `reference` via the citizen
/// PIN container (`GET DATA`).
fn read_policy_counters<T: CardTransport>(
    transport: &mut T,
    reference: u8,
) -> Result<Option<CredentialPolicyCounters>, AuthError<TxError<T>>> {
    let Some(apdu) = pin_container_query_apdu(reference) else {
        return Ok(None);
    };
    let response = transport
        .transmit(apdu.as_bytes())
        .map_err(AuthError::Transport)?;
    if !response.is_ok() {
        return Ok(None);
    }
    Ok(parse_policy_counters(&response.body))
}

/// PIN-management operations layered as default-impl methods on
/// every [`CardTransport`], delegating to `refineid-auth`.
pub trait PinOps: CardTransport {
    /// VERIFY APDU under the citizen numbering, enforcing the retry floor
    /// inside `refineid-auth`.
    ///
    /// # Errors
    /// [`AuthError::PinPolicy`], [`AuthError::RetryFloor`], or
    /// [`AuthError::Transport`].
    fn verify_pin(
        &mut self,
        slot: PinSlot,
        pin: PinBytes,
    ) -> Result<VerifyOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.verify_pin_with_scheme(slot, PinReferenceScheme::Citizen, pin)
    }

    /// VERIFY under an explicit reference numbering, delegating to
    /// `refineid-auth`.
    ///
    /// For organizational PIN 2, enters `DF.ESIGN` before probing and
    /// verifying; if `DF.ESIGN` selection is refused, returns that status as
    /// [`VerifyOutcome::Other`] without presenting the PIN.
    ///
    /// # Errors
    /// [`AuthError::UnsupportedSlot`], [`AuthError::PinPolicy`],
    /// [`AuthError::RetryFloor`], or [`AuthError::Transport`].
    fn verify_pin_with_scheme(
        &mut self,
        slot: PinSlot,
        scheme: PinReferenceScheme,
        pin: PinBytes,
    ) -> Result<VerifyOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        ensure_slot_supported(scheme, slot)?;
        if gates_esign_directory(scheme, slot) {
            let entered = self
                .select_esign_directory()
                .map_err(AuthError::Transport)?;
            if !entered.is_success() {
                return Ok(VerifyOutcome::Other(entered));
            }
        }
        let secret = pin.into_unvalidated_secret();
        match slot {
            PinSlot::Pin1 => {
                let pin1 = refineid_auth::Pin1::reconstruct(secret)
                    .map_err(|err| AuthError::PinPolicy(credential_input_to_policy(err)))?;
                refineid_auth::PinOps::verify_pin1_with_scheme(&mut CoreSession(self), scheme, pin1)
                    .map_err(map_core_session_auth_error)
            }
            PinSlot::Pin2 => {
                let pin2 = refineid_auth::Pin2::reconstruct(secret)
                    .map_err(|err| AuthError::PinPolicy(credential_input_to_policy(err)))?;
                refineid_auth::PinOps::verify_pin2_with_scheme(&mut CoreSession(self), scheme, pin2)
                    .map_err(map_core_session_auth_error)
            }
        }
    }

    /// Convenience for the PIN1 (auth) slot.
    ///
    /// # Errors
    /// See [`PinOps::verify_pin`].
    fn verify_pin1(&mut self, pin: PinBytes) -> Result<VerifyOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.verify_pin(PinSlot::Pin1, pin)
    }

    /// Read the PIN 1, PIN 2 and PUK lengths the card accepts under
    /// `numbering`, through `refineid-auth`.
    ///
    /// # Errors
    /// A transport failure or state transition during a read.
    fn read_card_pin_lengths(
        &mut self,
        numbering: PinReferenceScheme,
    ) -> Result<CardPinLengths, refineid_auth::AuthError<CoreReadError<Self::Error>>>
    where
        Self: Sized,
    {
        PinManageOps::read_card_pin_lengths_with_scheme(&mut CoreReads(self), numbering)
    }

    /// `CHANGE REFERENCE DATA` per ISO 7816-4 §7.5.7, delegated to
    /// `refineid-auth`.
    ///
    /// # Errors
    /// [`AuthError::UnsupportedSlot`], [`AuthError::PinPolicy`],
    /// [`AuthError::RetryFloor`], or [`AuthError::Transport`].
    fn change_pin(
        &mut self,
        lengths: &CardPinLengths,
        slot: PinSlot,
        current_pin: PinBytes,
        new_pin: PinBytes,
    ) -> Result<ChangePinOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        ensure_slot_supported(lengths.numbering(), slot)?;
        let current_secret = current_pin.into_unvalidated_secret();
        let new_secret = new_pin.into_unvalidated_secret();
        let outcome = match slot {
            PinSlot::Pin1 => {
                let current = refineid_auth::Pin1::reconstruct(current_secret)
                    .map_err(|err| AuthError::PinPolicy(credential_input_to_policy(err)))?;
                let new = refineid_auth::Pin1::reconstruct(new_secret)
                    .map_err(|err| AuthError::PinPolicy(credential_input_to_policy(err)))?;
                PinManageOps::change_pin1(&mut CoreSession(self), lengths, current, new)
                    .map_err(map_core_session_auth_error)?
            }
            PinSlot::Pin2 => {
                let current = refineid_auth::Pin2::reconstruct(current_secret)
                    .map_err(|err| AuthError::PinPolicy(credential_input_to_policy(err)))?;
                let new = refineid_auth::Pin2::reconstruct(new_secret)
                    .map_err(|err| AuthError::PinPolicy(credential_input_to_policy(err)))?;
                PinManageOps::change_pin2(&mut CoreSession(self), lengths, current, new)
                    .map_err(map_core_session_auth_error)?
            }
        };
        Ok(manage_to_change_outcome(outcome))
    }

    /// `RESET RETRY COUNTER` per ISO 7816-4 §7.5.10 (PUK-driven unblock),
    /// delegated to `refineid-auth`.
    ///
    /// # Errors
    /// [`AuthError::UnsupportedSlot`], [`AuthError::PinPolicy`],
    /// [`AuthError::RetryFloor`], or [`AuthError::Transport`].
    fn reset_retry_counter(
        &mut self,
        lengths: &CardPinLengths,
        target: PinSlot,
        puk: PinBytes,
        new_pin: PinBytes,
    ) -> Result<UnblockOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        ensure_slot_supported(lengths.numbering(), target)?;
        let Some(puk_range) = lengths.puk().accepted() else {
            return Err(AuthError::PinPolicy(PinPolicyReason::NoAcceptedLength));
        };
        if !puk_range.contains(puk.digit_count()) {
            return Err(AuthError::PinPolicy(PinPolicyReason::WrongLength {
                min: puk_range.min(),
                max: puk_range.max(),
            }));
        }
        let puk_typed = refineid_auth::Puk::reconstruct(puk.into_unvalidated_secret())
            .map_err(|err| AuthError::PinPolicy(credential_input_to_policy(err)))?;
        let new_secret = new_pin.into_unvalidated_secret();
        let outcome = match target {
            PinSlot::Pin1 => {
                let new = refineid_auth::Pin1::reconstruct(new_secret)
                    .map_err(|err| AuthError::PinPolicy(credential_input_to_policy(err)))?;
                PinManageOps::unblock_pin1(&mut CoreSession(self), lengths, puk_typed, new)
                    .map_err(map_core_session_auth_error)?
            }
            PinSlot::Pin2 => {
                let new = refineid_auth::Pin2::reconstruct(new_secret)
                    .map_err(|err| AuthError::PinPolicy(credential_input_to_policy(err)))?;
                PinManageOps::unblock_pin2(&mut CoreSession(self), lengths, puk_typed, new)
                    .map_err(map_core_session_auth_error)?
            }
        };
        Ok(manage_to_unblock_outcome(outcome))
    }

    /// Probe the card's PIN state for `slot` under the citizen numbering
    /// without touching its retry counter. Side-effect-free.
    ///
    /// # Errors
    /// Transport failure.
    fn pin_status(&mut self, slot: PinSlot) -> Result<PinStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.pin_status_with_scheme(slot, PinReferenceScheme::Citizen)
    }

    /// [`Self::pin_status`] under an explicit reference numbering, delegated
    /// to `refineid-auth`.
    ///
    /// # Errors
    /// Transport failure.
    fn pin_status_with_scheme(
        &mut self,
        slot: PinSlot,
        scheme: PinReferenceScheme,
    ) -> Result<PinStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        refineid_auth::PinOps::pin_status_with_scheme(&mut CoreReads(self), scheme, slot)
            .map_err(map_core_read_auth_error)
    }

    /// Ask the card which reference numbering it uses via counter-safe probes,
    /// delegated to `refineid-auth`.
    ///
    /// # Errors
    /// Transport failure.
    fn resolve_pin_reference_scheme(
        &mut self,
    ) -> Result<PinReferenceScheme, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        refineid_auth::PinOps::resolve_pin_reference_scheme(&mut CoreReads(self))
            .map_err(map_core_read_auth_error)
    }

    /// Read the shared PUK retry counter from the citizen PIN container
    /// without presenting a PUK, delegated to `refineid-auth`.
    ///
    /// # Errors
    /// Transport failure.
    fn puk_status(&mut self) -> Result<PukStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        read_puk_status_from_container(&mut CoreReads(self))
            .map(pin_status_to_puk_status)
            .map_err(map_core_read_auth_error)
    }

    /// [`Self::puk_status`] under an explicit reference numbering, delegated
    /// to `refineid-auth`.
    ///
    /// # Errors
    /// Transport failure.
    fn puk_status_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
    ) -> Result<PukStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        match scheme {
            PinReferenceScheme::Citizen => self.puk_status(),
            PinReferenceScheme::Organizational | PinReferenceScheme::Estonian => {
                PinManageOps::probe_puk_status_with_scheme(&mut CoreReads(self), scheme)
                    .map(pin_status_to_puk_status)
                    .map_err(map_core_read_auth_error)
            }
        }
    }

    /// Read PIN1 or PIN2 usage and recovery allowances without
    /// presenting a credential or changing any card counter.
    ///
    /// # Errors
    /// Transport failure while querying the card.
    fn pin_policy_counters(
        &mut self,
        slot: PinSlot,
    ) -> Result<Option<CredentialPolicyCounters>, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        read_policy_counters(self, slot.reference())
    }

    /// Read shared-PUK usage and recovery allowances without
    /// presenting the PUK or changing any card counter.
    ///
    /// # Errors
    /// Transport failure while querying the card.
    fn puk_policy_counters(
        &mut self,
    ) -> Result<Option<CredentialPolicyCounters>, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        read_policy_counters(self, PUK_REFERENCE_PKCS15)
    }

    /// Probe the FINEID "PIN changed" flag for `slot` per S1 v4.2
    /// §3.15.2 Table 19, delegated to `refineid-auth`.
    ///
    /// # Errors
    /// Transport failure only.
    fn pin_changed_flag(&mut self, slot: PinSlot) -> Result<Option<bool>, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let record =
            read_pin_change_record(&mut CoreReads(self), slot).map_err(map_core_read_auth_error)?;
        Ok(match record {
            PinChangeRecord::Changed => Some(true),
            PinChangeRecord::Unchanged => Some(false),
            PinChangeRecord::Unreadable => None,
        })
    }
}

impl<T: CardTransport + ?Sized> PinOps for T {}

/// refineid-core's card transport over this crate's, for the reads
/// refineid-core performs itself. It sends plain commands only; no
/// credential command crosses it.
pub(crate) struct CoreReads<'t, T>(pub(crate) &'t mut T);

/// Why a read refineid-core performs over this crate's card transport
/// failed.
#[derive(Debug)]
pub enum CoreReadError<E> {
    /// This crate's transport failed.
    Transport(E),
    /// refineid-core asked to send a credential command, which this
    /// read-only path does not carry.
    CredentialCommand,
}

impl<E: core::fmt::Display> core::fmt::Display for CoreReadError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "{error}"),
            Self::CredentialCommand => f.write_str("credential command on a read-only path"),
        }
    }
}

impl<E: TransportErrorExt> TransportErrorExt for CoreReadError<E> {
    fn kind(&self) -> TransportErrorKind {
        match self {
            Self::Transport(error) => error.kind(),
            Self::CredentialCommand => TransportErrorKind::Backend,
        }
    }
}

impl<T: CardTransport> CoreReads<'_, T> {
    /// Send `bytes` and lift this crate's error into `CoreReadError`.
    fn send(&mut self, bytes: &[u8]) -> Result<TransportOutcome, CoreReadError<T::Error>> {
        self.0
            .transmit_outcome(&CommandApdu::from(bytes))
            .map_err(CoreReadError::Transport)
    }
}

impl<T: CardTransport> refineid_apdu::CardTransport for CoreReads<'_, T> {
    type Error = CoreReadError<T::Error>;

    fn transmit(
        &mut self,
        command: &refineid_apdu::CommandApdu,
    ) -> Result<TransportOutcome, Self::Error> {
        let outcome = self.send(command.as_bytes())?;
        // ISO 7816-4 §5.3.4: `6Cxx` names the exact `Le`; a read-only
        // case-2 command is sent once more with it.
        if let TransportOutcome::Response(response) = &outcome
            && response.sw1 == WRONG_LE_SW1
            && let Some(corrected) = command.corrected_wrong_le(response.sw2)
        {
            return self.send(corrected.as_bytes());
        }
        Ok(outcome)
    }

    fn transmit_credential(
        &mut self,
        _command: refineid_apdu::CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        Err(CoreReadError::CredentialCommand)
    }
}

/// RAII guard that zeroes a temporary credential [`CommandApdu`] on drop.
struct ZeroizingCommandApdu(CommandApdu);

impl Drop for ZeroizingCommandApdu {
    fn drop(&mut self) {
        self.0.zeroize_bytes();
    }
}

/// Full `refineid-apdu` transport bridge used internally by [`PinOps`] to
/// delegate credential-bearing operations to `refineid-auth`.
struct CoreSession<'t, T>(&'t mut T);

impl<T: CardTransport> refineid_apdu::CardTransport for CoreSession<'_, T> {
    type Error = T::Error;

    fn transmit(
        &mut self,
        command: &refineid_apdu::CommandApdu,
    ) -> Result<TransportOutcome, Self::Error> {
        let outcome = self
            .0
            .transmit_outcome(&CommandApdu::from(command.as_bytes()))?;
        if let TransportOutcome::Response(response) = &outcome
            && response.sw1 == WRONG_LE_SW1
            && let Some(corrected) = command.corrected_wrong_le(response.sw2)
        {
            return self
                .0
                .transmit_outcome(&CommandApdu::from(corrected.as_bytes()));
        }
        Ok(outcome)
    }

    fn transmit_credential(
        &mut self,
        command: refineid_apdu::CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        command.expose_wire(|wire| {
            let apdu = ZeroizingCommandApdu(CommandApdu::new(wire.to_vec()));
            self.0.transmit_outcome(&apdu.0)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use crate::pkcs15::esign_wire;
    use crate::transport::{CommandApdu, ResponseApdu, TransportOutcome};

    const PLAIN_CLASS: u8 = 0x00;
    const VERIFY_MODE: u8 = 0x00;
    const CHANGE_REFERENCE_DATA_INS: u8 = 0x24;
    const CHANGE_REPLACE_MODE: u8 = 0x00;
    const RESET_RETRY_COUNTER_INS: u8 = 0x2C;
    const RESET_CODE_AND_NEW_MODE: u8 = 0x00;
    const RESET_NEW_ONLY_MODE: u8 = 0x02;
    const SW1_SUCCESS: u8 = 0x90;
    const SW2_SUCCESS: u8 = 0x00;
    const SW1_RETRY_COUNTER: u8 = 0x63;
    const SW2_TWO_RETRIES: u8 = 0xC2;
    const SW2_THREE_RETRIES: u8 = 0xC3;
    const SW2_FIVE_RETRIES: u8 = 0xC5;
    const SW1_SECURITY: u8 = 0x69;
    const SW2_SECURITY_NOT_SATISFIED: u8 = 0x82;
    const SW2_SM_INCORRECT: u8 = 0x88;
    const SW1_WRONG_PARAMETERS: u8 = 0x6A;
    const SW2_FILE_NOT_FOUND: u8 = 0x82;
    const SW2_INCORRECT_P1_P2: u8 = 0x86;
    const SW2_REFERENCE_NOT_FOUND: u8 = 0x88;
    const SW_WRONG_LENGTH: u16 = 0x6700;
    const SW_FILE_NOT_FOUND: u16 = 0x6A82;
    const SW_THREE_RETRIES: u16 = 0x63C3;
    const SW_ZERO_RETRIES: u16 = 0x63C0;
    const SW_FIVE_RETRIES: u16 = 0x63C5;
    const SW_NO_INFO: u16 = 0x6300;
    const SW_LOCKED: u16 = 0x6983;
    const SW_INVALIDATED: u16 = 0x6984;
    const SW_SUCCESS: u16 = 0x9000;
    const RETRIES_THREE: u8 = 3;
    const RETRIES_FOUR: u8 = 4;
    const RETRIES_FIVE: u8 = 5;
    const RETRIES_ZERO: u8 = 0;
    const CUTOVER_YEAR: u16 = 2026;
    const CUTOVER_MONTH: u8 = 1;
    const CUTOVER_DAY: u8 = 13;
    const DAY_BEFORE_CUTOVER: u8 = 12;
    const MIDNIGHT: u8 = 0;
    const TWELVE_DIGITS: &[u8; PIN1_STORED_LENGTH] = b"123456789012";
    const TWO_BLOCKS: usize = 2;

    fn ok() -> ResponseApdu {
        ResponseApdu {
            body: vec![],
            sw1: SW1_SUCCESS,
            sw2: SW2_SUCCESS,
        }
    }

    fn sw(sw1: u8, sw2: u8) -> ResponseApdu {
        ResponseApdu {
            body: vec![],
            sw1,
            sw2,
        }
    }

    fn pb<const N: usize>(bytes: &[u8; N]) -> PinBytes {
        PinBytes::try_from(*bytes).expect("valid test PIN")
    }

    fn lc(len: usize) -> u8 {
        u8::try_from(len).expect("short-form Lc")
    }

    fn case1_probe(reference: u8) -> Vec<u8> {
        vec![PLAIN_CLASS, VERIFY_INS, VERIFY_MODE, reference]
    }

    fn padded_block(digits: &[u8], stored: usize, pad: u8) -> Vec<u8> {
        let mut block = digits.to_vec();
        block.resize(stored, pad);
        block
    }

    fn citizen() -> CardPinLengths {
        CardPinLengths::not_listed(PinReferenceScheme::Citizen)
    }

    fn organization() -> CardPinLengths {
        CardPinLengths::not_listed(PinReferenceScheme::Organizational)
    }

    fn day(day: u8) -> DateTime {
        DateTime::new(
            CUTOVER_YEAR,
            CUTOVER_MONTH,
            day,
            MIDNIGHT,
            MIDNIGHT,
            MIDNIGHT,
        )
        .expect("valid fixture date")
    }

    struct SteppedTx {
        script: Vec<(Vec<u8>, ResponseApdu)>,
        cursor: usize,
    }

    impl CardTransport for SteppedTx {
        type Error = String;

        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            let Some((expected, response)) = self.script.get(self.cursor) else {
                return Err(format!("script exhausted at step {}", self.cursor));
            };
            assert_eq!(
                apdu.as_bytes(),
                expected.as_slice(),
                "APDU mismatch at step {}",
                self.cursor
            );
            self.cursor = self.cursor.saturating_add(1);
            Ok(TransportOutcome::Response(response.clone()))
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    struct ShouldNotTransmitTx;

    impl CardTransport for ShouldNotTransmitTx {
        type Error = String;

        fn transmit_outcome(
            &mut self,
            _apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            panic!("transport must not be touched on local rejection");
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    fn esign_entry() -> Vec<(Vec<u8>, ResponseApdu)> {
        vec![
            (esign_wire::select_mf().into_bytes(), ok()),
            (esign_wire::select_esign_by_name().into_bytes(), ok()),
        ]
    }

    #[test]
    fn resolve_scheme_finds_citizen_organizational_estonian_and_stops_on_security() {
        let mut citizen_tx = SteppedTx {
            script: vec![(
                case1_probe(PIN1_REFERENCE_PKCS15),
                sw(SW1_RETRY_COUNTER, SW2_THREE_RETRIES),
            )],
            cursor: 0,
        };
        assert_eq!(
            citizen_tx
                .resolve_pin_reference_scheme()
                .expect("citizen resolves"),
            PinReferenceScheme::Citizen
        );
        assert_eq!(citizen_tx.cursor, citizen_tx.script.len());

        let mut org_tx = SteppedTx {
            script: vec![
                (
                    case1_probe(PIN1_REFERENCE_PKCS15),
                    sw(SW1_WRONG_PARAMETERS, SW2_REFERENCE_NOT_FOUND),
                ),
                (
                    case1_probe(PIN1_REFERENCE_ORGANIZATIONAL),
                    sw(SW1_RETRY_COUNTER, SW2_FIVE_RETRIES),
                ),
            ],
            cursor: 0,
        };
        assert_eq!(
            org_tx
                .resolve_pin_reference_scheme()
                .expect("organizational resolves"),
            PinReferenceScheme::Organizational
        );
        assert_eq!(org_tx.cursor, org_tx.script.len());

        let mut ee_tx = SteppedTx {
            script: vec![
                (
                    case1_probe(PIN1_REFERENCE_PKCS15),
                    sw(SW1_WRONG_PARAMETERS, SW2_REFERENCE_NOT_FOUND),
                ),
                (
                    case1_probe(PIN1_REFERENCE_ORGANIZATIONAL),
                    sw(SW1_WRONG_PARAMETERS, SW2_INCORRECT_P1_P2),
                ),
                (
                    case1_probe(PIN1_REFERENCE_ESTONIAN),
                    sw(SW1_RETRY_COUNTER, SW2_THREE_RETRIES),
                ),
            ],
            cursor: 0,
        };
        assert_eq!(
            ee_tx
                .resolve_pin_reference_scheme()
                .expect("Estonian resolves"),
            PinReferenceScheme::Estonian
        );
        assert_eq!(ee_tx.cursor, ee_tx.script.len());

        for sw2 in [SW2_SECURITY_NOT_SATISFIED, SW2_SM_INCORRECT] {
            let mut pre_pace = SteppedTx {
                script: vec![(case1_probe(PIN1_REFERENCE_PKCS15), sw(SW1_SECURITY, sw2))],
                cursor: 0,
            };
            assert_eq!(
                pre_pace
                    .resolve_pin_reference_scheme()
                    .expect("security refusal stops probing"),
                PinReferenceScheme::Citizen
            );
            assert_eq!(pre_pace.cursor, pre_pace.script.len());
        }
    }

    #[test]
    fn activation_scheme_follows_numbering_and_validity_start() {
        assert_eq!(
            activation_scheme_for_card(PinReferenceScheme::Citizen, Some(day(DAY_BEFORE_CUTOVER))),
            Some(ActivationScheme::ActivationCodeIsPuk)
        );
        assert_eq!(
            activation_scheme_for_card(PinReferenceScheme::Citizen, Some(day(CUTOVER_DAY))),
            Some(ActivationScheme::PresetActivationPin)
        );
        assert_eq!(
            activation_scheme_for_card(PinReferenceScheme::Citizen, None),
            None
        );
        for start in [None, Some(day(DAY_BEFORE_CUTOVER)), Some(day(CUTOVER_DAY))] {
            assert_eq!(
                activation_scheme_for_card(PinReferenceScheme::Organizational, start),
                Some(ActivationScheme::ActivationCodeIsPuk)
            );
        }
    }

    #[test]
    fn pin_readiness_judges_flag_and_puk_scheme_counter() {
        let fresh = PinRetries::from_nibble(PIN_TRY_LIMIT).expect("try limit fits");
        let exhausted = PinRetries::from_nibble(RETRIES_ZERO).expect("zero fits");
        let puk = Some(ActivationScheme::ActivationCodeIsPuk);

        assert_eq!(
            PinReadiness::judge(puk, Some(false), Some(PinStatus::Remaining(fresh))),
            PinReadiness::AwaitsActivation
        );
        assert_eq!(
            PinReadiness::judge(puk, Some(true), Some(PinStatus::Locked)),
            PinReadiness::Activated
        );
        assert_eq!(
            PinReadiness::judge(puk, None, Some(PinStatus::Locked)),
            PinReadiness::AwaitsActivation
        );
        assert_eq!(
            PinReadiness::judge(puk, None, Some(PinStatus::Remaining(exhausted))),
            PinReadiness::AwaitsActivation
        );
        assert_eq!(
            PinReadiness::judge(puk, None, Some(PinStatus::Remaining(fresh))),
            PinReadiness::Activated
        );
        assert_eq!(
            PinReadiness::judge(puk, None, Some(PinStatus::NoInfo)),
            PinReadiness::Undecided
        );
        assert_eq!(
            PinReadiness::judge(
                Some(ActivationScheme::PresetActivationPin),
                None,
                Some(PinStatus::Locked)
            ),
            PinReadiness::Undecided
        );
    }

    #[test]
    fn estonian_pin2_operations_fail_closed_without_transmitting() {
        let lengths = CardPinLengths::not_listed(PinReferenceScheme::Estonian);
        let mut tx = ShouldNotTransmitTx;
        let pin = pb(b"123456");
        let puk = pb(b"12345678");

        assert!(matches!(
            tx.verify_pin_with_scheme(PinSlot::Pin2, PinReferenceScheme::Estonian, pin.clone()),
            Err(AuthError::UnsupportedSlot {
                scheme: PinReferenceScheme::Estonian,
                slot: PinSlot::Pin2,
            })
        ));
        assert!(matches!(
            tx.change_pin(&lengths, PinSlot::Pin2, pin.clone(), pin.clone()),
            Err(AuthError::UnsupportedSlot {
                scheme: PinReferenceScheme::Estonian,
                slot: PinSlot::Pin2,
            })
        ));
        assert!(matches!(
            tx.reset_retry_counter(&lengths, PinSlot::Pin2, puk, pin),
            Err(AuthError::UnsupportedSlot {
                scheme: PinReferenceScheme::Estonian,
                slot: PinSlot::Pin2,
            })
        ));
    }

    #[test]
    fn citizen_verify_probes_counter_then_sends_padded_block() {
        let mut verify_wire = vec![
            PLAIN_CLASS,
            VERIFY_INS,
            VERIFY_MODE,
            PIN1_REFERENCE_PKCS15,
            lc(PIN1_STORED_LENGTH),
        ];
        verify_wire.extend_from_slice(&padded_block(b"1234", PIN1_STORED_LENGTH, PIN_PAD_BYTE));
        let mut tx = SteppedTx {
            script: vec![
                (
                    case1_probe(PIN1_REFERENCE_PKCS15),
                    sw(SW1_RETRY_COUNTER, SW2_FIVE_RETRIES),
                ),
                (verify_wire, ok()),
            ],
            cursor: 0,
        };
        assert_eq!(
            tx.verify_pin1(pb(b"1234")).expect("verify succeeds"),
            VerifyOutcome::Ok
        );
        assert_eq!(tx.cursor, tx.script.len());
    }

    #[test]
    fn verify_refuses_below_retry_floor_without_sending_pin() {
        let mut tx = SteppedTx {
            script: vec![(
                case1_probe(PIN1_REFERENCE_PKCS15),
                sw(SW1_RETRY_COUNTER, SW2_TWO_RETRIES),
            )],
            cursor: 0,
        };
        assert!(matches!(
            tx.verify_pin1(pb(b"1234")),
            Err(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
                credential: FlooredCredential::Pin1,
                ..
            }))
        ));
        assert_eq!(tx.cursor, tx.script.len());
    }

    #[test]
    fn organizational_pin2_verify_selects_esign_then_probes_and_sends_bare_pin() {
        let mut verify_wire = vec![
            PLAIN_CLASS,
            VERIFY_INS,
            VERIFY_MODE,
            PIN2_REFERENCE_ORGANIZATIONAL,
            lc(b"123456".len()),
        ];
        verify_wire.extend_from_slice(b"123456");
        let mut script = esign_entry();
        script.push((
            case1_probe(PIN2_REFERENCE_ORGANIZATIONAL),
            sw(SW1_RETRY_COUNTER, SW2_FIVE_RETRIES),
        ));
        script.push((verify_wire, ok()));
        let mut tx = SteppedTx { script, cursor: 0 };
        let outcome = tx
            .verify_pin_with_scheme(
                PinSlot::Pin2,
                PinReferenceScheme::Organizational,
                pb(b"123456"),
            )
            .expect("organizational PIN2 verify succeeds");
        assert_eq!(outcome, VerifyOutcome::Ok);
        assert_eq!(tx.cursor, tx.script.len());
    }

    #[test]
    fn organizational_pin2_verify_falls_back_to_the_esign_identifier() {
        let refused = sw(SW1_WRONG_PARAMETERS, SW2_FILE_NOT_FOUND);
        let mut verify_wire = vec![
            PLAIN_CLASS,
            VERIFY_INS,
            VERIFY_MODE,
            PIN2_REFERENCE_ORGANIZATIONAL,
            lc(b"123456".len()),
        ];
        verify_wire.extend_from_slice(b"123456");
        let mut tx = SteppedTx {
            script: vec![
                (esign_wire::select_mf().into_bytes(), ok()),
                (
                    esign_wire::select_esign_by_name().into_bytes(),
                    refused.clone(),
                ),
                (
                    crate::pkcs15::child_df_select_attempts(crate::pkcs15::DF_ESIGN_FID)
                        .into_iter()
                        .next()
                        .expect("child-DF variant")
                        .into_bytes(),
                    refused,
                ),
                (esign_wire::select_esign_any_by_fid().into_bytes(), ok()),
                (
                    case1_probe(PIN2_REFERENCE_ORGANIZATIONAL),
                    sw(SW1_RETRY_COUNTER, SW2_FIVE_RETRIES),
                ),
                (verify_wire, ok()),
            ],
            cursor: 0,
        };
        let outcome = tx
            .verify_pin_with_scheme(
                PinSlot::Pin2,
                PinReferenceScheme::Organizational,
                pb(b"123456"),
            )
            .expect("organizational PIN2 verify succeeds after FID fallback");
        assert_eq!(outcome, VerifyOutcome::Ok);
        assert_eq!(tx.cursor, tx.script.len());
    }

    #[test]
    fn organizational_pin2_is_not_presented_when_esign_selection_fails() {
        let refused = sw(SW1_WRONG_PARAMETERS, SW2_FILE_NOT_FOUND);
        let mut script = vec![
            (esign_wire::select_mf().into_bytes(), ok()),
            (
                esign_wire::select_esign_by_name().into_bytes(),
                refused.clone(),
            ),
        ];
        for variant in crate::pkcs15::child_df_select_attempts(crate::pkcs15::DF_ESIGN_FID) {
            script.push((variant.into_bytes(), refused.clone()));
        }
        let mut tx = SteppedTx { script, cursor: 0 };
        let outcome = tx
            .verify_pin_with_scheme(
                PinSlot::Pin2,
                PinReferenceScheme::Organizational,
                pb(b"123456"),
            )
            .expect("refused SELECT returns an outcome");
        assert_eq!(outcome, VerifyOutcome::Other(StatusWord::FileNotFound));
        assert_eq!(tx.cursor, tx.script.len());
    }

    #[test]
    fn change_pin_probes_and_delegates_to_refineid_auth() {
        let mut change_wire = vec![
            PLAIN_CLASS,
            CHANGE_REFERENCE_DATA_INS,
            CHANGE_REPLACE_MODE,
            PIN1_REFERENCE_PKCS15,
            lc(PIN1_STORED_LENGTH.saturating_mul(TWO_BLOCKS)),
        ];
        change_wire.extend_from_slice(&padded_block(b"1234", PIN1_STORED_LENGTH, PIN_PAD_BYTE));
        change_wire.extend_from_slice(&padded_block(b"4321", PIN1_STORED_LENGTH, PIN_PAD_BYTE));
        let mut tx = SteppedTx {
            script: vec![
                (
                    case1_probe(PIN1_REFERENCE_PKCS15),
                    sw(SW1_RETRY_COUNTER, SW2_FIVE_RETRIES),
                ),
                (change_wire, ok()),
            ],
            cursor: 0,
        };
        assert_eq!(
            tx.change_pin(&citizen(), PinSlot::Pin1, pb(b"1234"), pb(b"4321"))
                .expect("change succeeds"),
            ChangePinOutcome::Ok
        );
        assert_eq!(tx.cursor, tx.script.len());

        let mut org_wire = vec![
            PLAIN_CLASS,
            CHANGE_REFERENCE_DATA_INS,
            CHANGE_REPLACE_MODE,
            PIN2_REFERENCE_ORGANIZATIONAL,
            lc(TWELVE_DIGITS.len().saturating_mul(TWO_BLOCKS)),
        ];
        org_wire.extend_from_slice(TWELVE_DIGITS);
        org_wire.extend_from_slice(TWELVE_DIGITS);
        let mut org_tx = SteppedTx {
            script: vec![
                (
                    case1_probe(PIN2_REFERENCE_ORGANIZATIONAL),
                    sw(SW1_RETRY_COUNTER, SW2_FIVE_RETRIES),
                ),
                (org_wire, ok()),
            ],
            cursor: 0,
        };
        assert_eq!(
            org_tx
                .change_pin(
                    &organization(),
                    PinSlot::Pin2,
                    pb(TWELVE_DIGITS),
                    pb(TWELVE_DIGITS),
                )
                .expect("organizational change succeeds"),
            ChangePinOutcome::Ok
        );
        assert_eq!(org_tx.cursor, org_tx.script.len());
    }

    #[test]
    fn change_pin_outside_card_range_refuses_locally() {
        let mut tx = ShouldNotTransmitTx;
        let err = tx
            .change_pin(&citizen(), PinSlot::Pin2, pb(b"123456"), pb(b"1234"))
            .expect_err("four-digit PIN2 rejected locally");
        assert!(matches!(
            err,
            AuthError::PinPolicy(PinPolicyReason::WrongLength {
                min: FINEID_PIN2_MIN_LENGTH,
                max: PIN_MAX_LENGTH,
            })
        ));
    }

    #[test]
    fn unblock_delegates_citizen_and_organizational_flows() {
        let mut reset_wire = vec![
            PLAIN_CLASS,
            RESET_RETRY_COUNTER_INS,
            RESET_CODE_AND_NEW_MODE,
            PIN1_REFERENCE_PKCS15,
            lc(PUK_STORED_LENGTH.saturating_add(PIN1_STORED_LENGTH)),
        ];
        reset_wire.extend_from_slice(&padded_block(b"12345678", PUK_STORED_LENGTH, PIN_PAD_BYTE));
        reset_wire.extend_from_slice(&padded_block(b"4321", PIN1_STORED_LENGTH, PIN_PAD_BYTE));
        let mut citizen_tx = SteppedTx {
            script: vec![
                (
                    case1_probe(PUK_REFERENCE_PKCS15),
                    sw(SW1_RETRY_COUNTER, SW2_FIVE_RETRIES),
                ),
                (reset_wire, ok()),
            ],
            cursor: 0,
        };
        assert_eq!(
            citizen_tx
                .reset_retry_counter(&citizen(), PinSlot::Pin1, pb(b"12345678"), pb(b"4321"))
                .expect("citizen unblock succeeds"),
            UnblockOutcome::Ok
        );
        assert_eq!(citizen_tx.cursor, citizen_tx.script.len());

        let mut verify_puk = vec![
            PLAIN_CLASS,
            VERIFY_INS,
            VERIFY_MODE,
            PUK_REFERENCE_ORGANIZATIONAL,
            lc(b"12345678".len()),
        ];
        verify_puk.extend_from_slice(b"12345678");
        let mut reset_new = vec![
            PLAIN_CLASS,
            RESET_RETRY_COUNTER_INS,
            RESET_NEW_ONLY_MODE,
            PIN1_REFERENCE_ORGANIZATIONAL,
            lc(b"1234".len()),
        ];
        reset_new.extend_from_slice(b"1234");
        let mut org_tx = SteppedTx {
            script: vec![
                (
                    case1_probe(PUK_REFERENCE_ORGANIZATIONAL),
                    sw(SW1_RETRY_COUNTER, SW2_FIVE_RETRIES),
                ),
                (verify_puk, ok()),
                (reset_new, ok()),
            ],
            cursor: 0,
        };
        assert_eq!(
            org_tx
                .reset_retry_counter(&organization(), PinSlot::Pin1, pb(b"12345678"), pb(b"1234"))
                .expect("organizational unblock succeeds"),
            UnblockOutcome::Ok
        );
        assert_eq!(org_tx.cursor, org_tx.script.len());
    }

    #[test]
    fn short_puk_and_seven_digit_activation_code_rejected_locally() {
        let mut tx = ShouldNotTransmitTx;
        for short in [pb(b"123456").clone(), pb(b"1234567")] {
            let err = tx
                .reset_retry_counter(&citizen(), PinSlot::Pin1, short, pb(b"4321"))
                .expect_err("short PUK rejected locally");
            assert!(matches!(
                err,
                AuthError::PinPolicy(PinPolicyReason::WrongLength {
                    min: PUK_MIN_LENGTH,
                    max: PUK_MAX_LENGTH,
                })
            ));
        }
    }

    #[test]
    fn puk_status_and_policy_counters_parse_pin_container() {
        const PIN_ATTRIBUTES_TAG_HI: u8 = 0xDF;
        const PIN_ATTRIBUTES_TAG_LO: u8 = 0x21;
        const PIN_ATTRIBUTES_LENGTH: u8 = 0x04;
        const FOUR_RETRIES_BYTE: u8 = 0x04;
        const UNLIMITED_USAGE: u8 = u8::MAX;
        const UNBLOCKING_NO_LIMIT: u8 = 0xA5;
        const PUK_METHOD: u8 = 0x83;

        let query = pin_container_query_apdu(PUK_REFERENCE_PKCS15)
            .expect("query builds")
            .as_bytes()
            .to_vec();
        let body = vec![
            PIN_ATTRIBUTES_TAG_HI,
            PIN_ATTRIBUTES_TAG_LO,
            PIN_ATTRIBUTES_LENGTH,
            FOUR_RETRIES_BYTE,
            UNLIMITED_USAGE,
            UNBLOCKING_NO_LIMIT,
            PUK_METHOD,
        ];
        let mut tx = SteppedTx {
            script: vec![
                (
                    query.clone(),
                    ResponseApdu {
                        body: body.clone(),
                        sw1: SW1_SUCCESS,
                        sw2: SW2_SUCCESS,
                    },
                ),
                (
                    query,
                    ResponseApdu {
                        body: body.clone(),
                        sw1: SW1_SUCCESS,
                        sw2: SW2_SUCCESS,
                    },
                ),
            ],
            cursor: 0,
        };
        let four = PinRetries::from_nibble(RETRIES_FOUR).expect("nibble");
        assert_eq!(
            tx.puk_status().expect("puk status"),
            PukStatus::Remaining(four)
        );
        assert_eq!(
            tx.puk_policy_counters().expect("puk policy counters"),
            Some(CredentialPolicyCounters {
                usage: UsageCounter::NoLimit,
                unblocking: UnblockingCounter::NoLimit,
            })
        );
        assert_eq!(tx.cursor, tx.script.len());

        // A wrapped PIN-container template parses its PIN-attributes child TLV.
        let mut wrapped = vec![PIN_CONTAINER_TEMPLATE_TAG, lc(body.len())];
        wrapped.extend_from_slice(&body);
        assert_eq!(
            parse_policy_counters(&wrapped),
            Some(CredentialPolicyCounters {
                usage: UsageCounter::NoLimit,
                unblocking: UnblockingCounter::NoLimit,
            })
        );

        // Decoy PIN-attributes bytes embedded inside an unrelated TLV value do not false-match.
        const DECOY_TAG: u8 = 0x80;
        let mut decoy = vec![DECOY_TAG, lc(body.len())];
        decoy.extend_from_slice(&body);
        let mut wrapped_decoy = vec![PIN_CONTAINER_TEMPLATE_TAG, lc(decoy.len())];
        wrapped_decoy.extend_from_slice(&decoy);
        assert_eq!(parse_policy_counters(&wrapped_decoy), None);
    }

    #[test]
    fn status_word_classifiers_cover_documented_states() {
        let zero = PinRetries::from_nibble(RETRIES_ZERO).expect("nibble");
        let three = PinRetries::from_nibble(RETRIES_THREE).expect("nibble");
        let five = PinRetries::from_nibble(RETRIES_FIVE).expect("nibble");

        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(SW_SUCCESS)),
            PinStatus::Verified
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(SW_FIVE_RETRIES)),
            PinStatus::Remaining(five)
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(SW_ZERO_RETRIES)),
            PinStatus::Remaining(zero)
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(SW_NO_INFO)),
            PinStatus::NoInfo
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(SW_LOCKED)),
            PinStatus::Locked
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(SW_INVALIDATED)),
            PinStatus::Locked
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(SW_FILE_NOT_FOUND)),
            PinStatus::Other(StatusWord::FileNotFound)
        );

        assert_eq!(
            classify_verify_sw(StatusWord::from_u16(SW_SUCCESS)),
            VerifyOutcome::Ok
        );
        assert_eq!(
            classify_verify_sw(StatusWord::from_u16(SW_ZERO_RETRIES)),
            VerifyOutcome::WrongPin { retries_left: zero }
        );
        assert_eq!(
            classify_verify_sw(StatusWord::from_u16(SW_FILE_NOT_FOUND)),
            VerifyOutcome::Other(StatusWord::FileNotFound)
        );

        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(SW_SUCCESS)),
            ChangePinOutcome::Ok
        );
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(SW_THREE_RETRIES)),
            ChangePinOutcome::WrongCurrentPin {
                retries_left: three
            }
        );
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(SW_LOCKED)),
            ChangePinOutcome::Locked
        );
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(SW_WRONG_LENGTH)),
            ChangePinOutcome::LengthError
        );
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(SW_FILE_NOT_FOUND)),
            ChangePinOutcome::Other(SW_FILE_NOT_FOUND)
        );

        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(SW_SUCCESS)),
            UnblockOutcome::Ok
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(SW_THREE_RETRIES)),
            UnblockOutcome::WrongPuk {
                retries_left: three
            }
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(SW_LOCKED)),
            UnblockOutcome::PukLocked
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(SW_INVALIDATED)),
            UnblockOutcome::Invalidated
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(SW_WRONG_LENGTH)),
            UnblockOutcome::LengthError
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(SW_FILE_NOT_FOUND)),
            UnblockOutcome::Other(SW_FILE_NOT_FOUND)
        );

        assert_eq!(
            classify_puk_status_sw(StatusWord::from_u16(SW_LOCKED)),
            PukStatus::Locked
        );
        assert_eq!(
            classify_puk_status_sw(StatusWord::from_u16(SW_INVALIDATED)),
            PukStatus::Invalidated
        );
        assert_eq!(
            classify_puk_status_sw(StatusWord::from_u16(SW_NO_INFO)),
            PukStatus::NoInfo
        );
    }
}
