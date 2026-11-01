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

//! `refineid pin change 1|2` / `pin unblock 1|2` /
//! `card pin-status`.
//!
//! PIN-management surface for both FINEID PIN slots:
//! - PIN1 (auth) gates the auth key.
//! - PIN2 (qualified-signature) gates the QES key.
//!
//! The PUK unblocks either slot; one PUK is the recovery path for
//! both PIN1 and PIN2. The card's reference numbering is resolved
//! once per session ([`PinReferenceScheme`]): citizen cards answer
//! FINEID S1 v4.2 §3.5.2 references, organization cards the FINEID
//! S4-2 v4.0 §4.2 ones.
//!
//! PIN bytes never reach argv, env, or any log line; the prompts
//! use rpassword (or stdin bufread when no tty) and the move into
//! [`PinBytes`] is immediate so the buffer zeroes on drop.

use alloc::fmt;

use refineid_lib_core::auth::{
    ActivationScheme, AuthError, ChangePinOutcome, PinOps as _, PinPolicyReason, PinReadiness,
    PinReferenceScheme, PinSlot, PinStatus, PukStatus, RetryFloorRefusal, UnblockOutcome,
    check_puk_retry_floor, check_retry_floor,
};
use refineid_lib_core::backend::{
    ReaderAccessCap, ReaderBackend as _, ReaderFilter, ReaderPickError,
};
use refineid_lib_core::crypto::digest::Sha256;
use refineid_lib_core::fineid_card::{CardClassificationError, FineidCardModel};
use refineid_lib_core::pin::{ActivationCode, PinBytes, Puk};
use refineid_lib_core::pkcs15::{CertSlot, FineidReaderPick};
use refineid_lib_core::pkcs15::{FineidReaderPicker as _, Pkcs15Ops as _};
use refineid_lib_core::x509::{DateTime, OwnedCert};
use refineid_lib_pcsc::{PcscBackend, PcscError};

/// Which PIN slot a manage-PIN operation targets. Thin layer over
/// [`PinSlot`] that also carries the user-facing label so error
/// messages and reports read naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinManageSlot {
    /// Authentication PIN (FINEID S4-1 v3.1 §4.1.1, PIN reference
    /// `0x11`); gates the authentication key.
    Pin1,
    /// Qualified-signature PIN (FINEID S4-1 v3.1 §4.1.1, PIN
    /// reference `0x82`); gates the non-repudiation signing key.
    Pin2,
}

impl PinManageSlot {
    /// Project to the lib-core [`PinSlot`] enum used by transport-
    /// level APDU builders. Drops the CLI-only label and keeps
    /// only the reference-byte mapping.
    #[must_use]
    pub const fn as_pin_slot(self) -> PinSlot {
        match self {
            Self::Pin1 => PinSlot::Pin1,
            Self::Pin2 => PinSlot::Pin2,
        }
    }
    /// User-facing label ("PIN1" / "PIN2") for prompts and report
    /// strings. `&'static str` from a fixed compile-time set.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pin1 => "PIN1",
            Self::Pin2 => "PIN2",
        }
    }
}

/// Inputs for `pin change 1|2`.
#[derive(Debug)]
pub struct ChangePinOptions {
    /// Which PIN slot to rotate. Drives both the APDU PIN
    /// reference byte and the spec rule applied to the new PIN
    /// length policy.
    pub slot: PinManageSlot,
    /// Current PIN value (the one the operator typed in the
    /// "current PIN" prompt). Consumed and zeroized at function
    /// return.
    pub current: PinBytes,
    /// New PIN value (the one the operator typed in the
    /// "new PIN" prompt). Consumed and zeroized at function
    /// return.
    pub new: PinBytes,
    /// Optional substring match against reader names; same
    /// semantics as the rest of the client crate. `None` accepts
    /// any single FINEID-responding reader (errors on ambiguity).
    /// Tier 0 `String` -- carried verbatim to
    /// `ReaderFilter::new`; tighter form would be `ReaderFilter`.
    pub reader_filter: Option<String>,
}

/// One reader's worth of `pin change` output.
#[derive(Debug, Clone)]
pub struct ChangePinReport {
    /// PC/SC reader name the modify APDU landed against. Tier 0
    /// `String` from `ReaderId::as_str().to_owned()`; tighter
    /// form would be `ReaderId`.
    pub reader: String,
    /// `CredentialIdentity::best_serial()` of the trust-gated
    /// card: PKCS#15 token serial when present, else printed /
    /// PEUIN form. Empty string when nothing was readable.
    /// Surfaced so the operator can confirm which physical card
    /// the PIN op landed against when multiple readers are
    /// connected.
    pub card_serial: String,
    /// `CredentialIdentity::person_string()` rendering --
    /// "SURNAME GIVENS" form (still uppercase per
    /// DVV-emitted cert subject; the typed [`NativeName`]
    /// rendering is a separate concern).
    ///
    /// [`NativeName`]: refineid_lib_core::identity::NativeName
    pub person: String,
    /// Which PIN slot the modify APDU targeted.
    pub slot: PinManageSlot,
    /// Card-side outcome from `CHANGE REFERENCE DATA`
    /// (FINEID S4-1 v3.1 §4.1.3 / ISO 7816-4 §7.5.7): Ok,
    /// `WrongCurrentPin` with retries, Locked, etc.
    pub outcome: ChangePinOutcome,
}

/// Inputs for `pin unblock 1|2`.
#[derive(Debug)]
pub struct UnblockPinOptions {
    /// Which PIN slot to unblock. Both PIN1 and PIN2 share the
    /// same PUK.
    pub slot: PinManageSlot,
    /// The 8 to 12-digit PUK code. Typed [`Puk`] forces construction
    /// via [`Puk::new`] at the operator-input boundary, so a
    /// non-PUK `PinBytes` value (e.g. a PIN or activation code)
    /// can't reach the `RESET RETRY COUNTER` APDU by accident.
    pub puk: Puk,
    /// New PIN value to set after the unblock succeeds. Consumed
    /// and zeroized at function return.
    pub new_pin: PinBytes,
    /// Optional substring match against reader names; same
    /// semantics as [`ChangePinOptions::reader_filter`]. Tier 0
    /// `String` -- presentational input to `ReaderFilter::new`.
    pub reader_filter: Option<String>,
}

/// One reader's worth of unblock output.
#[derive(Debug, Clone)]
pub struct UnblockPinReport {
    /// See [`ChangePinReport::reader`].
    pub reader: String,
    /// See [`ChangePinReport::card_serial`].
    pub card_serial: String,
    /// See [`ChangePinReport::person`].
    pub person: String,
    /// Which PIN slot the unblock APDU targeted.
    pub slot: PinManageSlot,
    /// Card-side outcome from `RESET RETRY COUNTER`
    /// (FINEID S4-1 v3.1 §4.1.4 / ISO 7816-4 §7.5.10): Ok,
    /// `WrongPuk` with retries, `PukLocked`, etc.
    pub outcome: UnblockOutcome,
}

/// Error returned from the PIN-management entrypoints
/// (`pin change`, `pin unblock`, `pin activate`).
#[derive(Debug)]
pub enum CardPinError {
    /// Reader enumeration / filter resolution failed.
    ReaderPick(ReaderPickError),
    /// PC/SC transport / transmit error.
    Pcsc(PcscError),
    /// Local-policy rejection (length / non-digit) before any
    /// APDU went out. Retry counter is unaffected.
    PinPolicy(PinPolicyReason),
    /// Couldn't SELECT the PKCS#15 application. FINEID gates the
    /// PIN-management INS bytes (0x20 status-form, 0x24, 0x2C)
    /// behind app SELECT -- SW=6D00 otherwise.
    Pkcs15Select(String),
    /// Lower-level transport / APDU failure not specific to PKCS#15
    /// SELECT (cert read, EF.TokenInfo read, ...). Tier 0 `String`
    /// -- presentational rendering of the upstream error.
    Transport(String),
    /// `pin activate` only: the activation entry's form doesn't
    /// match the card's activation scheme. Reported *before* any
    /// modify APDU, so the card-side try counter is untouched.
    ActivationLengthMismatch {
        /// The card's activation scheme.
        scheme: ActivationScheme,
        /// The digit count that scheme's activation entry has
        /// (`ActivationScheme::activation_entry_digit_count`).
        expected: usize,
    },
    /// `pin activate` only: the card's activation scheme could not
    /// be decided -- a citizen-numbered card whose authentication
    /// certificate validity start was not readable -- so refineid
    /// makes no activation decision.
    NoActivationScheme,
    /// `pin activate` only: the card's data couldn't be
    /// authenticated against a pinned anchor. The activation
    /// flow refuses to use untrusted card-side data (issuance
    /// date, etc.) for type selection -- without a verified
    /// chain anchor the data could be from a counterfeit card.
    CardDataUntrusted {
        /// Human-readable detail from
        /// `CardTrustAttestation::describe` explaining which
        /// trust gate failed (no pinned root match, cert read
        /// error, etc.). Tier 0 `String`; presentational.
        description: String,
    },
    /// The trusted card session was invalidated between the
    /// trust gate and the operation. Possible causes: card
    /// removed from reader mid-flow, reader unplugged, a
    /// different card inserted, the same physical port re-
    /// enumerated as a different reader. Trust does not survive
    /// any of these; the operator must re-run.
    CardSessionRevoked {
        /// Human-readable detail from
        /// `re_verify_session` explaining which invariant
        /// diverged (serial mismatch, EF.TokenInfo unreadable,
        /// ...). Tier 0 `String`; presentational.
        reason: String,
    },
    /// The card's contact-interface ATR matches no FINEID citizen
    /// card model refineid knows, and the card does not answer the
    /// organization reference numbering either. See
    /// `doc/fineid-card-models.md` for the known set. Expired
    /// models and any non-FINEID smartcard land here.
    CardModelNotSupported(CardClassificationError),
    /// `pin change` / `pin unblock`: the PIN still awaits
    /// activation ([`PinReadiness::AwaitsActivation`]). Refineid
    /// refuses before any modify APDU goes out; the operator runs
    /// `refineid pin activate` first.
    CardLooksUnactivated {
        /// Which PIN slot the probe targeted.
        slot: PinManageSlot,
        /// The PIN's counter-safe status probe. `None` when the
        /// probe APDU itself failed to return a status word.
        probe: Option<PinStatus>,
    },
    /// The retry floor refused a command that presents the current PIN
    /// or the PUK: the card reports two, one or no tries left for it, the
    /// credential blocked, or no readable counter.
    RetryFloor(RetryFloorRefusal),
}

impl fmt::Display for CardPinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReaderPick(e) => write!(f, "{e}"),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::PinPolicy(r) => write!(f, "PIN / PUK rejected locally: {r}"),
            Self::Pkcs15Select(s) => write!(f, "SELECT PKCS#15 app: {s}"),
            Self::Transport(s) => write!(f, "transport: {s}"),
            Self::ActivationLengthMismatch { scheme, expected } => write!(
                f,
                "activation PIN length wrong for this card: its activation \
                 ({scheme:?}) takes {expected} digits. Sending another length \
                 would burn a card-side try; refusing"
            ),
            Self::NoActivationScheme => write!(
                f,
                "couldn't decide this card's activation scheme (the \
                 authentication certificate's validity start is unreadable); \
                 refusing to activate"
            ),
            Self::CardDataUntrusted { description } => write!(
                f,
                "card-side data not trusted -- {description}. The activation \
                 flow refuses to use unverified card data; verify you're using \
                 a real DVV-issued FINEID card, or update PINNED_ROOT_SHA256 \
                 to include this card's root if it's a genuine new generation"
            ),
            Self::CardSessionRevoked { reason } => write!(
                f,
                "trusted card session revoked between trust gate and operation: \
                 {reason}. Trust does not survive card removal, reader unplug, \
                 reader rename, or card swap. Re-run the command after restoring \
                 the original reader + card."
            ),
            Self::CardModelNotSupported(e) => write!(f, "{e}"),
            Self::CardLooksUnactivated { slot, probe } => {
                let probe_desc = probe
                    .as_ref()
                    .map_or_else(|| "no probe result".to_owned(), |s| format!("{s:?}"));
                write!(
                    f,
                    "{} awaits activation (pin_status probe: {probe_desc}); refusing to send \
                     a modify APDU to it. Run `refineid pin activate` first to set PIN1 and \
                     PIN2.",
                    slot.label()
                )
            }
            Self::RetryFloor(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl core::error::Error for CardPinError {}

impl From<PcscError> for CardPinError {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

impl From<ReaderPickError> for CardPinError {
    fn from(e: ReaderPickError) -> Self {
        Self::ReaderPick(e)
    }
}

/// Map a lib-core `AuthError<TE>` into the client-side
/// [`CardPinError`] surface.
///
/// Transport errors stringify through the inner `Display` so
/// the CLI can show the underlying PC/SC message without
/// leaking the typed error to the public surface. PIN-policy
/// reasons (digit-only, length bounds) pass through as
/// `PinPolicy` because they are local-policy hits -- no
/// counter-burning APDU went out.
fn auth_to_card_pin(e: AuthError<impl fmt::Display>) -> CardPinError {
    match e {
        AuthError::Transport(t) => CardPinError::Transport(format!("{t}")),
        AuthError::PinPolicy(r) => CardPinError::PinPolicy(r),
    }
}

/// Trust-gated card session.
///
/// The trust gate has passed and a long-serial has been
/// bound. Activation-state is *not* yet known; downstream
/// operations must promote this into either
/// [`ActivationCardContext`] (for `pin activate`) or
/// [`PinManagementCardContext`] (for `pin change` /
/// `pin unblock`).
///
/// Built by `establish_trusted_session`: the card is identified
/// by ATR against the known FINEID citizen models or by the
/// organization reference numbering, its on-card root is pinned
/// against `PINNED_ROOT_SHA256`, its PKCS#15 long serial is
/// captured so any later step can detect a card swap mid-flow,
/// and its activation scheme is decided.
#[derive(Debug, Clone)]
pub struct TrustedCardSession {
    /// PC/SC reader id captured at trust-gate time; every
    /// subsequent re-open in the flow uses exactly this id.
    pub reader_id: refineid_lib_core::backend::ReaderId,
    /// Person identity extracted from the auth cert's subject DN
    /// (FINEID S2 §6.3.8.3). Read once at trust-gate time so PIN
    /// reports can show "who" without re-reading the cert.
    pub identity: refineid_lib_core::identity::CredentialIdentity,
    /// Attestation that justified using this card's data.
    /// `is_trusted()` returns `true` only for
    /// `PinnedRootMatched`.
    pub trust: CardTrustAttestation,
    /// PKCS#15 long serial bound at trust-gate time; every
    /// subsequent step re-reads and compares against this value
    /// to detect a card swap.
    pub bound_serial: refineid_lib_core::identity::TokenSerial,
    /// ATR-classified FINEID card model (see
    /// `doc/fineid-card-models.md`); `None` for an organization
    /// card the classifier does not know. Not a trust signal on
    /// its own; the trust signal is [`trust`](Self::trust).
    pub model: Option<FineidCardModel>,
    /// The credential reference numbering the card answers to.
    pub numbering: PinReferenceScheme,
    /// The authentication certificate's validity start; `None`
    /// when the certificate could not be read or parsed.
    pub validity_start: Option<DateTime>,
    /// The card's activation scheme
    /// ([`PinReferenceScheme::activation_scheme`]); `None` gives no
    /// activation decision.
    pub activation_scheme: Option<ActivationScheme>,
}

impl TrustedCardSession {
    /// Promote a trusted session into the
    /// [`PinManagementCardContext`] typestate, the input
    /// shape for `change_pin_first` and
    /// `unblock_pin_first`. By calling this constructor the
    /// caller asserts operator intent: the operator chose a
    /// PIN-management command (not `pin activate`), so they
    /// are claiming the card is in an already-activated
    /// state and the modify APDU is appropriate. The compiler
    /// then enforces that no `pin activate` code path can
    /// consume this value.
    ///
    /// This split is the type-level half of the safety; the
    /// runtime half (`pin_status` preflight + card-side
    /// counter on wrong PIN attempts) is in the modify
    /// functions themselves. Neither half alone catches every
    /// "operator inserted the wrong card" case; together they
    /// raise the floor.
    #[must_use]
    pub const fn into_pin_management_context(self) -> PinManagementCardContext {
        PinManagementCardContext { session: self }
    }
}

/// Card session promoted from a trusted base into the
/// "operator intends a PIN-management operation on an
/// already-activated card" typestate.
///
/// The type is opaque: there is no public field set, only a
/// borrow path back to the inner [`TrustedCardSession`].
/// Construct via
/// [`TrustedCardSession::into_pin_management_context`] from
/// the CLI's `pin change` / `pin unblock`
/// dispatch. Code in the `pin activate` dispatch cannot
/// produce this typestate by construction.
#[derive(Debug, Clone)]
pub struct PinManagementCardContext {
    /// Inner trusted session this context was promoted from.
    /// Held privately so callers can only reach
    /// reader id / identity / serial via the inherent methods,
    /// preventing accidental construction of an unrelated
    /// `PinManagementCardContext` from a stale session value.
    session: TrustedCardSession,
}

impl PinManagementCardContext {
    /// Borrow the reader id this context is bound to.
    #[must_use]
    pub const fn reader_id(&self) -> &refineid_lib_core::backend::ReaderId {
        &self.session.reader_id
    }
    /// Borrow the person identity captured at trust-gate time.
    #[must_use]
    pub const fn identity(&self) -> &refineid_lib_core::identity::CredentialIdentity {
        &self.session.identity
    }
    /// Borrow the trust attestation that justified building this
    /// context (always `PinnedRootMatched` once the type is
    /// constructed; other variants short-circuit in
    /// `establish_trusted_session`).
    #[must_use]
    pub const fn trust(&self) -> &CardTrustAttestation {
        &self.session.trust
    }
    /// Borrow the PKCS#15 long serial bound at trust-gate time.
    /// `re_verify_session` compares the on-card serial against
    /// this value before every modify APDU.
    #[must_use]
    pub const fn bound_serial(&self) -> &refineid_lib_core::identity::TokenSerial {
        &self.session.bound_serial
    }
    /// ATR-classified FINEID card model captured at trust-gate
    /// time; `None` for an organization card.
    #[must_use]
    pub const fn model(&self) -> Option<FineidCardModel> {
        self.session.model
    }
    /// The credential reference numbering the card answers to.
    #[must_use]
    pub const fn numbering(&self) -> PinReferenceScheme {
        self.session.numbering
    }
    /// The card's activation scheme; `None` gives no activation
    /// decision.
    #[must_use]
    pub const fn activation_scheme(&self) -> Option<ActivationScheme> {
        self.session.activation_scheme
    }
}

/// Run the trust-gate setup against the picked reader.
///
/// Phases (in order):
/// 1. Pick the FINEID-shape reader (or apply `reader_filter`).
/// 2. Open the transport, read the ATR, classify against the
///    known `FineidCardModel` set
///    ([`doc/fineid-card-models.md`][card]).
/// 3. SELECT the PKCS#15 application and resolve the reference
///    numbering; a card the ATR classifier does not know is
///    admitted only under the organization numbering.
/// 4. Read the on-card root cert (`EF.4334`), hash, match
///    against the pinned set ([`doc/fineid-s2-cert-profile.md`][s2]).
/// 5. Capture the PKCS#15 long serial for session binding.
/// 6. Read the authentication certificate's validity start and
///    decide the activation scheme.
///
/// Returns a [`TrustedCardSession`] the caller flows into the
/// modify step. The transport from this call is dropped; the
/// caller re-opens against `session.reader_id` and uses
/// `re_verify_session` before each modify APDU.
///
/// # Errors
/// - `CardModelNotSupported` -- ATR didn't classify and the card
///   answers the citizen numbering.
/// - `CardDataUntrusted` -- on-card root not pinned, or
///   PKCS#15 serial unavailable.
/// - PC/SC / SELECT / cert-read failures.
///
/// [card]: ../../../doc/fineid-card-models.md
/// [s2]: ../../../doc/fineid-s2-cert-profile.md
pub fn establish_trusted_session(
    backend: PcscBackend,
    reader_filter: Option<&ReaderFilter>,
) -> Result<TrustedCardSession, CardPinError> {
    use refineid_lib_core::transport::CardTransport as _;

    let FineidReaderPick {
        reader_id,
        identity,
    } = backend.pick_fineid_reader(reader_filter)?;
    let mut transport = backend.open_session(&reader_id, ReaderAccessCap::Read)?;

    // ATR classify -- public protocol-level signal for the citizen
    // models. An organization card is recognised by its reference
    // numbering (FINEID S4-2 v4.0 §4.2) instead.
    let atr = transport
        .atr()
        .map_err(|e| CardPinError::Transport(format!("ATR length: {e}")))?;
    let classified = atr.classify();

    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
    let numbering = transport
        .resolve_pin_reference_scheme()
        .map_err(auth_to_card_pin)?;
    let model = match (classified, numbering) {
        (Ok(model), _) => Some(model),
        (Err(_), PinReferenceScheme::Organizational) => None,
        (Err(e), PinReferenceScheme::Citizen) => {
            return Err(CardPinError::CardModelNotSupported(e));
        }
    };

    // Pinned-root trust gate (G3 RSA + G3 ECC both pinned per
    // doc/fineid-s2-cert-profile.md).
    let trust = match transport.read_certificate(CertSlot::RootCa) {
        Ok(root_der) => CardTrustAttestation::of_root(root_der.as_bytes()),
        Err(e) => CardTrustAttestation::RootCertUnavailable {
            reason: format!("{e}"),
        },
    };
    if !trust.is_trusted() {
        return Err(CardPinError::CardDataUntrusted {
            description: trust.describe(),
        });
    }

    // Bind the PKCS#15 long serial; `re_verify_session` checks
    // against this on every subsequent step. The serial is
    // session state (binds this transport to a specific
    // physical card for swap detection), not person identity,
    // so it doesn't live on `CredentialIdentity` -- read it
    // here directly from EF.TokenInfo.
    let token = transport
        .read_token_info()
        .map_err(|e| CardPinError::Transport(format!("EF.TokenInfo read: {e}")))?;
    let bound_serial = match token.serial_number_hex {
        Some(hex) => refineid_lib_core::identity::render_token_serial(hex),
        None => {
            return Err(CardPinError::CardDataUntrusted {
                description: "card did not publish a PKCS#15 serial; can't pin session identity"
                    .to_owned(),
            });
        }
    };

    let validity_start = transport
        .read_certificate(CertSlot::Authentication)
        .ok()
        .and_then(|der| OwnedCert::from_der(der.as_bytes()).ok())
        .map(|cert| cert.view().not_before);
    let activation_scheme = numbering.activation_scheme(validity_start);

    Ok(TrustedCardSession {
        reader_id,
        identity,
        trust,
        bound_serial,
        model,
        numbering,
        validity_start,
        activation_scheme,
    })
}

/// Gate for a change that presents the current PIN: a PIN that awaits
/// activation is refused, and the change is a PIN attempt, so the retry
/// floor applies; a probe that returned no status is an unreadable
/// counter.
fn change_gate(
    slot: PinManageSlot,
    readiness: PinReadiness,
    probe: Option<PinStatus>,
) -> Result<(), CardPinError> {
    if readiness == PinReadiness::AwaitsActivation {
        return Err(CardPinError::CardLooksUnactivated { slot, probe });
    }
    check_retry_floor(slot.as_pin_slot(), probe.unwrap_or(PinStatus::NoInfo))
        .map_err(CardPinError::RetryFloor)
}

/// Gate for a PUK-driven reset: a PIN that awaits activation is
/// refused, and the reset presents the PUK, so the retry floor applies
/// to the PUK's own counter. The target PIN's counter does not gate it:
/// a PIN at two, one or no tries left, or blocked, passes while the PUK
/// has five, four or three tries left.
fn unblock_gate(
    slot: PinManageSlot,
    readiness: PinReadiness,
    probe: Option<PinStatus>,
    puk: Option<PukStatus>,
) -> Result<(), CardPinError> {
    if readiness == PinReadiness::AwaitsActivation {
        return Err(CardPinError::CardLooksUnactivated { slot, probe });
    }
    puk_gate(puk)
}

/// One PIN's activation probes under `numbering`: its counter-safe
/// status and its PIN changed flag. The PIN container GET DATA
/// addresses the citizen references, so under the organization
/// numbering the flag is not read.
fn probe_slot<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut T,
    numbering: PinReferenceScheme,
    slot: PinSlot,
) -> SlotProbe {
    SlotProbe {
        status: transport.pin_status_with_scheme(slot, numbering).ok(),
        changed: match numbering {
            PinReferenceScheme::Citizen => transport.pin_changed_flag(slot).ok().flatten(),
            PinReferenceScheme::Organizational => None,
        },
    }
}

/// The retry floor for the PUK's counter; a probe that returned no
/// status is an unreadable counter.
fn puk_gate(puk: Option<PukStatus>) -> Result<(), CardPinError> {
    check_puk_retry_floor(puk.unwrap_or(PukStatus::NoInfo)).map_err(CardPinError::RetryFloor)
}

/// Rotate the PIN in `options.slot`. The card's own outcome
/// (wrong-current-PIN with retries-left, locked, etc.) is
/// surfaced via [`ChangePinReport::outcome`], not as an error.
///
/// `options` is taken by value so both embedded [`PinBytes`]
/// drop (and zeroize) when this returns.
///
/// # Errors
/// PC/SC / PKCS#15 / local-policy / transport failures.
pub fn change_pin_first(
    backend: PcscBackend,
    ctx: PinManagementCardContext,
    options: ChangePinOptions,
) -> Result<ChangePinReport, CardPinError> {
    change_pin_first_for_cli(backend, ctx, options)
}

/// Run the change gate (PIN activated, counter at or above the retry
/// floor) in a read-only session, so the CLI refuses before it prompts
/// for the PINs.
///
/// # Errors
/// [`CardPinError::RetryFloor`], [`CardPinError::CardLooksUnactivated`],
/// a card swap, or PC/SC / PKCS#15 failures.
pub(crate) fn probe_change_gate_for_cli(
    backend: PcscBackend,
    ctx: &PinManagementCardContext,
    slot: PinManageSlot,
) -> Result<(), CardPinError> {
    let mut transport = backend.open_session(ctx.reader_id(), ReaderAccessCap::Read)?;
    transport
        .select_pkcs15_application()
        .map_err(|error| CardPinError::Pkcs15Select(format!("{error}")))?;
    re_verify_session(&mut transport, ctx.bound_serial())?;
    let probe = probe_slot(&mut transport, ctx.numbering(), slot.as_pin_slot());
    change_gate(slot, probe.readiness(ctx.activation_scheme()), probe.status)
}

/// Run the unblock gate (PIN activated, PUK counter at or above the
/// retry floor) in a read-only session, so the CLI refuses before it
/// prompts for the PUK.
///
/// # Errors
/// [`CardPinError::RetryFloor`], [`CardPinError::CardLooksUnactivated`],
/// a card swap, or PC/SC / PKCS#15 failures.
pub(crate) fn probe_unblock_gate_for_cli(
    backend: PcscBackend,
    ctx: &PinManagementCardContext,
    slot: PinManageSlot,
) -> Result<(), CardPinError> {
    let mut transport = backend.open_session(ctx.reader_id(), ReaderAccessCap::Read)?;
    transport
        .select_pkcs15_application()
        .map_err(|error| CardPinError::Pkcs15Select(format!("{error}")))?;
    re_verify_session(&mut transport, ctx.bound_serial())?;
    let probe = probe_slot(&mut transport, ctx.numbering(), slot.as_pin_slot());
    unblock_gate(
        slot,
        probe.readiness(ctx.activation_scheme()),
        probe.status,
        transport.puk_status_with_scheme(ctx.numbering()).ok(),
    )
}

/// PIN change with the current PIN. Refuses on the retry floor before any
/// modify APDU, so a PIN at two, one or no tries left is never presented.
pub(crate) fn change_pin_first_for_cli(
    backend: PcscBackend,
    ctx: PinManagementCardContext,
    options: ChangePinOptions,
) -> Result<ChangePinReport, CardPinError> {
    // The typestate parameter `ctx` proves the caller is on a
    // PIN-management command path (operator intent: card is
    // activated). The compiler refuses to let
    // `ActivationCardContext` flow into this signature; the
    // `pin activate` dispatch cannot reach this function.
    let person = ctx.identity().person_string();
    let card_serial = ctx.identity().best_serial().unwrap_or("").to_owned();
    crate::events::CardTarget {
        device: ctx.reader_id().as_str(),
        card: &card_serial,
        person: &person,
    }
    .emit();

    // Re-open against the bound reader, SELECT, and re-verify
    // the bound serial -- catches a card swap between the
    // trust gate and the modify APDU. PinSequence: both PINs
    // arrived in `options` (prompts ran between sessions), so
    // the whole SELECT -> re-verify -> probe -> CHANGE span is
    // card-bound and runs inside one held PC/SC transaction.
    let mut transport = backend.open_session(ctx.reader_id(), ReaderAccessCap::PinSequence)?;
    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
    re_verify_session(&mut transport, ctx.bound_serial())?;

    // Counter-safe probes: the PIN's readiness and its counter.
    let slot = options.slot.as_pin_slot();
    let numbering = ctx.numbering();
    let probe = probe_slot(&mut transport, numbering, slot);
    change_gate(
        options.slot,
        probe.readiness(ctx.activation_scheme()),
        probe.status,
    )?;

    re_verify_session(&mut transport, ctx.bound_serial())?;

    let outcome = transport
        .change_pin_with_scheme(
            slot,
            numbering,
            options.current.clone(),
            options.new.clone(),
        )
        .map_err(auth_to_card_pin)?;
    let report = ChangePinReport {
        reader: ctx.reader_id().as_str().to_owned(),
        card_serial,
        person,
        slot: options.slot,
        outcome,
    };
    drop(options);
    drop(ctx);
    Ok(report)
}

/// PUK-driven unblock + replace PIN in `options.slot`.
///
/// **Danger:** a wrong PUK decrements the PUK try counter. Once
/// exhausted the card is dead -- no software recovery, DVV
/// reissue required. The card's own outcome (wrong-PUK with
/// retries-left, PUK locked, etc.) is surfaced via
/// [`UnblockPinReport::outcome`]. The PUK is presented only at five,
/// four or three PUK tries left; below that, blocked or unreadable, the
/// reset is refused before it is sent.
///
/// # Errors
/// PC/SC / PKCS#15 / local-policy / transport failures, and
/// [`CardPinError::RetryFloor`] for a PUK below the floor.
#[expect(
    clippy::needless_pass_by_value,
    reason = "UnblockPinOptions embeds PUK + new-PIN PinBytes; consumed by value so both drop+zeroize at function return."
)]
pub fn unblock_pin_first(
    backend: PcscBackend,
    ctx: PinManagementCardContext,
    options: UnblockPinOptions,
) -> Result<UnblockPinReport, CardPinError> {
    let person = ctx.identity().person_string();
    let card_serial = ctx.identity().best_serial().unwrap_or("").to_owned();
    crate::events::CardTarget {
        device: ctx.reader_id().as_str(),
        card: &card_serial,
        person: &person,
    }
    .emit();

    // PinSequence: PUK and the new PIN arrived in `options`
    // (the CLI prompts before this call), so the unblock span
    // is card-bound inside one held PC/SC transaction.
    let mut transport = backend.open_session(ctx.reader_id(), ReaderAccessCap::PinSequence)?;
    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
    re_verify_session(&mut transport, ctx.bound_serial())?;

    let slot = options.slot.as_pin_slot();
    let numbering = ctx.numbering();
    let probe = probe_slot(&mut transport, numbering, slot);
    unblock_gate(
        options.slot,
        probe.readiness(ctx.activation_scheme()),
        probe.status,
        transport.puk_status_with_scheme(numbering).ok(),
    )?;

    re_verify_session(&mut transport, ctx.bound_serial())?;

    // Bridge typed Puk to the auth primitive's PinBytes. The
    // transient PinBytes zeroizes on drop, same as every other
    // secret material.
    let puk_bytes = options.puk.to_pin_bytes();
    let outcome = transport
        .reset_retry_counter_with_scheme(slot, numbering, puk_bytes, options.new_pin.clone())
        .map_err(auth_to_card_pin)?;
    Ok(UnblockPinReport {
        reader: ctx.reader_id().as_str().to_owned(),
        card_serial,
        person,
        slot: options.slot,
        outcome,
    })
}

impl fmt::Display for ChangePinReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        if !self.card_serial.is_empty() {
            writeln!(f, "card:   {}", self.card_serial)?;
        }
        if !self.person.is_empty() {
            writeln!(f, "person: {}", self.person)?;
        }
        let label = self.slot.label();
        match &self.outcome {
            ChangePinOutcome::Ok => writeln!(
                f,
                "{label} changed; retry counter reset; re-VERIFY required for further ops"
            )?,
            ChangePinOutcome::WrongCurrentPin { retries_left } => {
                writeln!(f, "current {label} was wrong ({retries_left} retries left)")?;
            }
            ChangePinOutcome::Locked => writeln!(
                f,
                "{label} is blocked -- use the PUK to unblock before retrying"
            )?,
            ChangePinOutcome::LengthError => {
                writeln!(f, "card rejected APDU length (SW=6700) -- host bug")?;
            }
            ChangePinOutcome::Other(sw) => writeln!(f, "card returned unexpected SW={sw:#06X}")?,
        }
        Ok(())
    }
}

impl fmt::Display for UnblockPinReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        if !self.card_serial.is_empty() {
            writeln!(f, "card:   {}", self.card_serial)?;
        }
        if !self.person.is_empty() {
            writeln!(f, "person: {}", self.person)?;
        }
        let label = self.slot.label();
        match &self.outcome {
            UnblockOutcome::Ok => writeln!(
                f,
                "{label} unblocked; retry counter reset to max; re-VERIFY required for further ops"
            )?,
            UnblockOutcome::WrongPuk { retries_left } => writeln!(
                f,
                "PUK was wrong ({retries_left} retries left on the PUK itself; \
                 exhausting it permanently bricks the card)"
            )?,
            UnblockOutcome::PukLocked => writeln!(
                f,
                "PUK is itself blocked -- card needs DVV reissue, no software recovery"
            )?,
            UnblockOutcome::Invalidated => writeln!(
                f,
                "PIN unblock counter or PUK usage counter exhausted -- card needs DVV reissue"
            )?,
            UnblockOutcome::LengthError => {
                writeln!(f, "card rejected APDU length (SW=6700) -- host bug")?;
            }
            UnblockOutcome::Other(sw) => writeln!(f, "card returned unexpected SW={sw:#06X}")?,
        }
        Ok(())
    }
}

// ---- pin activate -- first-time setup flow --------------------

/// Outcome of verifying that card-side data can be trusted
/// before it drives type selection.
///
/// Per the typing-discipline rule "you cannot pass on
/// information that is not verified": the activation flow must
/// not use `cert.not_before` to choose an
/// [`refineid_lib_core::pin::ActivationCode`] variant until the
/// card itself has been authenticated against a pinned anchor.
///
/// Today this gate is the on-card root cert's SHA-256 matching
/// [`crate::trust_roots::PINNED_ROOT_SHA256`]. Full chain walk
/// (auth -> AIA-fetched intermediate -> on-card root) is a
/// follow-up; the pin-match alone defeats the "counterfeit
/// card with forged on-card data" attack because an attacker
/// can't put DVV's real root cert on a counterfeit card without
/// also forging a chain that signs it, which is the
/// cryptographic gate the pin enforces.
#[derive(Debug, Clone)]
pub enum CardTrustAttestation {
    /// On-card root cert's SHA-256 matched a pinned anchor.
    /// Card data may be used for type selection.
    PinnedRootMatched {
        /// Human-readable label of the pinned root that matched
        /// (e.g. "DVV CA Generation 3 RSA"). Sourced from
        /// `crate::trust_roots::PINNED_ROOT_SHA256`; the value
        /// is a compile-time string set so `&'static str` is
        /// acceptable.
        root_label: &'static str,
        /// SHA-256 of the on-card root DER -- the digest that
        /// matched the pin. Surfaced so logs can audit which
        /// fingerprint passed.
        root_sha256: Sha256,
    },
    /// On-card root cert was read but its SHA-256 doesn't match
    /// any pinned anchor. Card data MUST NOT be used.
    PinnedRootMismatch {
        /// Actual SHA-256 of the on-card root DER. Reported so
        /// the operator can confirm whether they're looking at a
        /// genuinely new generation (update the pin list) or a
        /// counterfeit / corrupted card.
        actual_sha256: Sha256,
    },
    /// On-card root cert couldn't be read at all (file absent,
    /// transport error). Card data MUST NOT be used.
    RootCertUnavailable {
        /// Underlying transport / parse error rendered via
        /// `to_string()`. Tier 0 `String`; presentational.
        reason: String,
    },
}

impl CardTrustAttestation {
    /// Attest an on-card root DER: hash it and look the digest up in
    /// [`crate::trust_roots::PINNED_ROOT_SHA256`] only. No earlier
    /// card's root, and nothing else read from a card, is a source
    /// of trust.
    #[must_use]
    pub fn of_root(root_der: &[u8]) -> Self {
        let actual = Sha256::of(root_der);
        crate::trust_roots::pinned_root_label(actual).map_or(
            Self::PinnedRootMismatch {
                actual_sha256: actual,
            },
            |label| Self::PinnedRootMatched {
                root_label: label,
                root_sha256: actual,
            },
        )
    }

    /// `true` only when card data may be passed forward to
    /// type-selection logic.
    #[must_use]
    pub const fn is_trusted(&self) -> bool {
        matches!(self, Self::PinnedRootMatched { .. })
    }

    /// Render the trust attestation as a one-line human
    /// string for the PIN-flow reports.
    ///
    /// Three shapes: positive (pinned to a labelled root with
    /// SHA-256), negative-pinning (root present but
    /// fingerprint unpinned), unavailable (could not read the
    /// root). The positive case is the only one with
    /// [`Self::is_trusted`] returning `true`.
    fn describe(&self) -> String {
        match self {
            Self::PinnedRootMatched {
                root_label,
                root_sha256,
            } => format!("on-card root pinned to {root_label} (sha256 {root_sha256})"),
            Self::PinnedRootMismatch { actual_sha256 } => format!(
                "ON-CARD ROOT NOT PINNED (actual sha256 {actual_sha256}); refusing to trust card data"
            ),
            Self::RootCertUnavailable { reason } => {
                format!("on-card root cert unreadable ({reason}); refusing to trust card data")
            }
        }
    }
}

/// Pre-activation card context.
///
/// Built only after [`CardTrustAttestation`] verifies the card
/// can be trusted and the card's activation scheme is decided.
/// The CLI uses the scheme to name the activation entry's length
/// in its prompt and construct the matching typed
/// [`refineid_lib_core::pin::ActivationCode`] variant.
///
/// The context also pins the **session identity** -- reader
/// name + card's long serial -- captured at trust-gate time.
/// Any subsequent step in the activation flow re-reads the
/// card's serial and refuses to continue if it doesn't match
/// (or if the transport fails outright, which covers card
/// removal / reader unplug / reader rename). Trust does not
/// survive a physical-state change.
#[derive(Debug, Clone)]
pub struct ActivationCardContext {
    /// PC/SC reader id captured at trust-gate time; subsequent
    /// re-opens in the activate flow use exactly this id.
    pub reader_id: refineid_lib_core::backend::ReaderId,
    /// Person identity extracted from the auth cert's subject DN
    /// at trust-gate time. Surfaced in activate report output.
    pub identity: refineid_lib_core::identity::CredentialIdentity,
    /// The authentication certificate's validity start; `None`
    /// when it could not be read (an organization card still has
    /// a scheme).
    pub validity_start: Option<DateTime>,
    /// The card's activation scheme
    /// ([`PinReferenceScheme::activation_scheme`]).
    pub scheme: ActivationScheme,
    /// The credential reference numbering the card answers to.
    pub numbering: PinReferenceScheme,
    /// Attestation that justified using the card data.
    pub trust: CardTrustAttestation,
    /// PKCS#15 EF.TokenInfo serial (long form) captured at
    /// trust-gate time. Any subsequent operation re-reads this
    /// and must match -- a different value means a card swap
    /// happened mid-flow, which revokes the trust.
    pub bound_serial: refineid_lib_core::identity::TokenSerial,
    /// The FINEID card model identified by ATR matching at
    /// session open (see [`doc/fineid-card-models.md`][doc]);
    /// `None` for an organization card the classifier does not
    /// know. ATR matching is **not** a trust signal on its own;
    /// the pinned-root SHA-256 in [`trust`](Self::trust) is.
    ///
    /// [doc]: ../../../doc/fineid-card-models.md
    pub model: Option<FineidCardModel>,
}

impl ActivationCardContext {
    /// The activation entry's exact digit count under the card's
    /// scheme: the 8-digit activation code (the PUK) for FINEID
    /// S4-1 v4.2 §4.6.1, the 7-digit preset activation PIN for
    /// §4.6.2.
    #[must_use]
    pub const fn activation_entry_digit_count(&self) -> usize {
        self.scheme.activation_entry_digit_count()
    }

    /// Whether the card answers the organization reference
    /// numbering (FINEID S4-2 v4.0 §4.2).
    #[must_use]
    pub const fn is_organization_card(&self) -> bool {
        matches!(self.numbering, PinReferenceScheme::Organizational)
    }
}

/// Run the trust gate against the picked FINEID reader and lift
/// the session into an [`ActivationCardContext`].
///
/// Per typing-discipline: we cannot pass on information that
/// hasn't been verified. The on-card root pin is the minimum
/// trust gate; until it matches, the certificate date isn't
/// trustworthy enough to drive type selection.
///
/// # Errors
/// - `CardDataUntrusted` when the on-card root doesn't match a
///   pinned anchor (or can't be read).
/// - `NoActivationScheme` when the scheme could not be decided.
/// - PC/SC / PKCS#15 / reader-pick failures.
pub fn classify_card_for_activation(
    backend: PcscBackend,
    reader_filter: Option<&ReaderFilter>,
) -> Result<ActivationCardContext, CardPinError> {
    let session = establish_trusted_session(backend, reader_filter)?;
    let scheme = session
        .activation_scheme
        .ok_or(CardPinError::NoActivationScheme)?;
    Ok(ActivationCardContext {
        reader_id: session.reader_id,
        identity: session.identity,
        validity_start: session.validity_start,
        scheme,
        numbering: session.numbering,
        trust: session.trust,
        bound_serial: session.bound_serial,
        model: session.model,
    })
}

/// Re-verify the trusted card session: the reader's still the
/// one we picked, the card's still there, and its long serial
/// still matches what we pinned at trust-gate time.
///
/// Called before every card-touching step in the activation
/// flow so a card swap / reader unplug / card removal between
/// the trust gate and the modify APDU is detected and refused.
///
/// # Errors
/// `CardSessionRevoked` on any divergence. Trust state cannot
/// be re-established by retrying -- the operator must re-run
/// the whole command.
fn re_verify_session<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut T,
    bound_serial: &refineid_lib_core::identity::TokenSerial,
) -> Result<(), CardPinError> {
    use refineid_lib_core::identity::render_token_serial;
    use refineid_lib_core::pkcs15::Pkcs15Ops as _;
    let token = transport
        .read_token_info()
        .map_err(|e| CardPinError::CardSessionRevoked {
            reason: format!("re-read EF.TokenInfo failed: {e}"),
        })?;
    let now_serial =
        token
            .serial_number_hex
            .as_ref()
            .ok_or_else(|| CardPinError::CardSessionRevoked {
                reason: "card no longer publishes EF.TokenInfo serial".to_owned(),
            })?;
    let current_full = render_token_serial(now_serial.clone());
    if &current_full != bound_serial {
        return Err(CardPinError::CardSessionRevoked {
            reason: format!(
                "card serial changed mid-flow: bound to {bound_serial:?}, \
                 reader now reports {current_full:?}"
            ),
        });
    }
    Ok(())
}

/// The PINs an activation sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationTarget {
    /// PIN1, then PIN2.
    Both,
    /// One PIN; the other keeps its state.
    One(PinManageSlot),
}

/// Inputs for `pin activate` -- the one-time DVV activation flow
/// that consumes the *activation PIN* (aktivointitunnusluku) from
/// the activation letter and sets the initial values of PIN1 and
/// PIN2.
#[derive(Debug)]
pub struct ActivateOptions {
    /// Typed activation entry from the DVV activation letter --
    /// [`ActivationCode::Seven`] under FINEID S4-1 v4.2 §4.6.2,
    /// [`ActivationCode::Eight`] under §4.6.1. The variant must
    /// match the card's [`ActivationScheme`]; a mismatch is
    /// reported as [`CardPinError::ActivationLengthMismatch`].
    pub activation_pin: ActivationCode,
    /// New basic PIN (PIN1, 4-12 digits).
    pub new_pin1: PinBytes,
    /// New signature PIN (PIN2, 6-12 digits).
    pub new_pin2: PinBytes,
    /// Override the pre-flight refusal when a targeted PIN reads
    /// as activated. Defaults to refuse-on-already-set.
    pub allow_reactivate: bool,
}

/// Inputs for `pin activate 1|2`: the activation flow for one PIN.
/// Each PIN's setup is its own card operation (FINEID S4-1 v4.2
/// s4.6), so one PIN can be set without the other.
#[derive(Debug)]
pub struct ActivateOneOptions {
    /// Typed activation code; see [`ActivateOptions::activation_pin`].
    pub activation_pin: ActivationCode,
    /// The PIN to set.
    pub slot: PinManageSlot,
    /// Its new value.
    pub new_pin: PinBytes,
    /// See [`ActivateOptions::allow_reactivate`].
    pub allow_reactivate: bool,
}

/// One reader's worth of activate output.
#[derive(Debug, Clone)]
pub struct ActivateReport {
    /// PC/SC reader name the activation APDUs landed against.
    /// Tier 0 `String` from `ReaderId::as_str().to_owned()`.
    pub reader: String,
    /// The PINs the run set out to activate.
    pub target: ActivationTarget,
    /// For [`ActivationTarget::One`]: the other PIN's probes showed
    /// it unactivated before the run, so the card is not fully
    /// active. `false` for [`ActivationTarget::Both`].
    pub other_looks_unactivated: bool,
    /// PIN-status pre-flight result. Surfaced so the operator
    /// can see whether refineid found the card unactivated /
    /// activated when it ran.
    pub preflight: ActivatePreflightOutcome,
    /// Card's outcome for the PIN1 setup. `None` when the
    /// pre-flight refusal aborted the flow before any APDU went
    /// out, or PIN1 is not in the target.
    pub pin1_outcome: Option<UnblockOutcome>,
    /// Same for PIN2. `None` also when PIN1 setup failed (we don't
    /// burn a second activation attempt against a card that's
    /// already rejected the code).
    pub pin2_outcome: Option<UnblockOutcome>,
}

/// What the PIN preflight saw before any modification was
/// attempted. Informational on success; the source of the refusal
/// otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivatePreflightOutcome {
    /// Every targeted PIN awaits activation. Activation proceeded.
    LooksUnactivated {
        /// Raw PIN1 probe outcome. `None` when the probe itself
        /// didn't return a status word.
        pin1: Option<PinStatus>,
        /// Raw PIN2 probe outcome. Same conventions as `pin1`.
        pin2: Option<PinStatus>,
    },
    /// A targeted PIN is activated, or the card does not show that
    /// it awaits activation ([`PinReadiness::Undecided`] reads as
    /// activated). Activation was refused (operator can override
    /// with `--allow-reactivate`).
    LooksActivated {
        /// PIN1 probe outcome. `None` when the probe returned no
        /// status word.
        pin1: Option<PinStatus>,
        /// PIN2 probe outcome. Same conventions as `pin1`.
        pin2: Option<PinStatus>,
    },
}

impl ActivatePreflightOutcome {
    /// `true` when a targeted PIN reads as activated. The CLI uses
    /// this to abort activation unless `--allow-reactivate` was
    /// passed.
    #[must_use]
    pub const fn looks_activated(&self) -> bool {
        matches!(self, Self::LooksActivated { .. })
    }
}

/// One PIN's activation probes: its counter status and its
/// PIN-changed flag.
#[derive(Debug, Clone, Copy)]
struct SlotProbe {
    /// Counter-safe `pin_status` result; `None` when the probe
    /// returned no status word.
    status: Option<PinStatus>,
    /// GET DATA "PIN changed" flag (`DF 2F`, S1 v4.2 s3.15.3);
    /// `None` when the card does not return it.
    changed: Option<bool>,
}

impl SlotProbe {
    /// The PIN's readiness under `scheme` ([`PinReadiness::judge`]).
    const fn readiness(self, scheme: Option<ActivationScheme>) -> PinReadiness {
        PinReadiness::judge(scheme, self.changed, self.status)
    }
}

/// Classify the PIN1/PIN2 probes into a preflight verdict over the
/// PINs `target` sets: unactivated only when every targeted PIN
/// awaits activation; an activated or undecided PIN makes it
/// activated.
fn classify_preflight(
    target: ActivationTarget,
    scheme: ActivationScheme,
    pin1: SlotProbe,
    pin2: SlotProbe,
) -> ActivatePreflightOutcome {
    let pin1_readiness = pin1.readiness(Some(scheme));
    let pin2_readiness = pin2.readiness(Some(scheme));
    let targeted: &[PinReadiness] = match target {
        ActivationTarget::Both => &[pin1_readiness, pin2_readiness],
        ActivationTarget::One(PinManageSlot::Pin1) => &[pin1_readiness],
        ActivationTarget::One(PinManageSlot::Pin2) => &[pin2_readiness],
    };
    let (pin1, pin2) = (pin1.status, pin2.status);
    if targeted
        .iter()
        .all(|&readiness| readiness == PinReadiness::AwaitsActivation)
    {
        ActivatePreflightOutcome::LooksUnactivated { pin1, pin2 }
    } else {
        ActivatePreflightOutcome::LooksActivated { pin1, pin2 }
    }
}

/// Map a `CHANGE REFERENCE DATA` outcome onto the
/// `UnblockOutcome` shape so [`ActivateReport`] can carry either
/// scheme's per-slot result behind a single field. The user-
/// facing semantics line up: a wrong "current PIN" on the new
/// scheme decrements the same five-try budget that a wrong PUK
/// burns on the old scheme, and the recovery path on either
/// terminal failure is the same DVV PUK-order procedure (S4-1
/// v4.2 §4.6.2 "When PIN(s) is/are blocked").
const fn change_to_unblock(o: ChangePinOutcome) -> UnblockOutcome {
    match o {
        ChangePinOutcome::Ok => UnblockOutcome::Ok,
        ChangePinOutcome::WrongCurrentPin { retries_left } => {
            UnblockOutcome::WrongPuk { retries_left }
        }
        ChangePinOutcome::Locked => UnblockOutcome::PukLocked,
        ChangePinOutcome::LengthError => UnblockOutcome::LengthError,
        ChangePinOutcome::Other(sw) => UnblockOutcome::Other(sw),
    }
}

/// Per-slot setup for [`activate_first`], FINEID S4-1 v4.2 §4.6:
///
/// - **§4.6.1, [`ActivationScheme::ActivationCodeIsPuk`]:** the
///   PIN ships blocked and the 8-digit activation code is the PUK.
///   `RESET RETRY COUNTER` (`INS=0x2C`) with `(activation code,
///   new PIN)`, under the PUK's retry floor. Organization cards
///   follow this scheme under their own reference numbering.
/// - **§4.6.2, [`ActivationScheme::PresetActivationPin`]:** the
///   PIN ships set to the 7-digit preset activation PIN. `CHANGE
///   REFERENCE DATA` (`INS=0x24`) with `(current = activation PIN,
///   new PIN)`.
///
/// `activation_pin_bytes` and `new_pin` are consumed by value so
/// the PIN material drops + zeroizes at function return.
fn activate_slot_setup<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut crate::apdu_trace::ApduTraceTransport<T>,
    slot: PinSlot,
    ctx: &ActivationCardContext,
    activation_pin_bytes: PinBytes,
    new_pin: PinBytes,
) -> Result<UnblockOutcome, CardPinError> {
    match ctx.scheme {
        ActivationScheme::PresetActivationPin => transport
            .change_pin_with_scheme(slot, ctx.numbering, activation_pin_bytes, new_pin)
            .map(change_to_unblock)
            .map_err(auth_to_card_pin),
        ActivationScheme::ActivationCodeIsPuk => {
            // The activation code is presented as the PUK, under the
            // PUK's counter.
            puk_gate(transport.puk_status_with_scheme(ctx.numbering).ok())?;
            transport
                .reset_retry_counter_with_scheme(slot, ctx.numbering, activation_pin_bytes, new_pin)
                .map_err(auth_to_card_pin)
        }
    }
}

const fn activation_continues_after_pin1(outcome: UnblockOutcome) -> bool {
    matches!(outcome, UnblockOutcome::Ok)
}

/// What [`activation_gate`] decided from the card's PIN probes.
enum ActivationGate {
    /// The card may be activated.
    Proceed {
        /// The preflight verdict.
        preflight: ActivatePreflightOutcome,
        /// See [`ActivateReport::other_looks_unactivated`].
        other_looks_unactivated: bool,
    },
    /// A targeted PIN looks activated and re-activation was not
    /// allowed.
    Refused(ActivateReport),
}

/// Probe both PIN slots and decide whether activation of `target`
/// may proceed: refuse a PIN that looks activated without
/// `allow_reactivate`, and apply the retry floor to the
/// counter the activation entry is presented under (each targeted
/// PIN under §4.6.2, the PUK under §4.6.1). `emit_probe` reports
/// the PIN-changed probe event.
///
/// # Errors
/// [`CardPinError::RetryFloor`] for a counter below the floor.
fn activation_gate<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut T,
    ctx: &ActivationCardContext,
    target: ActivationTarget,
    allow_reactivate: bool,
    emit_probe: bool,
) -> Result<ActivationGate, CardPinError> {
    let reader_label = ctx.reader_id.as_str().to_owned();
    let pin1 = probe_slot(transport, ctx.numbering, PinSlot::Pin1);
    let pin2 = probe_slot(transport, ctx.numbering, PinSlot::Pin2);
    if emit_probe {
        ActivateGuard::emit_pin_changed_probed(pin1.changed, pin2.changed);
    }
    let preflight = classify_preflight(target, ctx.scheme, pin1, pin2);
    let awaits =
        |probe: SlotProbe| probe.readiness(Some(ctx.scheme)) == PinReadiness::AwaitsActivation;
    let other_looks_unactivated = match target {
        ActivationTarget::Both => false,
        ActivationTarget::One(PinManageSlot::Pin1) => awaits(pin2),
        ActivationTarget::One(PinManageSlot::Pin2) => awaits(pin1),
    };

    if !allow_reactivate && preflight.looks_activated() {
        if let ActivatePreflightOutcome::LooksActivated { pin1, pin2 } = &preflight {
            let render =
                |status: &Option<PinStatus>| status.map_or_else(String::new, |s| format!("{s:?}"));
            crate::events::CardActivatePreflightRefused {
                reader: &reader_label,
                pin1_status: &render(pin1),
                pin2_status: &render(pin2),
            }
            .emit();
        }
        return Ok(ActivationGate::Refused(ActivateReport {
            reader: reader_label,
            target,
            other_looks_unactivated,
            preflight,
            pin1_outcome: None,
            pin2_outcome: None,
        }));
    }

    match ctx.scheme {
        // The activation PIN is presented as the current PIN, so each
        // setup is a PIN attempt under the retry floor.
        ActivationScheme::PresetActivationPin => {
            for (slot, probe) in [(PinSlot::Pin1, pin1), (PinSlot::Pin2, pin2)] {
                let targeted = match target {
                    ActivationTarget::Both => true,
                    ActivationTarget::One(one) => one.as_pin_slot() == slot,
                };
                if targeted {
                    check_retry_floor(slot, probe.status.unwrap_or(PinStatus::NoInfo))
                        .map_err(CardPinError::RetryFloor)?;
                }
            }
        }
        // The activation code is presented as the PUK.
        ActivationScheme::ActivationCodeIsPuk => {
            puk_gate(transport.puk_status_with_scheme(ctx.numbering).ok())?;
        }
    }
    Ok(ActivationGate::Proceed {
        preflight,
        other_looks_unactivated,
    })
}

/// Run [`activation_gate`] in a read-only session, so the CLI refuses
/// before it prompts for the activation PIN and the new PINs.
/// `Ok(Some(report))` is the refusal of an activated card.
///
/// # Errors
/// See [`activation_gate`]; also a card swap or PC/SC / PKCS#15
/// failures.
pub(crate) fn probe_activation_gate_for_cli(
    backend: PcscBackend,
    ctx: &ActivationCardContext,
    target: ActivationTarget,
    allow_reactivate: bool,
) -> Result<Option<ActivateReport>, CardPinError> {
    let mut transport = backend.open_session(&ctx.reader_id, ReaderAccessCap::Read)?;
    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
    re_verify_session(&mut transport, &ctx.bound_serial)?;
    Ok(
        match activation_gate(&mut transport, ctx, target, allow_reactivate, false)? {
            ActivationGate::Proceed { .. } => None,
            ActivationGate::Refused(report) => Some(report),
        },
    )
}

/// The new PIN values an activation sets.
enum ActivationPins {
    /// PIN1, then PIN2.
    Both {
        /// New PIN1.
        pin1: PinBytes,
        /// New PIN2.
        pin2: PinBytes,
    },
    /// One PIN.
    One {
        /// The PIN to set.
        slot: PinManageSlot,
        /// Its new value.
        pin: PinBytes,
    },
}

impl ActivationPins {
    /// The PINs these values set.
    const fn target(&self) -> ActivationTarget {
        match self {
            Self::Both { .. } => ActivationTarget::Both,
            Self::One { slot, .. } => ActivationTarget::One(*slot),
        }
    }
}

/// Drive the `pin activate` flow: trust-gated card -> factory
/// activation PIN -> fresh PIN1/PIN2.
///
/// FINEID S4-1 v4.2 §4.6. Steps:
///
///   1. Open a transport session against the bound reader.
///   2. Probe both PIN slots' status and PIN-changed flags
///      (counter-safe, never burns retries).
///   3. Refuse without `--allow-reactivate` a PIN that looks
///      activated ([`PinReadiness`]; undecided reads as activated).
///   4. Issue the scheme's APDU (`CHANGE REFERENCE DATA` under
///      §4.6.2 / `RESET RETRY COUNTER` under §4.6.1).
///   5. Emit per-step events; return the typed
///      [`ActivateReport`] so the CLI can summarise outcomes
///      without leaking PIN bytes.
///
/// `options` (and the inner [`PinBytes`]) is consumed by value
/// per Rule E1 -- on return the activation PIN + new PIN1/PIN2
/// are zeroized.
///
/// # Errors
/// Returns card selection, transport, PIN-policy, or activation failures.
pub fn activate_first(
    backend: PcscBackend,
    ctx: ActivationCardContext,
    options: ActivateOptions,
) -> Result<ActivateReport, CardPinError> {
    let ActivateOptions {
        activation_pin,
        new_pin1,
        new_pin2,
        allow_reactivate,
    } = options;
    run_activation(
        backend,
        &ctx,
        &activation_pin,
        allow_reactivate,
        ActivationPins::Both {
            pin1: new_pin1,
            pin2: new_pin2,
        },
    )
}

/// Drive the `pin activate 1|2` flow: [`activate_first`] for one
/// PIN. The preflight decides on that PIN's probes, and the retry
/// floor applies to its counter (§4.6.2) or the PUK's (§4.6.1).
///
/// # Errors
/// As [`activate_first`].
pub fn activate_one_first(
    backend: PcscBackend,
    ctx: ActivationCardContext,
    options: ActivateOneOptions,
) -> Result<ActivateReport, CardPinError> {
    let ActivateOneOptions {
        activation_pin,
        slot,
        new_pin,
        allow_reactivate,
    } = options;
    run_activation(
        backend,
        &ctx,
        &activation_pin,
        allow_reactivate,
        ActivationPins::One { slot, pin: new_pin },
    )
}

/// The shared body of [`activate_first`] and [`activate_one_first`].
/// `pins` is consumed so the new PIN values drop and zeroize here.
fn run_activation(
    backend: PcscBackend,
    ctx: &ActivationCardContext,
    activation_pin: &ActivationCode,
    allow_reactivate: bool,
    pins: ActivationPins,
) -> Result<ActivateReport, CardPinError> {
    let person = ctx.identity.person_string();
    crate::events::CardTarget {
        device: ctx.reader_id.as_str(),
        card: ctx.identity.best_serial().unwrap_or(""),
        person: &person,
    }
    .emit();

    // Validate the variant-vs-scheme invariant *before*
    // opening the reader so a mismatch surfaces a structured
    // length_mismatch event and the typed
    // `CardPinError::ActivationLengthMismatch` without burning
    // PC/SC resources.
    let reader_label = ctx.reader_id.as_str().to_owned();
    if let Some(err) = ActivateGuard::check_length_match(&reader_label, activation_pin, ctx.scheme)
    {
        return Err(err);
    }

    // PinSequence: the activation PIN and the new PINs arrived
    // in `options`, so the activation sequence is card-bound
    // inside one held PC/SC transaction (the trace wrapper does
    // not affect the hold; it lives in the inner PcscCard).
    let inner = backend.open_session(&ctx.reader_id, ReaderAccessCap::PinSequence)?;
    let mut transport = crate::apdu_trace::ApduTraceTransport::new(inner);
    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;

    // Session re-verification: the card we are about to touch
    // must be the same physical card the trust gate matched
    // against the pinned root. A card swap / reader rename /
    // reader unplug between the trust gate and here revokes
    // trust before any modify APDU lands.
    re_verify_session(&mut transport, &ctx.bound_serial)?;

    let target = pins.target();
    let (preflight, other_looks_unactivated) =
        match activation_gate(&mut transport, ctx, target, allow_reactivate, true)? {
            ActivationGate::Proceed {
                preflight,
                other_looks_unactivated,
            } => (preflight, other_looks_unactivated),
            ActivationGate::Refused(report) => return Ok(report),
        };
    let mut report = ActivateReport {
        reader: reader_label,
        target,
        other_looks_unactivated,
        preflight,
        pin1_outcome: None,
        pin2_outcome: None,
    };

    ActivateGuard::emit_scheme_selected(ctx.scheme);

    // Re-verify session before the first modify APDU.
    re_verify_session(&mut transport, &ctx.bound_serial)?;

    // The per-PIN setup APDU takes PinBytes by value; build a
    // transient PinBytes from the typed activation code's inner
    // bytes. Done per-call so the typed wrapper stays the source
    // of truth at the API boundary; the transient PinBytes
    // zeroizes on drop just like every other secret material.
    let activation_pin_bytes = activation_pin.to_pin_bytes();
    match pins {
        ActivationPins::One { slot, pin } => {
            let outcome = activate_slot_setup(
                &mut transport,
                slot.as_pin_slot(),
                ctx,
                activation_pin_bytes,
                pin,
            )?;
            ActivateGuard::emit_pin_set(&report.reader, slot, outcome);
            match slot {
                PinManageSlot::Pin1 => report.pin1_outcome = Some(outcome),
                PinManageSlot::Pin2 => report.pin2_outcome = Some(outcome),
            }
        }
        ActivationPins::Both { pin1, pin2 } => {
            let pin1_outcome = activate_slot_setup(
                &mut transport,
                PinSlot::Pin1,
                ctx,
                activation_pin_bytes.clone(),
                pin1,
            )?;
            ActivateGuard::emit_pin_set(&report.reader, PinManageSlot::Pin1, pin1_outcome);
            report.pin1_outcome = Some(pin1_outcome);

            // Single-shot: if PIN1 setup rejected the activation PIN
            // (wrong code, locked slot, anything other than Ok), don't
            // burn a second card-side try on the PIN2 slot. The operator
            // re-runs after fixing the input.
            if !activation_continues_after_pin1(pin1_outcome) {
                return Ok(report);
            }

            // Re-verify session before the second modify APDU. A card
            // swap between PIN1 and PIN2 setup is the canonical TOCTOU
            // case this gate defends against.
            re_verify_session(&mut transport, &ctx.bound_serial)?;

            let pin2_outcome = activate_slot_setup(
                &mut transport,
                PinSlot::Pin2,
                ctx,
                activation_pin_bytes,
                pin2,
            )?;
            ActivateGuard::emit_pin_set(&report.reader, PinManageSlot::Pin2, pin2_outcome);
            report.pin2_outcome = Some(pin2_outcome);
        }
    }
    Ok(report)
}

/// Activate-flow pre-flight helpers. Hosted on a unit struct per
/// typing-discipline (`doc/typing-discipline.md`).
struct ActivateGuard;

impl ActivateGuard {
    /// Variant-vs-scheme invariant. Emits the
    /// `card.activate.preflight.length_mismatch` event for a
    /// mismatch; returns the typed error so the caller can
    /// short-circuit.
    fn check_length_match(
        reader_label: &str,
        activation_pin: &ActivationCode,
        scheme: ActivationScheme,
    ) -> Option<CardPinError> {
        match (activation_pin, scheme) {
            (ActivationCode::Seven(_), ActivationScheme::PresetActivationPin)
            | (ActivationCode::Eight(_), ActivationScheme::ActivationCodeIsPuk) => None,
            (ActivationCode::Seven(_), ActivationScheme::ActivationCodeIsPuk)
            | (ActivationCode::Eight(_), ActivationScheme::PresetActivationPin) => {
                let expected = scheme.activation_entry_digit_count();
                Self::emit_length_mismatch(reader_label, scheme, expected);
                Some(CardPinError::ActivationLengthMismatch { scheme, expected })
            }
        }
    }

    /// Emit the `card.activate.preflight.length_mismatch`
    /// event when the activation entry's form doesn't fit the
    /// card's scheme.
    ///
    /// FINEID S4-1 v4.2 §4.6.1 takes the 8-digit activation code
    /// (the PUK), §4.6.2 the 7-digit preset activation PIN. The
    /// event is emitted *before* the typed error is returned so
    /// the audit trail captures the local-policy refusal even on
    /// pipelines that swallow the error string.
    fn emit_length_mismatch(reader_label: &str, scheme: ActivationScheme, expected: usize) {
        crate::events::CardActivatePreflightLengthMismatch {
            reader: reader_label,
            activation_scheme: &format!("{scheme:?}"),
            expected_length: &format!("{expected}"),
        }
        .emit();
    }

    /// Emit the `card.activate.preflight.pin_changed_probed`
    /// event with the per-slot PIN-changed flag values.
    ///
    /// FINEID S1 v4.2 §3.15.3 -- the card-side flag indicates
    /// whether the slot's PIN has been changed from its
    /// factory value, and decides the PIN's readiness under
    /// either scheme. `None` collapses to "indeterminate" (the
    /// card does not return the flag).
    fn emit_pin_changed_probed(pin1: Option<bool>, pin2: Option<bool>) {
        let render = |flag: Option<bool>| -> &'static str {
            match flag {
                Some(true) => "yes",
                Some(false) => "no",
                None => "indeterminate",
            }
        };
        crate::events::CardActivatePreflightPinChangedProbed {
            pin1_changed: render(pin1),
            pin2_changed: render(pin2),
        }
        .emit();
    }

    /// Emit the per-PIN setup event with the card's outcome.
    fn emit_pin_set(reader: &str, slot: PinManageSlot, outcome: UnblockOutcome) {
        let outcome = format!("{outcome:?}");
        match slot {
            PinManageSlot::Pin1 => crate::events::CardActivatePin1Set {
                reader,
                outcome: &outcome,
            }
            .emit(),
            PinManageSlot::Pin2 => crate::events::CardActivatePin2Set {
                reader,
                outcome: &outcome,
            }
            .emit(),
        }
    }

    /// Emit the `card.activate.scheme_selected` event naming
    /// the card's activation scheme and its APDU.
    ///
    /// FINEID S4-1 v4.2 §4.6.2 uses the `CHANGE REFERENCE DATA`
    /// form (INS=`24`), §4.6.1 `RESET RETRY COUNTER` (INS=`2C`).
    /// Emitted before the modify APDU goes out so the audit
    /// trail shows which path the activate flow took.
    fn emit_scheme_selected(activation_scheme: ActivationScheme) {
        let (scheme, apdu_ins, section) = match activation_scheme {
            ActivationScheme::PresetActivationPin => ("preset_activation_pin", "24", "4.6.2"),
            ActivationScheme::ActivationCodeIsPuk => ("activation_code_is_puk", "2c", "4.6.1"),
        };
        crate::events::CardActivateSchemeSelected {
            scheme,
            apdu_ins,
            fineid_s4_1_section: section,
        }
        .emit();
    }
}

impl fmt::Display for ActivateReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        match &self.preflight {
            ActivatePreflightOutcome::LooksUnactivated { .. } => {
                writeln!(f, "preflight: card looks un-activated; proceeding")?;
            }
            ActivatePreflightOutcome::LooksActivated { pin1, pin2 } => {
                writeln!(
                    f,
                    "preflight: card looks ALREADY ACTIVATED (PIN1: {}, PIN2: {})",
                    CardPinHelpers::fmt_probe(*pin1),
                    CardPinHelpers::fmt_probe(*pin2),
                )?;
                if self.pin1_outcome.is_none() && self.pin2_outcome.is_none() {
                    writeln!(
                        f,
                        "  refused without --allow-reactivate; activating a PIN \
                         that is already set overwrites it or spends one of its tries"
                    )?;
                    return Ok(());
                }
            }
        }
        if let Some(o) = self.pin1_outcome {
            writeln!(f, "PIN1 setup: {}", CardPinHelpers::fmt_unblock(o, "PIN1"))?;
        }
        if let Some(o) = self.pin2_outcome {
            writeln!(f, "PIN2 setup: {}", CardPinHelpers::fmt_unblock(o, "PIN2"))?;
        } else if self.target != ActivationTarget::Both {
            // A one-PIN activation reports only its PIN.
        } else if matches!(self.pin1_outcome, Some(UnblockOutcome::Ok)) {
            // Shouldn't happen -- if PIN1 succeeded we always try PIN2.
            writeln!(f, "PIN2 setup: not attempted")?;
        } else if self.pin1_outcome.is_some() {
            writeln!(
                f,
                "PIN2 setup: not attempted (PIN1 setup failed; re-run after fixing \
                 the activation PIN -- each invocation consumes one card-side try)"
            )?;
        } else {
            // No PIN setup attempted yet; nothing to report for PIN2.
        }
        Ok(())
    }
}

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct CardPinHelpers;

impl CardPinHelpers {
    /// Render a PIN status probe for the preflight lines.
    fn fmt_probe(status: Option<PinStatus>) -> String {
        status.map_or_else(|| "no reading".to_owned(), |s| format!("{s:?}"))
    }

    /// Render an [`UnblockOutcome`] for the activation / PIN-
    /// change reports.
    ///
    /// Each variant names the card-side condition in a way
    /// the operator can act on: `Ok` confirms counter reset,
    /// `WrongPuk` shows the remaining attempts, `PukLocked`
    /// names the DVV-paid reissue path, etc. `LengthError`
    /// is a host-side bug -- if the card returned `6700`,
    /// refineid sent a malformed APDU.
    fn fmt_unblock(o: UnblockOutcome, label: &str) -> String {
        match o {
            UnblockOutcome::Ok => format!("ok ({label} set; retry counter reset to max)"),
            UnblockOutcome::WrongPuk { retries_left } => {
                format!(
                    "WRONG activation PIN ({retries_left} card-side tries left; lockout pending)"
                )
            }
            UnblockOutcome::PukLocked => {
                "ACTIVATION PIN LOCKED -- order a PUK from DVV to recover (paid)".to_owned()
            }
            UnblockOutcome::Invalidated => {
                "card invalidated the activation PIN -- DVV reissue may be required".to_owned()
            }
            UnblockOutcome::LengthError => {
                "card rejected APDU length (SW=6700) -- host bug".to_owned()
            }
            UnblockOutcome::Other(sw) => format!("card returned unexpected SW={sw:#06X}"),
        }
    }
}

#[cfg(test)]
mod gate_tests {
    use refineid_lib_core::apdu::status_word::PinRetries;
    use refineid_lib_core::auth::{ActivationScheme, PIN_TRY_LIMIT};

    use super::{
        CardPinError, PinManageSlot, PinReadiness, PinStatus, PukStatus, change_gate, unblock_gate,
    };
    use crate::test_util::{TestResult, check_true};

    /// Tries left at which a PIN attempt is served.
    const SERVED: &[u8] = &[5, 4, 3];
    /// Tries left at which a PIN attempt is refused.
    const BELOW_FLOOR: &[u8] = &[2, 1, 0];
    /// A status word outside the modeled set.
    const UNMODELED_SW: u16 = 0x6F00;
    /// Both PINs a change or a PUK reset can target.
    const SLOTS: &[PinManageSlot] = &[PinManageSlot::Pin1, PinManageSlot::Pin2];
    /// Readiness verdicts that let a change or a PUK reset reach the
    /// retry floor.
    const NOT_AWAITING: &[PinReadiness] = &[PinReadiness::Activated, PinReadiness::Undecided];

    fn remaining(count: u8) -> Result<PinStatus, &'static str> {
        PinRetries::from_nibble(count)
            .map(PinStatus::Remaining)
            .ok_or("tries fit a nibble")
    }

    #[test]
    fn a_change_is_served_at_five_four_and_three_tries() -> TestResult {
        for &slot in SLOTS {
            for &readiness in NOT_AWAITING {
                for &count in SERVED {
                    check_true(
                        change_gate(slot, readiness, Some(remaining(count)?)).is_ok(),
                        "served",
                    )?;
                }
                check_true(
                    change_gate(slot, readiness, Some(PinStatus::Verified)).is_ok(),
                    "verified",
                )?;
            }
        }
        Ok(())
    }

    #[test]
    fn a_change_is_refused_at_two_one_zero_tries_and_blocked() -> TestResult {
        for &slot in SLOTS {
            let pin = match slot {
                PinManageSlot::Pin1 => "PIN 1",
                PinManageSlot::Pin2 => "PIN 2",
            };
            for &count in BELOW_FLOOR {
                let refused = change_gate(slot, PinReadiness::Activated, Some(remaining(count)?));
                check_true(
                    matches!(refused, Err(CardPinError::RetryFloor(_))),
                    "below the floor",
                )?;
                let text = refused.err().map(|e| e.to_string()).unwrap_or_default();
                check_true(text.contains(pin), "names the PIN")?;
                check_true(text.contains(&count.to_string()), "names the tries left")?;
                check_true(text.contains("PUK"), "names the PUK")?;
            }
            check_true(
                matches!(
                    change_gate(slot, PinReadiness::Activated, Some(PinStatus::Locked)),
                    Err(CardPinError::RetryFloor(_))
                ),
                "blocked",
            )?;
        }
        Ok(())
    }

    fn puk_remaining(count: u8) -> Result<PukStatus, &'static str> {
        PinRetries::from_nibble(count)
            .map(PukStatus::Remaining)
            .ok_or("tries fit a nibble")
    }

    #[test]
    fn a_puk_reset_is_allowed_at_any_pin_counter_while_the_puk_is_served() -> TestResult {
        for &slot in SLOTS {
            for &puk in SERVED {
                for &count in BELOW_FLOOR.iter().chain(SERVED) {
                    check_true(
                        unblock_gate(
                            slot,
                            PinReadiness::Activated,
                            Some(remaining(count)?),
                            Some(puk_remaining(puk)?),
                        )
                        .is_ok(),
                        "PUK reset",
                    )?;
                }
                check_true(
                    unblock_gate(
                        slot,
                        PinReadiness::Activated,
                        Some(PinStatus::Locked),
                        Some(puk_remaining(puk)?),
                    )
                    .is_ok(),
                    "blocked",
                )?;
            }
        }
        Ok(())
    }

    #[test]
    fn a_puk_reset_is_refused_at_two_one_zero_puk_tries() -> TestResult {
        for &slot in SLOTS {
            for &puk in BELOW_FLOOR {
                let refused = unblock_gate(
                    slot,
                    PinReadiness::Activated,
                    Some(PinStatus::Locked),
                    Some(puk_remaining(puk)?),
                );
                check_true(
                    matches!(refused, Err(CardPinError::RetryFloor(_))),
                    "below the floor",
                )?;
                let text = refused.err().map(|e| e.to_string()).unwrap_or_default();
                check_true(text.contains("PUK"), "names the PUK")?;
                check_true(text.contains(&puk.to_string()), "names the tries left")?;
                check_true(!text.contains("PIN"), "names no other credential")?;
            }
        }
        Ok(())
    }

    #[test]
    fn a_puk_reset_is_refused_on_a_blocked_or_unreadable_puk() -> TestResult {
        for &slot in SLOTS {
            for puk in [
                None,
                Some(PukStatus::NoInfo),
                Some(PukStatus::Locked),
                Some(PukStatus::Invalidated),
                Some(PukStatus::Other(UNMODELED_SW)),
            ] {
                check_true(
                    matches!(
                        unblock_gate(slot, PinReadiness::Activated, Some(PinStatus::Locked), puk),
                        Err(CardPinError::RetryFloor(_))
                    ),
                    "refused",
                )?;
            }
        }
        Ok(())
    }

    #[test]
    fn an_unreadable_counter_refuses_a_change_at_the_retry_floor() -> TestResult {
        for &slot in SLOTS {
            for probe in [None, Some(PinStatus::NoInfo)] {
                check_true(
                    matches!(
                        change_gate(slot, PinReadiness::Activated, probe),
                        Err(CardPinError::RetryFloor(_))
                    ),
                    "unreadable counter",
                )?;
            }
        }
        Ok(())
    }

    /// An unactivated §4.6.2 PIN has a full counter and its PIN
    /// changed flag unchanged: a change and a PUK reset both refuse
    /// it as awaiting activation.
    #[test]
    fn an_unactivated_preset_pin_is_refused_by_change_and_unblock() -> TestResult {
        let fresh = remaining(PIN_TRY_LIMIT)?;
        let readiness = PinReadiness::judge(
            Some(ActivationScheme::PresetActivationPin),
            Some(false),
            Some(fresh),
        );
        for &slot in SLOTS {
            check_true(
                matches!(
                    change_gate(slot, readiness, Some(fresh)),
                    Err(CardPinError::CardLooksUnactivated { .. })
                ),
                "change refused",
            )?;
            check_true(
                matches!(
                    unblock_gate(
                        slot,
                        readiness,
                        Some(fresh),
                        Some(puk_remaining(PIN_TRY_LIMIT)?)
                    ),
                    Err(CardPinError::CardLooksUnactivated { .. })
                ),
                "unblock refused",
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod activate_tests {
    use refineid_lib_core::apdu::status_word::PinRetries;
    use refineid_lib_core::auth::{ActivationScheme, PIN_TRY_LIMIT, PinReferenceScheme};

    use super::{
        ActivatePreflightOutcome, ActivationTarget, CardPinError, ChangePinOutcome, PinManageSlot,
        PinStatus, SlotProbe, UnblockOutcome, activation_continues_after_pin1, change_to_unblock,
        classify_preflight,
    };
    use crate::test_util::{TestResult, check_true};
    use refineid_lib_core::pin::ActivationPinSeven;

    /// The counter of a PIN or PUK never presented wrongly.
    fn fresh() -> Result<PinStatus, &'static str> {
        PinRetries::from_nibble(PIN_TRY_LIMIT)
            .map(PinStatus::Remaining)
            .ok_or("PIN_TRY_LIMIT fits a nibble")
    }

    /// An exhausted counter: the `63C0` "0 tries left" answer.
    fn exhausted() -> Result<PinStatus, &'static str> {
        const NO_TRIES_LEFT: u8 = 0;
        PinRetries::from_nibble(NO_TRIES_LEFT)
            .map(PinStatus::Remaining)
            .ok_or("zero fits a nibble")
    }

    const fn probe(status: Option<PinStatus>, changed: Option<bool>) -> SlotProbe {
        SlotProbe { status, changed }
    }

    /// §4.6.2 preflight with the PIN changed flag unreadable: the
    /// full counter is the factory state and an activated one alike,
    /// so the PIN reads as activated and is refused without
    /// `--allow-reactivate`.
    #[test]
    fn preset_preflight_unreadable_flag_reads_as_activated() -> TestResult {
        let pf = classify_preflight(
            ActivationTarget::Both,
            ActivationScheme::PresetActivationPin,
            probe(Some(fresh()?), None),
            probe(Some(fresh()?), None),
        );
        check_true(
            matches!(pf, ActivatePreflightOutcome::LooksActivated { .. }),
            "LooksActivated",
        )
    }

    /// §4.6.2 preflight, PIN changed flag unchanged: a fresh card,
    /// proceed.
    #[test]
    fn preset_preflight_unchanged_flag_proceeds() -> TestResult {
        let pf = classify_preflight(
            ActivationTarget::Both,
            ActivationScheme::PresetActivationPin,
            probe(Some(fresh()?), Some(false)),
            probe(Some(fresh()?), Some(false)),
        );
        check_true(
            matches!(pf, ActivatePreflightOutcome::LooksUnactivated { .. }),
            "LooksUnactivated",
        )?;
        check_true(!pf.looks_activated(), "proceeds")
    }

    /// §4.6.2 preflight, PIN changed flag changed: the card has
    /// been activated already; refuse so presenting the preset
    /// activation PIN doesn't spend a try.
    #[test]
    fn preset_preflight_changed_flag_refuses() -> TestResult {
        let pf = classify_preflight(
            ActivationTarget::Both,
            ActivationScheme::PresetActivationPin,
            probe(Some(fresh()?), Some(true)),
            probe(Some(fresh()?), Some(true)),
        );
        check_true(
            matches!(pf, ActivatePreflightOutcome::LooksActivated { .. }),
            "LooksActivated",
        )
    }

    /// Activating both touches both slots: a card whose PIN 2 was
    /// activated alone refuses, so the set PIN 2 is neither presented
    /// the factory code nor overwritten.
    #[test]
    fn both_preflight_refuses_when_only_pin2_is_activated() -> TestResult {
        let pf = classify_preflight(
            ActivationTarget::Both,
            ActivationScheme::PresetActivationPin,
            probe(Some(fresh()?), Some(false)),
            probe(Some(fresh()?), Some(true)),
        );
        check_true(
            matches!(pf, ActivatePreflightOutcome::LooksActivated { .. }),
            "LooksActivated",
        )
    }

    /// The changed flag alone proves activation; a status probe that
    /// returned nothing must not turn an activated PIN back into a
    /// factory one.
    #[test]
    fn changed_flag_refuses_without_a_status_reading() -> TestResult {
        for scheme in [
            ActivationScheme::PresetActivationPin,
            ActivationScheme::ActivationCodeIsPuk,
        ] {
            let pf = classify_preflight(
                ActivationTarget::One(PinManageSlot::Pin1),
                scheme,
                probe(None, Some(true)),
                probe(None, Some(false)),
            );
            check_true(
                matches!(pf, ActivatePreflightOutcome::LooksActivated { .. }),
                "LooksActivated",
            )?;
        }
        Ok(())
    }

    /// §4.6.1 factory PINs ship blocked: the card answers `6983`
    /// (blocked) or `63C0` (0 tries left). With the flag unchanged,
    /// or unreadable, both await activation, and activation proceeds
    /// without `--allow-reactivate`.
    #[test]
    fn puk_scheme_factory_pins_proceed_without_override() -> TestResult {
        for status in [PinStatus::Locked, exhausted()?] {
            for changed in [Some(false), None] {
                let pf = classify_preflight(
                    ActivationTarget::Both,
                    ActivationScheme::ActivationCodeIsPuk,
                    probe(Some(status), changed),
                    probe(Some(status), changed),
                );
                check_true(
                    matches!(pf, ActivatePreflightOutcome::LooksUnactivated { .. }),
                    "LooksUnactivated",
                )?;
                check_true(!pf.looks_activated(), "proceeds")?;
            }
        }
        Ok(())
    }

    /// §4.6.1 with the flag unreadable: a usable counter or a
    /// verified PIN is activated, and a reading that is neither a
    /// counter nor blocked reads as activated too.
    #[test]
    fn puk_scheme_counter_fallback_reads_as_activated() -> TestResult {
        for status in [fresh()?, PinStatus::Verified] {
            let pf = classify_preflight(
                ActivationTarget::One(PinManageSlot::Pin1),
                ActivationScheme::ActivationCodeIsPuk,
                probe(Some(status), None),
                probe(None, None),
            );
            check_true(
                matches!(pf, ActivatePreflightOutcome::LooksActivated { .. }),
                "LooksActivated",
            )?;
        }
        for status in [None, Some(PinStatus::NoInfo)] {
            let pf = classify_preflight(
                ActivationTarget::One(PinManageSlot::Pin1),
                ActivationScheme::ActivationCodeIsPuk,
                probe(status, None),
                probe(None, None),
            );
            check_true(
                matches!(pf, ActivatePreflightOutcome::LooksActivated { .. }),
                "undecided reads as activated",
            )?;
        }
        Ok(())
    }

    /// §4.6.1: a blocked PIN whose flag says changed was activated
    /// and then used up; it belongs to PUK recovery, not activation.
    #[test]
    fn puk_scheme_blocked_changed_pin_is_activated() -> TestResult {
        let pf = classify_preflight(
            ActivationTarget::Both,
            ActivationScheme::ActivationCodeIsPuk,
            probe(Some(PinStatus::Locked), Some(true)),
            probe(Some(PinStatus::Locked), Some(false)),
        );
        check_true(
            matches!(pf, ActivatePreflightOutcome::LooksActivated { .. }),
            "LooksActivated",
        )
    }

    /// An organization card activates by §4.6.1 whatever the
    /// certificate date: its blocked PINs (`63C0`) with no readable
    /// flag await activation.
    #[test]
    fn organization_card_activates_by_the_puk_scheme() -> TestResult {
        let scheme = PinReferenceScheme::Organizational
            .activation_scheme(None)
            .ok_or("organization numbering has a scheme")?;
        check_true(
            scheme == ActivationScheme::ActivationCodeIsPuk,
            "activation code is the PUK",
        )?;
        let pf = classify_preflight(
            ActivationTarget::Both,
            scheme,
            probe(Some(exhausted()?), None),
            probe(Some(exhausted()?), None),
        );
        check_true(!pf.looks_activated(), "proceeds")
    }

    /// A one-PIN activation decides on that PIN's probes: with PIN1
    /// changed and PIN2 still factory, PIN2 may be activated, PIN1 is
    /// refused, and each one's other PIN reads as it is.
    #[test]
    fn one_pin_preflight_decides_on_that_pin() -> TestResult {
        let scheme = ActivationScheme::PresetActivationPin;
        let changed = probe(Some(fresh()?), Some(true));
        let factory = probe(Some(fresh()?), Some(false));
        let one = ActivationTarget::One;
        check_true(
            !classify_preflight(one(PinManageSlot::Pin2), scheme, changed, factory)
                .looks_activated(),
            "PIN 2 proceeds",
        )?;
        check_true(
            classify_preflight(one(PinManageSlot::Pin1), scheme, changed, factory)
                .looks_activated(),
            "PIN 1 refused",
        )?;
        check_true(
            classify_preflight(ActivationTarget::Both, scheme, changed, factory).looks_activated(),
            "both refused while one PIN is activated",
        )
    }

    /// §4.6.2 PIN setup uses `CHANGE REFERENCE DATA`; the
    /// outcome is `ChangePinOutcome`. `ActivateReport` carries
    /// the unified `UnblockOutcome` form -- check the variant
    /// mapping covers every case.
    #[test]
    fn change_to_unblock_covers_every_variant() -> TestResult {
        let three = PinRetries::from_nibble(3).ok_or("PinRetries::from_nibble(3)")?;
        check_true(
            matches!(change_to_unblock(ChangePinOutcome::Ok), UnblockOutcome::Ok),
            "Ok -> Ok",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::WrongCurrentPin {
                    retries_left: three
                }),
                UnblockOutcome::WrongPuk { .. }
            ),
            "WrongCurrentPin -> WrongPuk",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::Locked),
                UnblockOutcome::PukLocked
            ),
            "Locked -> PukLocked",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::LengthError),
                UnblockOutcome::LengthError
            ),
            "LengthError -> LengthError",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::Other(0x6A88)),
                UnblockOutcome::Other(0x6A88)
            ),
            "Other -> Other",
        )
    }

    #[test]
    fn activation_failure_never_proceeds_to_pin2() -> TestResult {
        let three = PinRetries::from_nibble(3).ok_or("PinRetries::from_nibble(3)")?;
        check_true(
            activation_continues_after_pin1(UnblockOutcome::Ok),
            "successful PIN1 activation proceeds to PIN2",
        )?;
        for outcome in [
            UnblockOutcome::WrongPuk {
                retries_left: three,
            },
            UnblockOutcome::PukLocked,
            UnblockOutcome::Invalidated,
            UnblockOutcome::LengthError,
            UnblockOutcome::Other(0x6A80),
        ] {
            check_true(
                !activation_continues_after_pin1(outcome),
                "failed PIN1 activation stops before PIN2",
            )?;
        }
        Ok(())
    }

    #[test]
    fn activation_length_mismatch_debug_and_display_do_not_leak_candidate_length() -> TestResult {
        let err = CardPinError::ActivationLengthMismatch {
            scheme: ActivationScheme::PresetActivationPin,
            expected: ActivationPinSeven::LENGTH,
        };
        let expected_debug = format!(
            "ActivationLengthMismatch {{ scheme: PresetActivationPin, expected: {} }}",
            ActivationPinSeven::LENGTH
        );
        check_true(format!("{err:?}") == expected_debug, "debug format")?;
        check_true(
            err.to_string()
                .contains(&format!("takes {} digits", ActivationPinSeven::LENGTH)),
            "display format",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod trust_tests {
    use super::CardTrustAttestation;
    use crate::test_util::{TestResult, check_true};

    /// A public self-signed root that is not a DVV root.
    const UNPINNED_SELF_SIGNED_PEM: &[u8] =
        include_bytes!("../test-vectors/icao-pkd-un-csca-2.pem");
    /// The pinned DVV G3 ECC root.
    const DVV_ROOT_ECC_DER: &[u8] = include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-ecc.der");

    /// An unpinned self-signed root is refused on the first card a
    /// process sees and on every card after it: presenting it does
    /// not make it trusted.
    #[test]
    fn an_unpinned_self_signed_root_is_refused_even_as_the_first_card() -> TestResult {
        let root = crate::text::decode_cert_pem_or_der(UNPINNED_SELF_SIGNED_PEM)
            .ok_or("decode the self-signed root")?;
        for presentation in ["first card", "same root again"] {
            check_true(
                !CardTrustAttestation::of_root(&root).is_trusted(),
                presentation,
            )?;
        }
        check_true(
            CardTrustAttestation::of_root(DVV_ROOT_ECC_DER).is_trusted(),
            "pinned DVV root",
        )?;
        check_true(
            !CardTrustAttestation::of_root(&root).is_trusted(),
            "still refused after a pinned card",
        )
    }
}
