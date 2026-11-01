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

//! Typed event schemas.
//!
//! Every event refineid emits has a corresponding struct here.
//! Each struct holds `&str` field values (zero-copy from the
//! call site) and accompanying `const` blocks declare the
//! [`EventName`], [`Severity`], [`Persistence`], and per-field
//! [`FieldDescriptor`]s that bind the schema to the
//! [`EventRecord`] trait in `refineid-lib-core`. Adding a
//! nested struct or a non-string field to one of these
//! definitions is a code-review event (the observability
//! "flat keys only" rule per `doc/observability.md`).
//!
//! See [`doc/observability.md`][doc] for the format contract,
//! event-name hierarchy, severity-per-level guidance (Rule
//! E16), persistence-tier guidance (Rule E18), and the privacy
//! classification (Rule E1 + the `FieldPrivacy` enum). New
//! events get a new struct + a `const` block of typed
//! identifiers + an `impl EventRecord` block that wires them
//! together; the existing entries below are the worked
//! examples.
//!
//! [doc]: ../../../../doc/observability.md
//!
//! ## Why each event also gets a `.emit(&self)` method
//!
//! The trait method is `refineid_lib_core::events::emit::<E>(&E)`
//! and works equally well at call sites. The thin `.emit(&self)`
//! shim on each event lets calling code write
//! `crate::events::CardTarget { ... }.emit();` -- the
//! ergonomic shape the codebase already uses pervasively.
//! The shim dispatches to the typed trait emit; the wire form
//! is identical.

use core::fmt;

use refineid_lib_core::events::{
    EventName, EventRecord, FieldDescriptor, FieldName, FieldPrivacy, Persistence, Severity,
};

// ===========================================================
// card.target
// ===========================================================

/// `card.target` -- emitted at the start of every command that
/// addresses a specific card.
///
/// Goes out before any modify APDU. Records which physical
/// reader + which card serial + who's on the card, so a SOC
/// reader of the log can pin every later event to a specific
/// session.
#[derive(Debug)]
pub struct CardTarget<'a> {
    /// PC/SC reader name as the OS exposes it.
    pub device: &'a str,
    /// Best-available card serial -- printed plastic serial
    /// when known, otherwise the full PKCS#15 form.
    pub card: &'a str,
    /// Surname + given names + PEUIN, space-separated. Empty
    /// string when the auth cert wasn't readable.
    pub person: &'a str,
}

impl CardTarget<'_> {
    /// Event-name identifier emitted on the log line.
    pub const EVENT_NAME: EventName = EventName::new("card.target");
    /// Severity per Rule E16: notice (session-start audit signal).
    pub const LEVEL: Severity = Severity::Notice;
    /// Persistence per Rule E18: ephemeral (routine session
    /// marker; failures persist, success does not).
    pub const PERSISTENCE: Persistence = Persistence::Ephemeral;
    /// Reader name; safe to emit to public destinations.
    pub const F_DEVICE: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("device"), FieldPrivacy::Public);
    /// Card serial: PII (per Rule E1's privacy classification);
    /// uniquely identifies the citizen via the DVV registry.
    pub const F_CARD: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("card"), FieldPrivacy::Private);
    /// Holder identity (name + PEUIN): PII.
    pub const F_PERSON: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("person"), FieldPrivacy::Private);

    /// Emit this event to the configured global log sink.
    pub fn emit(&self) {
        refineid_lib_core::events::emit(self);
    }
}

impl EventRecord for CardTarget<'_> {
    fn event_name(&self) -> EventName {
        Self::EVENT_NAME
    }

    fn level(&self) -> Severity {
        Self::LEVEL
    }

    fn persistence(&self) -> Persistence {
        Self::PERSISTENCE
    }

    fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display)) {
        f(Self::F_DEVICE, &self.device);
        f(Self::F_CARD, &self.card);
        f(Self::F_PERSON, &self.person);
    }
}

// ===========================================================
// card.activate.preflight.ready
// ===========================================================

/// `card.activate.preflight.ready` -- emitted once after the
/// card session is open and the card's activation scheme is
/// decided, just before the operator is prompted for the
/// activation PIN.
///
/// The structured form of "here's what we know about the card
/// and here's what we're about to do." SOC parsers get a flat
/// snapshot of the activation policy at the moment of input;
/// humans can pretty-print. Semantic explanations of these
/// fields (what consumes-the-letter-PIN means, why ONE attempt
/// per invocation, the DVV cutoff reasoning) live in
/// [`doc/dvv-terminology.md`][dvv], not in the event payload.
///
/// [dvv]: ../../../../doc/dvv-terminology.md
#[derive(Debug)]
pub struct CardActivatePreflightReady<'a> {
    /// Auth cert `notBefore` as `YYYY-MM-DD`; `""` when it was
    /// not readable.
    pub card_issued: &'a str,
    /// DVV category label, e.g. `"Citizen eID"`. See
    /// `doc/fineid-card-models.md` for the allowed set. This and
    /// the other model fields are `""` for an organization card
    /// the ATR classifier does not know.
    pub card_type: &'a str,
    /// Vendor brand DVV publishes for this model, e.g.
    /// `"Thales"` or `"Gemalto"`.
    pub card_vendor: &'a str,
    /// Vendor's product family name, e.g. `"MultiApp"`.
    pub card_vendor_product: &'a str,
    /// Vendor's product version, bare (no leading `v`), e.g.
    /// `"5.0"` or `"4.2"`.
    pub card_vendor_product_version: &'a str,
    /// FINEID specification document identifier, e.g.
    /// `"S4-1"`.
    pub fineid_specification: &'a str,
    /// Version of the FINEID specification document, bare,
    /// e.g. `"4.0"` or `"3.1"`.
    pub fineid_specification_version: &'a str,
    /// Activation entry length the card's scheme takes -- `"8"`
    /// for the FINEID S4-1 v4.2 §4.6.1 activation PIN (the PUK),
    /// `"7"` for the §4.6.2 preset activation PIN. The scheme
    /// comes from the reference numbering and the certificate's
    /// validity start, not from the card model.
    pub activation_pin_length: &'a str,
    /// Card-side wrong-try cap before the activation entry
    /// locks. `"5"` under both schemes.
    pub wrong_tries_to_lock: &'a str,
    /// `"1"` -- refineid runs one activation attempt per
    /// invocation by design.
    pub attempts_this_invocation: &'a str,
}

impl CardActivatePreflightReady<'_> {
    /// Event-name identifier emitted on the log line.
    pub const EVENT_NAME: EventName = EventName::new("card.activate.preflight.ready");
    /// Severity per Rule E16: notice (about to take a security-
    /// relevant action -- the activation flow is starting).
    pub const LEVEL: Severity = Severity::Notice;
    /// Persistence per Rule E18: ephemeral (the act itself
    /// is forensic-grade and emits via `CardActivatePin1Set` /
    /// `CardActivatePin2Set`; the preflight context is
    /// background not worth the disk artifact on its own).
    pub const PERSISTENCE: Persistence = Persistence::Ephemeral;
    /// Card issuance date; not PII on its own.
    pub const F_CARD_ISSUED: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("card_issued"), FieldPrivacy::Public);
    /// DVV category label; not PII.
    pub const F_CARD_TYPE: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("card_type"), FieldPrivacy::Public);
    /// Card vendor; not PII.
    pub const F_CARD_VENDOR: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("card_vendor"), FieldPrivacy::Public);
    /// Card vendor product family; not PII.
    pub const F_CARD_VENDOR_PRODUCT: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("card_vendor_product"), FieldPrivacy::Public);
    /// Card vendor product version; not PII.
    pub const F_CARD_VENDOR_PRODUCT_VERSION: FieldDescriptor = FieldDescriptor::new(
        FieldName::new("card_vendor_product_version"),
        FieldPrivacy::Public,
    );
    /// FINEID spec identifier; not PII.
    pub const F_FINEID_SPECIFICATION: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("fineid_specification"), FieldPrivacy::Public);
    /// FINEID spec version; not PII.
    pub const F_FINEID_SPECIFICATION_VERSION: FieldDescriptor = FieldDescriptor::new(
        FieldName::new("fineid_specification_version"),
        FieldPrivacy::Public,
    );
    /// Activation PIN length (`"7"` / `"8"`); not PII.
    pub const F_ACTIVATION_PIN_LENGTH: FieldDescriptor = FieldDescriptor::new(
        FieldName::new("activation_pin_length"),
        FieldPrivacy::Public,
    );
    /// Wrong-tries cap; not PII.
    pub const F_WRONG_TRIES_TO_LOCK: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("wrong_tries_to_lock"), FieldPrivacy::Public);
    /// Attempts-per-invocation; not PII.
    pub const F_ATTEMPTS_THIS_INVOCATION: FieldDescriptor = FieldDescriptor::new(
        FieldName::new("attempts_this_invocation"),
        FieldPrivacy::Public,
    );

    /// Emit this event to the configured global log sink.
    pub fn emit(&self) {
        refineid_lib_core::events::emit(self);
    }
}

impl EventRecord for CardActivatePreflightReady<'_> {
    fn event_name(&self) -> EventName {
        Self::EVENT_NAME
    }

    fn level(&self) -> Severity {
        Self::LEVEL
    }

    fn persistence(&self) -> Persistence {
        Self::PERSISTENCE
    }

    fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display)) {
        f(Self::F_CARD_ISSUED, &self.card_issued);
        f(Self::F_CARD_TYPE, &self.card_type);
        f(Self::F_CARD_VENDOR, &self.card_vendor);
        f(Self::F_CARD_VENDOR_PRODUCT, &self.card_vendor_product);
        f(
            Self::F_CARD_VENDOR_PRODUCT_VERSION,
            &self.card_vendor_product_version,
        );
        f(Self::F_FINEID_SPECIFICATION, &self.fineid_specification);
        f(
            Self::F_FINEID_SPECIFICATION_VERSION,
            &self.fineid_specification_version,
        );
        f(Self::F_ACTIVATION_PIN_LENGTH, &self.activation_pin_length);
        f(Self::F_WRONG_TRIES_TO_LOCK, &self.wrong_tries_to_lock);
        f(
            Self::F_ATTEMPTS_THIS_INVOCATION,
            &self.attempts_this_invocation,
        );
    }
}

// ===========================================================
// card.activate.preflight.refused
// ===========================================================

/// `card.activate.preflight.refused` -- PIN-status pre-flight
/// refused the activation.
///
/// A targeted PIN reads as activated (a PIN the card does not
/// show to await activation reads as activated) and
/// `--allow-reactivate` was not passed. The flow aborts before any
/// modify APDU lands.
#[derive(Debug)]
pub struct CardActivatePreflightRefused<'a> {
    /// Reader the probe ran against.
    pub reader: &'a str,
    /// PIN1 status probe outcome, rendered
    /// via [`PinStatus`]' `Debug` ("Verified", "Remaining(5)",
    /// "Locked").
    ///
    /// [`PinStatus`]: refineid_lib_core::auth::PinStatus
    pub pin1_status: &'a str,
    /// PIN2 status probe outcome. `""` when the PIN2 probe
    /// didn't return a status word.
    pub pin2_status: &'a str,
}

impl CardActivatePreflightRefused<'_> {
    /// Event-name identifier emitted on the log line.
    pub const EVENT_NAME: EventName = EventName::new("card.activate.preflight.refused");
    /// Severity per Rule E16: warning (recoverable rejection;
    /// operator-relevant).
    pub const LEVEL: Severity = Severity::Warning;
    /// Persistence per Rule E18: OS-managed (the citizen may
    /// want to diagnose why activation was refused).
    pub const PERSISTENCE: Persistence = Persistence::OsManaged;
    /// Reader name.
    pub const F_READER: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("reader"), FieldPrivacy::Public);
    /// PIN1 status enum-as-string.
    pub const F_PIN1_STATUS: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("pin1_status"), FieldPrivacy::Public);
    /// PIN2 status enum-as-string.
    pub const F_PIN2_STATUS: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("pin2_status"), FieldPrivacy::Public);

    /// Emit this event to the configured global log sink.
    pub fn emit(&self) {
        refineid_lib_core::events::emit(self);
    }
}

impl EventRecord for CardActivatePreflightRefused<'_> {
    fn event_name(&self) -> EventName {
        Self::EVENT_NAME
    }

    fn level(&self) -> Severity {
        Self::LEVEL
    }

    fn persistence(&self) -> Persistence {
        Self::PERSISTENCE
    }

    fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display)) {
        f(Self::F_READER, &self.reader);
        f(Self::F_PIN1_STATUS, &self.pin1_status);
        f(Self::F_PIN2_STATUS, &self.pin2_status);
    }
}

// ===========================================================
// card.activate.preflight.length_mismatch
// ===========================================================

/// `card.activate.preflight.length_mismatch` -- typed activation
/// entry variant did not match the length the card's activation
/// scheme requires.
///
/// Refineid refuses *before* any modify APDU so the operator can
/// re-prompt without burning a card-side try.
#[derive(Debug)]
pub struct CardActivatePreflightLengthMismatch<'a> {
    /// Reader the operator targeted.
    pub reader: &'a str,
    /// The card's activation scheme (`"ActivationCodeIsPuk"` /
    /// `"PresetActivationPin"`), rendered via
    /// [`ActivationScheme`]'s `Debug`.
    ///
    /// [`ActivationScheme`]: refineid_lib_core::auth::ActivationScheme
    pub activation_scheme: &'a str,
    /// Activation-entry length the scheme requires (`"8"` for
    /// §4.6.1, `"7"` for §4.6.2).
    pub expected_length: &'a str,
}

impl CardActivatePreflightLengthMismatch<'_> {
    /// Event-name identifier emitted on the log line.
    pub const EVENT_NAME: EventName = EventName::new("card.activate.preflight.length_mismatch");
    /// Severity per Rule E16: warning (failed precondition).
    pub const LEVEL: Severity = Severity::Warning;
    /// Persistence per Rule E18: OS-managed (operator may
    /// want to see the mismatch reason after the fact).
    pub const PERSISTENCE: Persistence = Persistence::OsManaged;
    /// Reader name.
    pub const F_READER: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("reader"), FieldPrivacy::Public);
    /// The card's activation scheme.
    pub const F_ACTIVATION_SCHEME: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("activation_scheme"), FieldPrivacy::Public);
    /// Expected PIN length (`"7"` / `"8"`).
    pub const F_EXPECTED_LENGTH: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("expected_length"), FieldPrivacy::Public);

    /// Emit this event to the configured global log sink.
    pub fn emit(&self) {
        refineid_lib_core::events::emit(self);
    }
}

impl EventRecord for CardActivatePreflightLengthMismatch<'_> {
    fn event_name(&self) -> EventName {
        Self::EVENT_NAME
    }

    fn level(&self) -> Severity {
        Self::LEVEL
    }

    fn persistence(&self) -> Persistence {
        Self::PERSISTENCE
    }

    fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display)) {
        f(Self::F_READER, &self.reader);
        f(Self::F_ACTIVATION_SCHEME, &self.activation_scheme);
        f(Self::F_EXPECTED_LENGTH, &self.expected_length);
    }
}

// ===========================================================
// card.activate.preflight.pin_changed_probed
// ===========================================================

/// `card.activate.preflight.pin_changed_probed` -- emitted after
/// the GET DATA `DF 2F` probe for both PIN slots.
///
/// The flag decides whether each PIN awaits activation under
/// either scheme (S1 v4.2 §3.15.3); without it, §4.6.1 reads the
/// PIN counter and §4.6.2 makes no decision.
#[derive(Debug)]
pub struct CardActivatePreflightPinChangedProbed<'a> {
    /// PIN1 "PIN changed" flag, `"yes"` / `"no"` /
    /// `"indeterminate"` (card declined the probe).
    pub pin1_changed: &'a str,
    /// Same shape as [`pin1_changed`](Self::pin1_changed) for
    /// PIN2.
    pub pin2_changed: &'a str,
}

impl CardActivatePreflightPinChangedProbed<'_> {
    /// Event-name identifier emitted on the log line.
    pub const EVENT_NAME: EventName = EventName::new("card.activate.preflight.pin_changed_probed");
    /// Severity per Rule E16: notice (informational probe result).
    pub const LEVEL: Severity = Severity::Notice;
    /// Persistence per Rule E18: ephemeral (background probe;
    /// not a forensic-grade act).
    pub const PERSISTENCE: Persistence = Persistence::Ephemeral;
    /// PIN1 changed flag.
    pub const F_PIN1_CHANGED: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("pin1_changed"), FieldPrivacy::Public);
    /// PIN2 changed flag.
    pub const F_PIN2_CHANGED: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("pin2_changed"), FieldPrivacy::Public);

    /// Emit this event to the configured global log sink.
    pub fn emit(&self) {
        refineid_lib_core::events::emit(self);
    }
}

impl EventRecord for CardActivatePreflightPinChangedProbed<'_> {
    fn event_name(&self) -> EventName {
        Self::EVENT_NAME
    }

    fn level(&self) -> Severity {
        Self::LEVEL
    }

    fn persistence(&self) -> Persistence {
        Self::PERSISTENCE
    }

    fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display)) {
        f(Self::F_PIN1_CHANGED, &self.pin1_changed);
        f(Self::F_PIN2_CHANGED, &self.pin2_changed);
    }
}

// ===========================================================
// card.activate.scheme.selected
// ===========================================================

/// `card.activate.scheme.selected` -- emitted after the
/// preflight gate clears and refineid has chosen the card's
/// activation scheme and its APDU. See `doc/observability.md` for
/// the naming convention.
///
/// Useful for log triage when activation fails: tells the
/// operator which spec section refineid believed applied
/// (S4-1 v4.2 §4.6.1 RESET RETRY COUNTER vs §4.6.2 CHANGE
/// REFERENCE DATA) and therefore what an unexpected SW would
/// have been a deviation from.
#[derive(Debug)]
pub struct CardActivateSchemeSelected<'a> {
    /// `"preset_activation_pin"` (S4-1 v4.2 §4.6.2 CHANGE
    /// REFERENCE DATA) or `"activation_code_is_puk"` (§4.6.1
    /// RESET RETRY COUNTER).
    pub scheme: &'a str,
    /// ISO 7816-4 instruction byte the per-slot setup APDU will
    /// carry, lowercase hex (`"24"` / `"2c"`).
    pub apdu_ins: &'a str,
    /// FINEID S4-1 section the scheme is documented under (`"4.6.2"`
    /// / `"4.6.1"`).
    pub fineid_s4_1_section: &'a str,
}

impl CardActivateSchemeSelected<'_> {
    /// Event-name identifier emitted on the log line.
    pub const EVENT_NAME: EventName = EventName::new("card.activate.scheme.selected");
    /// Severity per Rule E16: notice (per-spec branch decision).
    pub const LEVEL: Severity = Severity::Notice;
    /// Persistence per Rule E18: ephemeral.
    pub const PERSISTENCE: Persistence = Persistence::Ephemeral;
    /// Selected scheme (`"preset_activation_pin"` /
    /// `"activation_code_is_puk"`).
    pub const F_SCHEME: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("scheme"), FieldPrivacy::Public);
    /// APDU instruction byte (hex).
    pub const F_APDU_INS: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("apdu_ins"), FieldPrivacy::Public);
    /// FINEID spec section.
    pub const F_FINEID_S4_1_SECTION: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("fineid_s4_1_section"), FieldPrivacy::Public);

    /// Emit this event to the configured global log sink.
    pub fn emit(&self) {
        refineid_lib_core::events::emit(self);
    }
}

impl EventRecord for CardActivateSchemeSelected<'_> {
    fn event_name(&self) -> EventName {
        Self::EVENT_NAME
    }

    fn level(&self) -> Severity {
        Self::LEVEL
    }

    fn persistence(&self) -> Persistence {
        Self::PERSISTENCE
    }

    fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display)) {
        f(Self::F_SCHEME, &self.scheme);
        f(Self::F_APDU_INS, &self.apdu_ins);
        f(Self::F_FINEID_S4_1_SECTION, &self.fineid_s4_1_section);
    }
}

// ===========================================================
// card.activate.pin1.set
// ===========================================================

/// `card.activate.pin1.set` -- emitted after the PIN1 setup APDU
/// completes (or after refineid converts the wire outcome into
/// the unified `UnblockOutcome` form for either scheme).
///
/// PIN values are deliberately absent from this forensic event.
#[derive(Debug)]
pub struct CardActivatePin1Set<'a> {
    /// Reader the modify APDU landed against.
    pub reader: &'a str,
    /// Outcome enum rendered via [`UnblockOutcome`]'s `Debug`
    /// (`"Ok"`, `"WrongPuk { retries_left: 4 }"`, `"PukLocked"`,
    /// `"Invalidated"`, `"LengthError"`, `"Other(0xNNNN)"`).
    ///
    /// [`UnblockOutcome`]: refineid_lib_core::auth::UnblockOutcome
    pub outcome: &'a str,
}

impl CardActivatePin1Set<'_> {
    /// Event-name identifier emitted on the log line.
    pub const EVENT_NAME: EventName = EventName::new("card.activate.pin1.set");
    /// Severity per Rule E16: notice (successful security-relevant
    /// state change).
    pub const LEVEL: Severity = Severity::Notice;
    /// Persistence per Rule E18: forensic (the citizen may need
    /// durable proof of when their PIN was changed; the audit-
    /// chain sink consumes this when wired).
    pub const PERSISTENCE: Persistence = Persistence::Forensic;
    /// Reader name.
    pub const F_READER: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("reader"), FieldPrivacy::Public);
    /// Outcome rendering.
    pub const F_OUTCOME: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("outcome"), FieldPrivacy::Public);

    /// Emit this event to the configured global log sink.
    pub fn emit(&self) {
        refineid_lib_core::events::emit(self);
    }
}

impl EventRecord for CardActivatePin1Set<'_> {
    fn event_name(&self) -> EventName {
        Self::EVENT_NAME
    }

    fn level(&self) -> Severity {
        Self::LEVEL
    }

    fn persistence(&self) -> Persistence {
        Self::PERSISTENCE
    }

    fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display)) {
        f(Self::F_READER, &self.reader);
        f(Self::F_OUTCOME, &self.outcome);
    }
}

// ===========================================================
// card.activate.pin2.set
// ===========================================================

/// `card.activate.pin2.set` -- emitted after the PIN2 setup APDU
/// completes. PIN values are deliberately absent.
#[derive(Debug)]
pub struct CardActivatePin2Set<'a> {
    /// Reader the modify APDU landed against.
    pub reader: &'a str,
    /// Outcome enum rendered via `Debug`. See
    /// [`CardActivatePin1Set::outcome`].
    pub outcome: &'a str,
}

impl CardActivatePin2Set<'_> {
    /// Event-name identifier emitted on the log line.
    pub const EVENT_NAME: EventName = EventName::new("card.activate.pin2.set");
    /// Severity per Rule E16: notice.
    pub const LEVEL: Severity = Severity::Notice;
    /// Persistence per Rule E18: forensic.
    pub const PERSISTENCE: Persistence = Persistence::Forensic;
    /// Reader name.
    pub const F_READER: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("reader"), FieldPrivacy::Public);
    /// Outcome rendering.
    pub const F_OUTCOME: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("outcome"), FieldPrivacy::Public);

    /// Emit this event to the configured global log sink.
    pub fn emit(&self) {
        refineid_lib_core::events::emit(self);
    }
}

impl EventRecord for CardActivatePin2Set<'_> {
    fn event_name(&self) -> EventName {
        Self::EVENT_NAME
    }

    fn level(&self) -> Severity {
        Self::LEVEL
    }

    fn persistence(&self) -> Persistence {
        Self::PERSISTENCE
    }

    fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display)) {
        f(Self::F_READER, &self.reader);
        f(Self::F_OUTCOME, &self.outcome);
    }
}

// ===========================================================
// card.activate.apdu.tx
// ===========================================================

/// `card.activate.apdu.tx` -- one command APDU sent during the
/// activate flow.
///
/// Captures only the public four-byte command header and total
/// command length. Data bytes are never emitted because modify
/// commands carry PIN or PUK material.
#[derive(Debug)]
pub struct CardActivateApduTx<'a> {
    /// Monotonic step counter within the current activate run,
    /// starting at `"1"`. Pairs each tx with the matching rx.
    pub step: &'a str,
    /// Public CLA-INS-P1-P2 header as lowercase hex.
    pub header_hex: &'a str,
    /// Total command length, including source-redacted data.
    pub command_len: usize,
}

impl CardActivateApduTx<'_> {
    /// Event-name identifier emitted on the log line.
    pub const EVENT_NAME: EventName = EventName::new("card.activate.apdu.tx");
    /// Severity per Rule E16: debug (wire metadata; verbose by
    /// design).
    pub const LEVEL: Severity = Severity::Debug;
    /// Persistence per Rule E18: ephemeral.
    pub const PERSISTENCE: Persistence = Persistence::Ephemeral;
    /// Step counter.
    pub const F_STEP: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("step"), FieldPrivacy::Public);
    /// Public APDU header.
    pub const F_HEADER_HEX: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("header_hex"), FieldPrivacy::Public);
    /// Total command length.
    pub const F_COMMAND_LEN: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("command_len"), FieldPrivacy::Public);

    /// Emit this event to the configured global log sink.
    pub fn emit(&self) {
        refineid_lib_core::events::emit(self);
    }
}

impl EventRecord for CardActivateApduTx<'_> {
    fn event_name(&self) -> EventName {
        Self::EVENT_NAME
    }

    fn level(&self) -> Severity {
        Self::LEVEL
    }

    fn persistence(&self) -> Persistence {
        Self::PERSISTENCE
    }

    fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display)) {
        f(Self::F_STEP, &self.step);
        f(Self::F_HEADER_HEX, &self.header_hex);
        f(Self::F_COMMAND_LEN, &self.command_len);
    }
}

// ===========================================================
// card.activate.apdu.rx
// ===========================================================

/// `card.activate.apdu.rx` -- emitted after every APDU response
/// during the activation flow. Records the response length and
/// SW1/SW2 status word; response bytes are never emitted.
#[derive(Debug)]
pub struct CardActivateApduRx<'a> {
    /// Monotonic step counter; matches the [`CardActivateApduTx`]
    /// step value.
    pub step: &'a str,
    /// Response body length, excluding SW1/SW2.
    pub response_len: usize,
    /// SW1+SW2 as 4-character uppercase hex, e.g. `"9000"` /
    /// `"63C4"`.
    pub sw: &'a str,
    /// Optional non-response transport outcome (`"NoCard"`,
    /// `"ReaderRemoved"`, etc.). `""` when the APDU returned a
    /// real response.
    pub transport_outcome: &'a str,
}

impl CardActivateApduRx<'_> {
    /// Event-name identifier emitted on the log line.
    pub const EVENT_NAME: EventName = EventName::new("card.activate.apdu.rx");
    /// Severity per Rule E16: debug.
    pub const LEVEL: Severity = Severity::Debug;
    /// Persistence per Rule E18: ephemeral.
    pub const PERSISTENCE: Persistence = Persistence::Ephemeral;
    /// Step counter.
    pub const F_STEP: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("step"), FieldPrivacy::Public);
    /// Response body length.
    pub const F_RESPONSE_LEN: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("response_len"), FieldPrivacy::Public);
    /// Status word.
    pub const F_SW: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("sw"), FieldPrivacy::Public);
    /// Transport outcome label.
    pub const F_TRANSPORT_OUTCOME: FieldDescriptor =
        FieldDescriptor::new(FieldName::new("transport_outcome"), FieldPrivacy::Public);

    /// Emit this event to the configured global log sink.
    pub fn emit(&self) {
        refineid_lib_core::events::emit(self);
    }
}

impl EventRecord for CardActivateApduRx<'_> {
    fn event_name(&self) -> EventName {
        Self::EVENT_NAME
    }

    fn level(&self) -> Severity {
        Self::LEVEL
    }

    fn persistence(&self) -> Persistence {
        Self::PERSISTENCE
    }

    fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display)) {
        f(Self::F_STEP, &self.step);
        f(Self::F_RESPONSE_LEN, &self.response_len);
        f(Self::F_SW, &self.sw);
        f(Self::F_TRANSPORT_OUTCOME, &self.transport_outcome);
    }
}
