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

//! What the one window shows, derived from a [`UiState`], so that every
//! driver lays out the same states with the same words.
//!
//! The texts are the Apple app's English source strings for the same
//! states (`Sources/App/Localizable.xcstrings` in refineid-apple).

use std::ops::RangeInclusive;

use refineid_client::card_pin::PinManageSlot;
use refineid_lib_core::auth::{
    PinSlot, PinStatus, PukStatus, check_puk_retry_floor, check_retry_floor,
};
use refineid_lib_core::pin::{ActivationPinEight, ActivationPinSeven, PinBytes, Puk};

use crate::model::{CanRequest, CardSource, ReaderPresence, UiState};

/// How many digits `slot`'s PIN may have.
#[must_use]
pub fn pin_digits(slot: PinSlot) -> RangeInclusive<usize> {
    slot.min_length()..=PinBytes::MAX_LENGTH
}

/// How many digits the PUK may have.
#[must_use]
pub fn puk_digits() -> RangeInclusive<usize> {
    Puk::MIN_LENGTH..=Puk::MAX_LENGTH
}

/// How many digits an activation PIN may have: seven on the newer
/// card, eight on the older.
#[must_use]
pub fn activation_digits() -> RangeInclusive<usize> {
    ActivationPinSeven::LENGTH..=ActivationPinEight::LENGTH
}

/// Whether `entry` is digits only, as many as `digits` allows.
fn fits(entry: &str, digits: &RangeInclusive<usize>) -> bool {
    digits.contains(&entry.len()) && entry.bytes().all(|byte| byte.is_ascii_digit())
}

/// Keeps the digits of `typed`, at most `max` of them.
#[must_use]
pub fn digits_only(typed: &str, max: usize) -> String {
    typed
        .chars()
        .filter(char::is_ascii_digit)
        .take(max)
        .collect()
}

/// Whether the signing controls can sign: documents wait, nothing runs,
/// the card in use can sign, and PIN 2 is typed when it is asked here.
#[must_use]
pub fn can_sign(state: &UiState, pin2: &str) -> bool {
    !state.pdf_documents.is_empty()
        && !state.busy
        && state.selected_card.is_some()
        && state.signature_supported
        && (!asks_pin2_here(state) || fits(pin2, &pin_digits(PinSlot::Pin2)))
}

/// Whether the activation form is filled in: an activation PIN, and each
/// new PIN typed twice alike.
#[must_use]
pub fn activation_complete(code: &str, pin1: [&str; 2], pin2: [&str; 2]) -> bool {
    fits(code, &activation_digits())
        && fits(pin1[0], &pin_digits(PinSlot::Pin1))
        && pin1[0] == pin1[1]
        && fits(pin2[0], &pin_digits(PinSlot::Pin2))
        && pin2[0] == pin2[1]
}

/// "Connect a card reader."
pub const CONNECT_READER: &str = "Connect a card reader.";
/// "Insert the card into the reader."
pub const INSERT_CARD: &str = "Insert the card into the reader.";
/// "Reading information…"
pub const READING: &str = "Reading information\u{2026}";
/// The line for a card in a reader here that could not be read, drawn
/// in orange.
pub const CARD_NOT_READY: &str = "Remove the card from the reader for a moment.";
/// "Connecting to the phone…"
pub const CONNECTING_TO_PHONE: &str = "Connecting to the phone\u{2026}";
/// "Insert the card into the phone's card reader."
pub const INSERT_INTO_PHONE_READER: &str = "Insert the card into the phone's card reader.";
/// The suffix of a holder served by the paired phone.
pub const VIA_PHONE: &str = "(via phone)";
/// The pairing prompt above the code boxes.
pub const PAIRING_PROMPT: &str =
    "Open RefineID remote access on your phone and enter the pairing code:";
/// The accessible name of the pairing code boxes.
pub const PAIRING_CODE: &str = "Pairing code";
/// The accessible name of the progress shown while a code is tried.
pub const CONNECTING_TO_PHONE_PROGRESS: &str = "Connecting to the phone";
/// The accessible name of the card access number boxes.
pub const CARD_ACCESS_NUMBER: &str = "Card Access Number (CAN)";
/// The caption beside the card access number boxes.
pub const CAN_CAPTION: &str = "CAN";
/// The remote-use switch's name and tooltip.
pub const REMOTE_ACCESS: &str = "Remote Access";
/// The remote-use switch's value while off.
pub const REMOTE_OFF: &str = "Off";
/// The remote-use switch's value while on.
pub const REMOTE_ON: &str = "On";
/// The name of the PIN codes window and of the button that opens it.
pub const PIN_CODES: &str = "PIN Codes";
/// The PIN codes button's value while a code is below the retry floor.
pub const PIN_NEEDS_RESET: &str = "A PIN code needs a reset";
/// The empty drop area's invitation.
pub const DROP_INVITATION: &str = "Drop documents here to sign them";
/// The drop area's accessible name.
pub const DOCUMENTS_TO_SIGN: &str = "Documents to sign";
/// The file dialog button of the empty drop area.
pub const CHOOSE: &str = "Choose\u{2026}";
/// The file dialog button beside a pile.
pub const ADD: &str = "Add\u{2026}";
/// Empties the pile.
pub const CLEAR: &str = "Clear";
/// The signing method choice.
pub const SIGNING_METHOD: &str = "Signing method";
/// Each PDF signed in itself.
pub const SEPARATELY: &str = "Separately (PDF)";
/// One container over every document.
pub const AS_A_PACKAGE: &str = "As a package";
/// The PIN 2 field of the signing controls.
pub const PIN_2: &str = "PIN 2";
/// Signs the pile.
pub const SIGN: &str = "Sign\u{2026}";
/// The accessible name of the progress shown while signing.
pub const SIGNING_DOCUMENT: &str = "Signing document\u{2026}";
/// The activation form's heading.
pub const CARD_ACTIVATION: &str = "Card activation";
/// The activation form's first field.
pub const ACTIVATION_PIN: &str = "Activation PIN";
/// The activation form's new PIN 1.
pub const NEW_PIN_1: &str = "New PIN 1";
/// The activation form's repeated PIN 1.
pub const NEW_PIN_1_AGAIN: &str = "New PIN 1 again";
/// The activation form's new PIN 2.
pub const NEW_PIN_2: &str = "New PIN 2";
/// The activation form's repeated PIN 2.
pub const NEW_PIN_2_AGAIN: &str = "New PIN 2 again";
/// Activates the card.
pub const ACTIVATE_CARD: &str = "Activate Card";
/// The label before the attempts row of the PIN codes window.
pub const ATTEMPTS_LEFT: &str = "Attempts left:";
/// The PUK field.
pub const PUK: &str = "PUK";

/// The accessible name of the button that takes `document` out of the
/// pile.
#[must_use]
pub fn remove_document(name: &str) -> String {
    format!("Remove {name}")
}

/// The outcome line of a document that was signed.
#[must_use]
pub fn document_signed(name: &str) -> String {
    format!("{name} signed")
}

/// The line after the paired phone said it forgot this computer.
#[must_use]
pub fn phone_forgot(phone: &str) -> String {
    format!("{phone} forgot this computer")
}

/// The line at the top of the window (the Apple app's `IdentityLine`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityLine {
    /// Remote use off and no reader attached.
    ConnectReader,
    /// Remote use off and the readers empty.
    InsertCard,
    /// A card in a reader here whose holder is not read yet.
    Reading,
    /// The holder of the card in a reader here.
    LocalHolder(String),
    /// A card in a reader here that stayed unread after the inspection
    /// settled.
    CardNotReady,
    /// Remote use on, no card here and no phone paired: the line is the
    /// pairing prompt.
    PairPhone,
    /// The phone, by name, said it forgot this computer.
    PhoneForgot(String),
    /// A paired phone that offers no holder yet.
    ConnectingToPhone,
    /// The holder of the card the paired phone serves.
    PhoneHolder(String),
    /// The paired phone reports no card in its card reader.
    PhoneReaderEmpty,
}

impl IdentityLine {
    /// The line for `state`. A card here overrides the paired phone;
    /// with remote use off the line speaks of the readers here alone;
    /// otherwise the paired phone's line stands, and with no phone paired
    /// the line asks for a pairing code.
    #[must_use]
    pub fn derive(state: &UiState) -> Self {
        let selected = state.selected_card.and_then(|index| state.cards.get(index));
        if state.reader == ReaderPresence::Card || state.has_local_card {
            return match selected {
                Some(card) if card.source == CardSource::Local => {
                    Self::LocalHolder(card.display_name())
                }
                _ if state.card_unread => Self::CardNotReady,
                _ => Self::Reading,
            };
        }
        if !state.remote_use {
            return if state.reader == ReaderPresence::NoReader {
                Self::ConnectReader
            } else {
                Self::InsertCard
            };
        }
        if state.phone.is_none() {
            return state
                .phone_that_forgot
                .clone()
                .map_or(Self::PairPhone, Self::PhoneForgot);
        }
        if state.phone_reader_empty {
            return Self::PhoneReaderEmpty;
        }
        match selected {
            Some(card) if card.source == CardSource::Phone => {
                Self::PhoneHolder(card.display_name())
            }
            _ => Self::ConnectingToPhone,
        }
    }

    /// The words of the line; empty for the pairing prompt, which has
    /// its own text.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::ConnectReader => CONNECT_READER.to_owned(),
            Self::InsertCard => INSERT_CARD.to_owned(),
            Self::Reading => READING.to_owned(),
            Self::CardNotReady => CARD_NOT_READY.to_owned(),
            Self::LocalHolder(name) => name.clone(),
            Self::PairPhone => String::new(),
            Self::PhoneForgot(phone) => phone_forgot(phone),
            Self::ConnectingToPhone => CONNECTING_TO_PHONE.to_owned(),
            Self::PhoneHolder(name) => format!("{name} {VIA_PHONE}"),
            Self::PhoneReaderEmpty => INSERT_INTO_PHONE_READER.to_owned(),
        }
    }

    /// Whether the line is a warning, drawn in orange.
    #[must_use]
    pub fn is_warning(&self) -> bool {
        matches!(self, Self::CardNotReady)
    }

    /// Whether the line is the holder's name, drawn in the primary text
    /// colour; every other line is secondary.
    #[must_use]
    pub fn is_holder(&self) -> bool {
        matches!(self, Self::LocalHolder(_) | Self::PhoneHolder(_))
    }
}

/// What fills the window below the identity line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowContent {
    /// The six-box card access number entry, in place of the line too.
    CardAccessNumber(CanRequest),
    /// The activation form, in place of the line too.
    Activation,
    /// The pairing prompt and its code boxes.
    PairingPrompt,
    /// The drop area and the signing controls.
    Documents,
    /// Nothing but the line.
    LineOnly,
}

impl WindowContent {
    /// The content for `state`, the first that holds: a contactless card
    /// asking for its number, a card waiting to be taken into use, the
    /// pairing prompt while remote use is on with no phone paired and
    /// nothing else to show, the documents while an identity is
    /// available or documents wait.
    #[must_use]
    pub fn derive(state: &UiState) -> Self {
        if let Some(request) = state.can_request {
            return Self::CardAccessNumber(request);
        }
        if state.activation_available {
            return Self::Activation;
        }
        let line = IdentityLine::derive(state);
        let pile = !state.pdf_documents.is_empty();
        if matches!(line, IdentityLine::PairPhone | IdentityLine::PhoneForgot(_)) && !pile {
            return Self::PairingPrompt;
        }
        if line.is_holder() || pile {
            Self::Documents
        } else {
            Self::LineOnly
        }
    }
}

/// Whether the toolbar button opens the PIN codes window rather than
/// switching remote use: a card is in a reader here.
#[must_use]
pub fn toolbar_opens_pin_codes(state: &UiState) -> bool {
    state.reader == ReaderPresence::Card || state.has_local_card
}

/// Whether the signing controls ask for PIN 2 here: the card is in a
/// reader here. A paired phone's card takes PIN 2 on the phone.
#[must_use]
pub fn asks_pin2_here(state: &UiState) -> bool {
    state.selected_card_is_local
}

/// The tries a counter reports: its count, or none when blocked.
fn pin_tries(status: Option<PinStatus>) -> Option<u8> {
    match status? {
        PinStatus::Remaining(retries) => Some(retries.get()),
        PinStatus::Locked => Some(0),
        PinStatus::Verified | PinStatus::NoInfo | PinStatus::Other(_) => None,
    }
}

/// The tries the PUK's counter reports, by the same rule.
fn puk_tries(status: Option<PukStatus>) -> Option<u8> {
    match status? {
        PukStatus::Remaining(retries) => Some(retries.get()),
        PukStatus::Locked => Some(0),
        PukStatus::Invalidated | PukStatus::NoInfo | PukStatus::Other(_) => None,
    }
}

/// Whether a PIN's counter is below the retry floor.
fn pin_below_floor(slot: PinSlot, status: Option<PinStatus>) -> bool {
    pin_tries(status).is_some() && status.is_some_and(|s| check_retry_floor(slot, s).is_err())
}

/// Whether the PUK's counter is below the retry floor.
fn puk_below_floor(status: Option<PukStatus>) -> bool {
    puk_tries(status).is_some() && status.is_some_and(|s| check_puk_retry_floor(s).is_err())
}

/// What a card below the retry floor needs (the Apple app's
/// `CredentialRetryHealth.Recovery`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// PIN 1 is below the floor: reset it with the PUK.
    ResetPin1,
    /// PIN 2 is below the floor: reset it with the PUK.
    ResetPin2,
    /// The PUK is below the floor: other software recovers the card.
    UseOtherSoftware,
    /// The PUK is blocked.
    Unrecoverable,
}

impl Recovery {
    /// What the card in a reader here needs, when one of its counters is
    /// below the floor.
    #[must_use]
    pub fn derive(state: &UiState) -> Option<Self> {
        if !state.selected_card_is_local {
            return None;
        }
        // A counter that reports no tries (verified, or not reported) is
        // no concern for that credential.
        if puk_tries(state.puk_status) == Some(0) {
            Some(Self::Unrecoverable)
        } else if puk_below_floor(state.puk_status) {
            Some(Self::UseOtherSoftware)
        } else if pin_below_floor(PinSlot::Pin1, state.pin1_status) {
            Some(Self::ResetPin1)
        } else if pin_below_floor(PinSlot::Pin2, state.pin2_status) {
            Some(Self::ResetPin2)
        } else {
            None
        }
    }

    /// The two sentences the PIN codes window opens with.
    #[must_use]
    pub fn sentences(self) -> [&'static str; 2] {
        match self {
            Self::ResetPin1 => [
                "RefineID does not use PIN 1 with fewer than 3 attempts left.",
                "Reset PIN 1 with the PUK, or use other software.",
            ],
            Self::ResetPin2 => [
                "RefineID does not use PIN 2 with fewer than 3 attempts left.",
                "Reset PIN 2 with the PUK, or use other software.",
            ],
            Self::UseOtherSoftware => [
                "Use other software to recover the card",
                "RefineID will not use either of the final two PUK attempts.",
            ],
            Self::Unrecoverable => [
                "The PUK is blocked",
                "This card cannot be recovered with software.",
            ],
        }
    }

    /// The tasks the window offers: the resets while a PIN needs one,
    /// none while only other software can help.
    #[must_use]
    pub fn tasks(recovery: Option<Self>) -> &'static [PinTask] {
        match recovery {
            Some(Self::ResetPin1 | Self::ResetPin2) => &[PinTask::ResetPin1, PinTask::ResetPin2],
            Some(Self::UseOtherSoftware | Self::Unrecoverable) => &[],
            None => &PinTask::ALL,
        }
    }

    /// The task the window opens on.
    #[must_use]
    pub fn initial_task(recovery: Option<Self>) -> PinTask {
        match recovery {
            Some(Self::ResetPin2) => PinTask::ResetPin2,
            Some(Self::ResetPin1) => PinTask::ResetPin1,
            Some(Self::UseOtherSoftware | Self::Unrecoverable) | None => PinTask::ChangePin1,
        }
    }
}

/// One task of the PIN codes window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinTask {
    /// Change PIN 1 with the current PIN 1.
    ChangePin1,
    /// Change PIN 2 with the current PIN 2.
    ChangePin2,
    /// Set a new PIN 1 with the PUK.
    ResetPin1,
    /// Set a new PIN 2 with the PUK.
    ResetPin2,
}

impl PinTask {
    /// Every task, in the order the window lists them.
    pub const ALL: [Self; 4] = [
        Self::ChangePin1,
        Self::ChangePin2,
        Self::ResetPin1,
        Self::ResetPin2,
    ];

    /// The task's name in the task selector.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::ChangePin1 => "Change PIN 1",
            Self::ChangePin2 => "Change PIN 2",
            Self::ResetPin1 => "Reset PIN 1",
            Self::ResetPin2 => "Reset PIN 2",
        }
    }

    /// The PIN the task sets.
    #[must_use]
    pub fn slot(self) -> PinSlot {
        match self {
            Self::ChangePin1 | Self::ResetPin1 => PinSlot::Pin1,
            Self::ChangePin2 | Self::ResetPin2 => PinSlot::Pin2,
        }
    }

    /// Whether the task presents the PUK rather than the current PIN.
    #[must_use]
    pub fn uses_puk(self) -> bool {
        matches!(self, Self::ResetPin1 | Self::ResetPin2)
    }

    /// The three field names: the code presented, the new code, the new
    /// code again.
    #[must_use]
    pub fn fields(self) -> [&'static str; 3] {
        match self {
            Self::ChangePin1 => ["Current basic code", "New basic code", "Basic code again"],
            Self::ChangePin2 => [
                "Current signature code",
                "New signature code",
                "Signature code again",
            ],
            Self::ResetPin1 => [PUK, "New basic code", "Basic code again"],
            Self::ResetPin2 => [PUK, "New signature code", "Signature code again"],
        }
    }

    /// The slot the controller's intent names.
    #[must_use]
    pub fn manage_slot(self) -> PinManageSlot {
        match self.slot() {
            PinSlot::Pin1 => PinManageSlot::Pin1,
            PinSlot::Pin2 => PinManageSlot::Pin2,
        }
    }

    /// Whether the three entries are filled in: the code presented, and
    /// the new PIN typed twice alike and differing from the current one.
    #[must_use]
    pub fn complete(self, entries: [&str; 3]) -> bool {
        let [presented, new, again] = entries;
        let presented_fits = if self.uses_puk() {
            fits(presented, &puk_digits())
        } else {
            fits(presented, &pin_digits(self.slot())) && presented != new
        };
        presented_fits && fits(new, &pin_digits(self.slot())) && new == again
    }

    /// Whether the card in a reader here lets the task run: the counter
    /// the task spends is at or above the retry floor.
    #[must_use]
    pub fn available(self, state: &UiState) -> bool {
        if state.busy || !state.selected_card_is_local {
            return false;
        }
        match self {
            Self::ChangePin1 => state.pin1_change_available,
            Self::ChangePin2 => state.pin2_change_available,
            Self::ResetPin1 | Self::ResetPin2 => state
                .puk_status
                .is_some_and(|status| check_puk_retry_floor(status).is_ok()),
        }
    }

    /// The button that runs the task.
    #[must_use]
    pub fn action(self) -> &'static str {
        match self {
            Self::ChangePin1 => "Change Basic PIN 1",
            Self::ChangePin2 => "Change Signature PIN 2",
            Self::ResetPin1 => "Reset Basic PIN 1",
            Self::ResetPin2 => "Reset Signature PIN 2",
        }
    }
}

/// One entry of the attempts row: a counter below full.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptsEntry {
    /// "PIN 1", "PIN 2" or "PUK", then the count or the state.
    pub text: String,
    /// Whether the counter is below the retry floor or blocked: drawn in
    /// red beside a mark.
    pub below_floor: bool,
}

/// The counters of the card in a reader here that are below full; the
/// row is not shown while this is empty.
#[must_use]
pub fn attempts_below_full(state: &UiState) -> Vec<AttemptsEntry> {
    let limit = refineid_lib_core::auth::PIN_TRY_LIMIT;
    let pin = |name: &str, slot: PinSlot, status: Option<PinStatus>| {
        let value = match status? {
            PinStatus::Verified => return None,
            PinStatus::Remaining(retries) if retries.get() >= limit => return None,
            PinStatus::Remaining(retries) if retries.is_exhausted() => "blocked".to_owned(),
            PinStatus::Remaining(retries) => format!("{}/{limit}", retries.get()),
            PinStatus::Locked => "blocked".to_owned(),
            PinStatus::NoInfo | PinStatus::Other(_) => "unknown".to_owned(),
        };
        Some(AttemptsEntry {
            text: format!("{name} {value}"),
            below_floor: pin_below_floor(slot, status),
        })
    };
    let puk = |status: Option<PukStatus>| {
        let value = match status? {
            PukStatus::Remaining(retries) if retries.get() >= limit => return None,
            PukStatus::Remaining(retries) if retries.is_exhausted() => "blocked".to_owned(),
            PukStatus::Remaining(retries) => format!("{}/{limit}", retries.get()),
            PukStatus::Locked => "blocked".to_owned(),
            PukStatus::Invalidated => "invalidated".to_owned(),
            PukStatus::NoInfo | PukStatus::Other(_) => "unknown".to_owned(),
        };
        Some(AttemptsEntry {
            text: format!("{PUK} {value}"),
            below_floor: puk_below_floor(status) || matches!(status, Some(PukStatus::Invalidated)),
        })
    };
    if !state.selected_card_is_local {
        return Vec::new();
    }
    [
        pin("PIN 1", PinSlot::Pin1, state.pin1_status),
        pin("PIN 2", PinSlot::Pin2, state.pin2_status),
        puk(state.puk_status),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use refineid_client::card_check::CardCheckReport;
    use refineid_lib_core::apdu::status_word::PinRetries;
    use refineid_lib_core::identity::{CredentialIdentity, Surname};
    use refineid_rapp_core::ids::PairId;

    use crate::model::{ManagedCard, PairedPhone};

    const HOLDER: &str = "Tormanen";

    fn retries(count: u8) -> PinRetries {
        PinRetries::from_nibble(count).expect("retry nibble")
    }

    fn card(source: CardSource) -> ManagedCard {
        let identity = CredentialIdentity::new()
            .with_surname(Surname::new(HOLDER.to_owned()).expect("surname"));
        ManagedCard {
            source,
            report: CardCheckReport {
                reader: "Synthetic Card Reader".to_owned(),
                identity,
                atr_hex: "3b00".to_owned(),
                token_info: refineid_lib_core::pkcs15::TokenInfo::default(),
                card_access: refineid_lib_core::card_access::CardAccess::default(),
                certs: Vec::new(),
                pin_reference_scheme: refineid_lib_core::auth::PinReferenceScheme::Citizen,
                pin1: None,
                pin2: None,
                puk: None,
                pin1_policy: None,
                pin2_policy: None,
                puk_policy: None,
                pin1_changed: None,
                pin2_changed: None,
                emrtd: None,
                emrtd_error: None,
            },
            activation_context: None,
        }
    }

    fn phone() -> PairedPhone {
        PairedPhone {
            pair_id: PairId::from_array(*b"synthetic-pair-1"),
            name: "custodian-1".to_owned(),
            platform: "Android".to_owned(),
            certificate_cached: true,
            signs_documents: true,
        }
    }

    fn local_card_state() -> UiState {
        UiState {
            reader: ReaderPresence::Card,
            has_local_card: true,
            selected_card_is_local: true,
            cards: vec![card(CardSource::Local)],
            selected_card: Some(0),
            ..UiState::default()
        }
    }

    #[test]
    fn with_remote_use_off_the_line_speaks_of_the_readers_here() {
        let mut state = UiState::default();
        assert_eq!(IdentityLine::derive(&state).text(), CONNECT_READER);
        assert_eq!(WindowContent::derive(&state), WindowContent::LineOnly);
        state.reader = ReaderPresence::Empty;
        assert_eq!(IdentityLine::derive(&state).text(), INSERT_CARD);
        state.reader = ReaderPresence::Card;
        assert_eq!(IdentityLine::derive(&state), IdentityLine::Reading);
        state.card_unread = true;
        assert_eq!(IdentityLine::derive(&state).text(), CARD_NOT_READY);
        assert!(IdentityLine::derive(&state).is_warning());
        assert!(toolbar_opens_pin_codes(&state));
    }

    #[test]
    fn a_card_here_names_its_holder_and_overrides_the_phone() {
        let mut state = local_card_state();
        state.remote_use = true;
        state.phone = Some(phone());
        assert_eq!(IdentityLine::derive(&state).text(), HOLDER);
        assert_eq!(WindowContent::derive(&state), WindowContent::Documents);
        assert!(asks_pin2_here(&state));
    }

    #[test]
    fn the_paired_phone_line_follows_the_apple_precedence() {
        let mut state = UiState {
            remote_use: true,
            reader: ReaderPresence::Empty,
            ..UiState::default()
        };
        assert_eq!(IdentityLine::derive(&state), IdentityLine::PairPhone);
        assert_eq!(WindowContent::derive(&state), WindowContent::PairingPrompt);
        state.phone_that_forgot = Some("custodian-1".to_owned());
        assert_eq!(
            IdentityLine::derive(&state).text(),
            "custodian-1 forgot this computer"
        );
        assert_eq!(WindowContent::derive(&state), WindowContent::PairingPrompt);

        state.phone = Some(phone());
        state.phone_that_forgot = None;
        assert_eq!(IdentityLine::derive(&state).text(), CONNECTING_TO_PHONE);
        assert_eq!(WindowContent::derive(&state), WindowContent::LineOnly);

        state.cards = vec![card(CardSource::Phone)];
        state.selected_card = Some(0);
        // A pairing without the signing grant asks for no PIN 2 here either.
        assert!(!asks_pin2_here(&state));
        state.pdf_documents = vec!["/documents/report.pdf".into()];
        assert!(!can_sign(&state, ""));
        state.pdf_documents.clear();
        state.signature_supported = true;
        assert_eq!(IdentityLine::derive(&state).text(), "Tormanen (via phone)");
        assert_eq!(WindowContent::derive(&state), WindowContent::Documents);
        assert!(!asks_pin2_here(&state));
        state.pdf_documents = vec!["/documents/report.pdf".into()];
        assert!(can_sign(&state, ""));
        state.pdf_documents.clear();
        assert!(!toolbar_opens_pin_codes(&state));

        state.phone_reader_empty = true;
        assert_eq!(
            IdentityLine::derive(&state).text(),
            INSERT_INTO_PHONE_READER
        );
    }

    #[test]
    fn waiting_documents_keep_the_drop_area_over_the_prompt() {
        let state = UiState {
            remote_use: true,
            pdf_documents: vec!["/documents/report.pdf".into()],
            ..UiState::default()
        };
        assert_eq!(WindowContent::derive(&state), WindowContent::Documents);
    }

    #[test]
    fn the_access_number_and_the_activation_replace_the_content() {
        let mut state = local_card_state();
        state.activation_available = true;
        assert_eq!(WindowContent::derive(&state), WindowContent::Activation);
        state.can_request = Some(CanRequest::Needed);
        assert_eq!(
            WindowContent::derive(&state),
            WindowContent::CardAccessNumber(CanRequest::Needed)
        );
    }

    #[test]
    fn the_attempts_row_lists_only_counters_below_full() {
        let mut state = local_card_state();
        state.pin1_status = Some(PinStatus::Remaining(retries(5)));
        state.pin2_status = Some(PinStatus::Verified);
        state.puk_status = Some(PukStatus::Remaining(retries(5)));
        assert!(attempts_below_full(&state).is_empty());
        assert_eq!(Recovery::derive(&state), None);
        assert_eq!(Recovery::tasks(None), &PinTask::ALL);

        state.pin2_status = Some(PinStatus::Remaining(retries(4)));
        assert_eq!(
            attempts_below_full(&state),
            vec![AttemptsEntry {
                text: "PIN 2 4/5".to_owned(),
                below_floor: false
            }]
        );
        assert_eq!(Recovery::derive(&state), None);
    }

    #[test]
    fn a_verified_counter_hides_no_other_counter_below_the_floor() {
        let mut state = local_card_state();
        state.pin1_status = Some(PinStatus::Verified);
        state.pin2_status = Some(PinStatus::Remaining(retries(2)));
        state.puk_status = Some(PukStatus::Remaining(retries(5)));
        assert_eq!(Recovery::derive(&state), Some(Recovery::ResetPin2));
        state.puk_status = Some(PukStatus::NoInfo);
        assert_eq!(Recovery::derive(&state), Some(Recovery::ResetPin2));
        state.pin2_status = Some(PinStatus::Remaining(retries(5)));
        assert_eq!(Recovery::derive(&state), None);
    }

    #[test]
    fn a_counter_below_the_floor_names_the_way_back() {
        let mut state = local_card_state();
        state.pin1_status = Some(PinStatus::Remaining(retries(2)));
        state.pin2_status = Some(PinStatus::Remaining(retries(5)));
        state.puk_status = Some(PukStatus::Remaining(retries(5)));
        let recovery = Recovery::derive(&state);
        assert_eq!(recovery, Some(Recovery::ResetPin1));
        assert_eq!(
            Recovery::ResetPin1.sentences(),
            [
                "RefineID does not use PIN 1 with fewer than 3 attempts left.",
                "Reset PIN 1 with the PUK, or use other software."
            ]
        );
        assert_eq!(
            Recovery::tasks(recovery),
            &[PinTask::ResetPin1, PinTask::ResetPin2]
        );
        assert_eq!(Recovery::initial_task(recovery), PinTask::ResetPin1);
        assert_eq!(
            attempts_below_full(&state),
            vec![AttemptsEntry {
                text: "PIN 1 2/5".to_owned(),
                below_floor: true
            }]
        );

        state.pin1_status = Some(PinStatus::Locked);
        assert_eq!(attempts_below_full(&state)[0].text, "PIN 1 blocked");
        state.puk_status = Some(PukStatus::Remaining(retries(2)));
        assert_eq!(Recovery::derive(&state), Some(Recovery::UseOtherSoftware));
        assert!(Recovery::tasks(Recovery::derive(&state)).is_empty());
        state.puk_status = Some(PukStatus::Locked);
        assert_eq!(Recovery::derive(&state), Some(Recovery::Unrecoverable));
    }

    #[test]
    fn a_task_is_complete_when_its_entries_fit() {
        assert!(PinTask::ChangePin1.complete(["2719", "3842", "3842"]));
        assert!(!PinTask::ChangePin1.complete(["2719", "3842", "3843"]));
        assert!(!PinTask::ChangePin1.complete(["2719", "2719", "2719"]));
        assert!(!PinTask::ChangePin2.complete(["271946", "3842", "3842"]));
        assert!(PinTask::ResetPin2.complete(["27194638", "384251", "384251"]));
        assert!(!PinTask::ResetPin2.complete(["2719", "384251", "384251"]));
        assert!(activation_complete(
            "2719463",
            ["3842", "3842"],
            ["384251", "384251"]
        ));
        assert!(!activation_complete(
            "27194",
            ["3842", "3842"],
            ["384251", "384251"]
        ));
        assert_eq!(digits_only("27a19 46", 4), "2719");
    }

    #[test]
    fn a_phone_card_has_no_pin_codes() {
        let mut state = UiState {
            cards: vec![card(CardSource::Phone)],
            selected_card: Some(0),
            pin1_status: Some(PinStatus::Remaining(retries(1))),
            ..UiState::default()
        };
        state.puk_status = Some(PukStatus::Remaining(retries(5)));
        state.pin2_status = Some(PinStatus::Remaining(retries(5)));
        assert_eq!(Recovery::derive(&state), None);
        assert!(attempts_below_full(&state).is_empty());
    }
}
