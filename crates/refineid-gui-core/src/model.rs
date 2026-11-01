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

//! Typed data models for GUI state and user intentions.

use std::path::PathBuf;

use refineid_client::card_check::CardCheckReport;
use refineid_client::card_pin::{ActivationCardContext, PinManageSlot};
use refineid_doc_sign::document::Format;
use refineid_lib_core::auth::{
    CardPinLengths, PinReadiness, PinReferenceScheme, PinSlot, PinStatus, PukStatus,
    check_retry_floor,
};
use refineid_lib_core::can::Can;
use refineid_lib_core::identity::TokenSerial;
use refineid_lib_core::pin::PinBytes;
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::profiles::ProfileName;
use refineid_rapp_core::remote::PairSummary;

/// Where a managed card is read: a reader attached to this computer, or
/// a paired phone over RAPP.
///
/// Only a local card is inspected by this program. A phone's card is
/// listed from the pairing record, its PINs are handled on the phone,
/// and no PIN action applies to it here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardSource {
    /// A card in a PC/SC reader attached to this computer.
    Local,
    /// A card served by a paired phone.
    Phone,
}

/// A managed smart card detected on the local host or via a remote RAPP pair.
#[derive(Clone, Debug)]
pub struct ManagedCard {
    /// Where the card is read.
    pub source: CardSource,
    /// Full inspection report.
    pub report: CardCheckReport,
    /// Factory activation context for cards that require initial activation.
    pub activation_context: Option<ActivationCardContext>,
}

/// The common name without the trailing identifier.
///
/// A citizen certificate's subject common name is the surname, the
/// given names and the identifier, in that order (FINEID S2 §6.3.6.1).
/// The name shown is the common name as the card carries it, less
/// that last token when it equals the identifier.
fn holder_name(common_name: &str, peuin: Option<&str>) -> String {
    let trimmed = common_name.trim_end();
    peuin
        .and_then(|id| trimmed.strip_suffix(id))
        .and_then(|rest| rest.strip_suffix(' '))
        .map_or(trimmed, str::trim_end)
        .to_owned()
}

impl ManagedCard {
    /// Person name string.
    pub fn person_name(&self) -> String {
        self.report.identity.person_string()
    }

    /// The cardholder line: the certificate subject's common name
    /// without the identifier it ends with, or the person string when
    /// the certificate was not read.
    pub fn display_name(&self) -> String {
        let identity = &self.report.identity;
        identity.common_name.as_ref().map_or_else(
            || self.person_name(),
            |cn| holder_name(cn.as_str(), identity.peuin.as_ref().map(AsRef::as_ref)),
        )
    }

    /// Whether a change with the current PIN passes the retry floor for
    /// `slot`: five, four or three tries left, or already verified.
    pub fn pin_change_available(&self, slot: PinSlot, status: Option<&PinStatus>) -> bool {
        status.is_some_and(|&status| check_retry_floor(slot, status).is_ok())
    }

    /// Each PIN's readiness ([`PinReadiness::judge`]), PIN 1 then
    /// PIN 2, under the card's activation scheme; without a scheme
    /// only the PIN changed flag decides.
    pub fn pin_readiness(&self) -> [PinReadiness; 2] {
        let scheme = self.activation_context.as_ref().map(|ctx| ctx.scheme);
        let report = &self.report;
        [
            PinReadiness::judge(scheme, report.pin1_changed, report.pin1),
            PinReadiness::judge(scheme, report.pin2_changed, report.pin2),
        ]
    }

    /// Whether factory activation is available: the activation sets
    /// both PINs, so both must await it.
    pub fn activation_available(&self) -> bool {
        self.activation_context.is_some()
            && self
                .pin_readiness()
                .iter()
                .all(|&readiness| readiness == PinReadiness::AwaitsActivation)
    }

    /// Whether the card answers the organization reference numbering
    /// (FINEID S4-2 v4.0 §4.2).
    pub fn is_organization_card(&self) -> bool {
        self.report.pin_reference_scheme == PinReferenceScheme::Organizational
    }

    /// Check if PIN unblocking is available for PIN1 and PIN2.
    pub fn recovery_availability(&self) -> (bool, bool) {
        if self.activation_available() {
            return (false, false);
        }
        let pin1_locked = matches!(self.report.pin1, Some(PinStatus::Locked));
        let pin2_locked = matches!(self.report.pin2, Some(PinStatus::Locked));
        (pin1_locked, pin2_locked)
    }
}

impl UiState {
    /// Whether the paired phone's card signs: the card in use is the
    /// phone's, which it is only while no reader here holds a card, and
    /// the pairing grants document signing. The
    /// signing then takes PIN 2 on the phone: a driver shows no PIN 2
    /// field and sends [`UserIntent::SignDocuments`] with `pin2: None`.
    #[must_use]
    pub fn phone_signs(&self) -> bool {
        self.selected_card.is_some() && !self.selected_card_is_local && self.signature_supported
    }
}

/// Supported signing output formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignFormat {
    /// PAdES signature embedded in each PDF.
    Pades,
    /// One ASiC-E container over every document.
    AsicE,
}

impl SignFormat {
    /// Whether `document` can carry its own signature: a PDF.
    #[must_use]
    pub fn is_pdf(document: &std::path::Path) -> bool {
        document
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case(PDF_EXTENSION))
    }

    /// The format every one of `documents` can take: each PDF signed in
    /// itself when all are PDFs, one container otherwise.
    #[must_use]
    pub fn shared(documents: &[PathBuf]) -> Self {
        if documents.iter().all(|document| Self::is_pdf(document)) {
            Self::Pades
        } else {
            Self::AsicE
        }
    }
}

/// The file extension of a PDF.
const PDF_EXTENSION: &str = "pdf";

impl From<SignFormat> for Format {
    fn from(f: SignFormat) -> Self {
        match f {
            SignFormat::Pades => Format::Pades,
            SignFormat::AsicE => Format::AsicEXades,
        }
    }
}

/// A pairing ceremony under way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RappPairingState {
    /// The typed pairing code, in two-character clusters ("7K X4 M9").
    pub code: String,
}

/// What the card readers attached to this computer report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReaderPresence {
    /// No reader is attached.
    #[default]
    NoReader,
    /// Readers are attached and none holds a card.
    Empty,
    /// A reader holds a card.
    Card,
}

impl ReaderPresence {
    /// The presence a PC/SC presence signature reports: each reader's
    /// name and whether it holds a card.
    #[must_use]
    pub fn from_signature(signature: &[(String, bool)]) -> Self {
        if signature.iter().any(|(_, present)| *present) {
            Self::Card
        } else if signature.is_empty() {
            Self::NoReader
        } else {
            Self::Empty
        }
    }
}

/// A contactless card whose application opens only with its card
/// access number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanRequest {
    /// No number has been tried for the card yet.
    Needed,
    /// The card refused the number last typed.
    Refused,
}

/// The paired phone, as its stored pairing describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairedPhone {
    /// The pair identifier.
    pub pair_id: PairId,
    /// The name the phone is listed under.
    pub name: String,
    /// The platform the phone introduced itself with.
    pub platform: String,
    /// Whether the phone's authentication certificate is cached.
    pub certificate_cached: bool,
    /// Whether the pairing grants document signing: the phone's card
    /// signs, and PIN 2 is typed on the phone.
    pub signs_documents: bool,
}

impl PairedPhone {
    /// The phone of a pairing that can open a session; `None` for a
    /// pairing that cannot.
    #[must_use]
    pub fn from_summary(summary: &PairSummary) -> Option<Self> {
        summary.usable().then(|| Self {
            pair_id: summary.pair_id,
            name: summary.peer_display_name.clone(),
            platform: summary.peer_platform.clone(),
            certificate_cached: summary.auth_cert.is_some(),
            signs_documents: summary
                .granted_profiles
                .contains(&ProfileName::DocumentSigning),
        })
    }
}

/// An immutable snapshot of the user interface state.
#[derive(Clone, Debug)]
pub struct UiState {
    /// Application window title.
    pub window_title: String,
    /// Top-level informational or error status message.
    pub status_message: String,
    /// True if an asynchronous card inspection, PIN operation, or sign job is running.
    pub busy: bool,
    /// List of detected smart cards.
    pub cards: Vec<ManagedCard>,
    /// Index of currently selected card.
    pub selected_card: Option<usize>,
    /// Serial number of selected card.
    pub card_serial: Option<TokenSerial>,
    /// Whether PIN1 has been changed from its factory value.
    pub pin1_changed: Option<bool>,
    /// Whether PIN2 has been changed from its factory value.
    pub pin2_changed: Option<bool>,

    /// Authentication PIN1 status.
    pub pin1_status: Option<PinStatus>,
    /// Qualified signature PIN2 status.
    pub pin2_status: Option<PinStatus>,
    /// Unblocking code PUK status.
    pub puk_status: Option<PukStatus>,
    /// Whether changing PIN1 is allowed.
    pub pin1_change_available: bool,
    /// Whether changing PIN2 is allowed.
    pub pin2_change_available: bool,
    /// Whether factory activation is available.
    pub activation_available: bool,
    /// Whether unblocking PIN1 is available.
    pub pin1_unblock_available: bool,
    /// Whether unblocking PIN2 is available.
    pub pin2_unblock_available: bool,
    /// Whether unblocking uses an activation code.
    pub unblock_uses_activation_code: bool,
    /// Whether the selected card is an organization card (FINEID S4-2
    /// v4.0 §4.2 reference numbering).
    pub organization_card: bool,
    /// Whether the card model supports digital signatures.
    pub signature_supported: bool,
    /// The PIN and PUK lengths the card in a reader here accepts where
    /// PINs are set, read in its activation session; `None` when they
    /// were not read, and the FINEID bounds apply.
    pub pin_lengths: Option<CardPinLengths>,

    /// Whether a card in a reader attached to this computer was read.
    /// A local card overrides the paired phone.
    pub has_local_card: bool,
    /// Whether the currently selected card is hosted on a local PC/SC reader.
    /// When false (a phone over RAPP), its PINs are handled on the phone.
    pub selected_card_is_local: bool,
    /// What the attached readers report, before any card is read.
    pub reader: ReaderPresence,
    /// A contactless card in a reader asks for its card access number.
    pub can_request: Option<CanRequest>,
    /// A reader holds a card that the inspection, repeated while the
    /// card settled, did not read.
    pub card_unread: bool,

    /// PDF documents queued for signature.
    pub pdf_documents: Vec<PathBuf>,
    /// Active signature format.
    pub sign_format: SignFormat,
    /// Outcome of the last signing operation.
    pub sign_result: Option<String>,

    /// Active RAPP phone pairing state.
    pub pairing: Option<RappPairingState>,
    /// The paired phone, while one is paired.
    pub phone: Option<PairedPhone>,
    /// Whether remote use is on: a phone is paired, or the user turned
    /// it on to pair one.
    pub remote_use: bool,
    /// The paired phone reports no card in the card reader attached to it.
    pub phone_reader_empty: bool,
    /// The name of the phone that said it forgot this computer, until a
    /// phone is paired again.
    pub phone_that_forgot: Option<String>,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            window_title: format!("RefineID {}", refineid_lib_core::VERSION),
            status_message: String::new(),
            busy: false,
            cards: Vec::new(),
            selected_card: None,
            card_serial: None,
            pin1_changed: None,
            pin2_changed: None,
            pin1_status: None,
            pin2_status: None,
            puk_status: None,
            pin1_change_available: false,
            pin2_change_available: false,
            activation_available: false,
            pin1_unblock_available: false,
            pin2_unblock_available: false,
            unblock_uses_activation_code: false,
            organization_card: false,
            signature_supported: false,
            pin_lengths: None,
            has_local_card: false,
            selected_card_is_local: false,
            reader: ReaderPresence::NoReader,
            can_request: None,
            card_unread: false,
            pdf_documents: Vec::new(),
            sign_format: SignFormat::Pades,
            sign_result: None,
            pairing: None,
            phone: None,
            remote_use: false,
            phone_reader_empty: false,
            phone_that_forgot: None,
        }
    }
}

/// High-level user actions dispatched from the presentation driver to the controller.
#[derive(Debug)]
pub enum UserIntent {
    /// Factory activation for new cards.
    ActivateCard {
        /// Activation code bytes.
        activation_code: PinBytes,
        /// New PIN1 bytes.
        new_pin1: PinBytes,
        /// New PIN2 bytes.
        new_pin2: PinBytes,
    },
    /// Change an existing PIN.
    ChangePin {
        /// Target slot (PIN1 or PIN2).
        slot: PinManageSlot,
        /// Current PIN bytes.
        current_pin: PinBytes,
        /// New PIN bytes.
        new_pin: PinBytes,
    },
    /// Reactivate a locked PIN using the PUK.
    ReactivatePin {
        /// Target slot (PIN1 or PIN2).
        slot: PinManageSlot,
        /// Unblocking PUK bytes.
        puk: PinBytes,
        /// New PIN bytes.
        new_pin: PinBytes,
    },
    /// Open the contactless card in the reader with its card access number.
    EnterCan(Can),
    /// Add documents to the signing queue.
    AddDocuments(Vec<PathBuf>),
    /// Take one document out of the signing queue.
    RemoveDocument(PathBuf),
    /// Clear the signing queue.
    ClearDocuments,
    /// Set signing format (PAdES or ASiC-E).
    SetSignFormat(SignFormat),
    /// Sign all queued documents.
    SignDocuments {
        /// Qualified signature PIN2 bytes for a card in a reader here;
        /// `None` when the paired phone signs, which takes PIN 2 on its
        /// own screen.
        pin2: Option<PinBytes>,
    },
    /// Pair with the phone showing this code.
    StartPairing {
        /// The code as the user typed it.
        code: String,
    },
    /// Turn remote use on or off. Off forgets the paired phone.
    SetRemoteUse(bool),
}

#[cfg(test)]
mod tests {
    use super::*;

    use refineid_rapp_core::store::PairingState;

    /// A synthetic pair identifier.
    const PAIR_ID: PairId = PairId::from_array(*b"synthetic-pair-1");

    fn summary(state: PairingState) -> PairSummary {
        PairSummary {
            pair_id: PAIR_ID,
            peer_display_name: "Alpha Phone".to_owned(),
            peer_platform: "Android".to_owned(),
            granted_profiles: Vec::new(),
            auth_cert: None,
            state,
        }
    }

    #[test]
    fn the_holder_name_drops_the_identifier_the_common_name_ends_with() {
        assert_eq!(
            holder_name("Tormanen Paivi 12345678N", Some("12345678N")),
            "Tormanen Paivi"
        );
        assert_eq!(
            holder_name("Tormanen Paivi 12345678N", None),
            "Tormanen Paivi 12345678N"
        );
        assert_eq!(
            holder_name("Tormanen Paivi", Some("12345678N")),
            "Tormanen Paivi"
        );
        assert_eq!(holder_name("12345678N", Some("12345678N")), "12345678N");
    }

    #[test]
    fn the_readers_report_no_reader_an_empty_reader_or_a_card() {
        assert_eq!(
            ReaderPresence::from_signature(&[]),
            ReaderPresence::NoReader
        );
        let empty = vec![("Synthetic Card Reader".to_owned(), false)];
        assert_eq!(
            ReaderPresence::from_signature(&empty),
            ReaderPresence::Empty
        );
        let card = vec![
            ("Synthetic Card Reader".to_owned(), false),
            ("Second Synthetic Card Reader".to_owned(), true),
        ];
        assert_eq!(ReaderPresence::from_signature(&card), ReaderPresence::Card);
    }

    #[test]
    fn a_pile_with_anything_but_pdfs_is_a_package() {
        let pdfs = vec![
            PathBuf::from("/documents/a.pdf"),
            PathBuf::from("/documents/B.PDF"),
        ];
        assert_eq!(SignFormat::shared(&pdfs), SignFormat::Pades);
        let mixed = vec![
            PathBuf::from("/documents/a.pdf"),
            PathBuf::from("/documents/notes.txt"),
        ];
        assert_eq!(SignFormat::shared(&mixed), SignFormat::AsicE);
        assert_eq!(SignFormat::shared(&[]), SignFormat::Pades);
    }

    #[test]
    fn only_a_usable_pairing_is_a_phone() {
        let phone =
            PairedPhone::from_summary(&summary(PairingState::PairedDisconnected)).expect("phone");
        assert_eq!(phone.name, "Alpha Phone");
        assert!(!phone.certificate_cached);
        assert!(PairedPhone::from_summary(&summary(PairingState::StorageConfirming)).is_none());
        assert!(PairedPhone::from_summary(&summary(PairingState::Revoking)).is_none());
    }
}
