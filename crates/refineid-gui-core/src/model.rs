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
use std::sync::Arc;

use refineid_client::card_check::CardCheckReport;
use refineid_client::card_pin::{ActivationCardContext, PinManageSlot};
use refineid_lib_core::auth::{PinSlot, PinStatus, PukStatus, check_retry_floor};
use refineid_lib_core::identity::TokenSerial;
use refineid_lib_core::pin::PinBytes;
use refineid_lib_core::pkcs15::CardGeneration;
use refineid_lib_core::sign::document::Format;
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::remote::PairSummary;

use crate::image::RgbaImageBuffer;

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

    /// Card key for cache lookup.
    pub fn key(&self) -> String {
        self.report
            .token_info
            .serial_number_hex
            .as_ref()
            .map_or_else(
                || {
                    format!(
                        "fallback:{}\u{1f}{}",
                        self.report.identity.person_string(),
                        self.report.atr_hex
                    )
                },
                |serial| format!("serial:{serial}"),
            )
    }

    /// Whether a change with the current PIN passes the retry floor for
    /// `slot`: five, four or three tries left, or already verified.
    pub fn pin_change_available(&self, slot: PinSlot, status: Option<&PinStatus>) -> bool {
        status.is_some_and(|&status| check_retry_floor(slot, status).is_ok())
    }

    /// Check if legacy factory activation is required.
    pub fn legacy_activation_required(&self) -> bool {
        let pin1_locked = matches!(self.report.pin1, Some(PinStatus::Locked));
        let unchanged = self.report.pin1_changed == Some(false);
        pin1_locked && unchanged
    }

    /// Check if factory activation is available.
    pub fn activation_available(&self) -> bool {
        if let Some(ctx) = &self.activation_context {
            (ctx.generation == CardGeneration::Newer && self.report.pin1_changed == Some(false))
                || (ctx.generation == CardGeneration::Older && self.legacy_activation_required())
        } else {
            false
        }
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

/// Supported signing output formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignFormat {
    /// PAdES signature embedded directly into the PDF.
    Pades,
    /// ASiC-E container alongside the document.
    AsicE,
}

impl From<SignFormat> for Format {
    fn from(f: SignFormat) -> Self {
        match f {
            SignFormat::Pades => Format::Pades,
            SignFormat::AsicE => Format::AsicEXades,
        }
    }
}

/// Active RAPP phone pairing state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RappPairingState {
    /// The typed pairing code, in two-character clusters ("7K X4 M9").
    pub code: String,
    /// Human-readable status line.
    pub status: String,
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
    /// Whether legacy card activation rules apply.
    pub legacy_activation: bool,
    /// Whether unblocking PIN1 is available.
    pub pin1_unblock_available: bool,
    /// Whether unblocking PIN2 is available.
    pub pin2_unblock_available: bool,
    /// Whether unblocking uses an activation code.
    pub unblock_uses_activation_code: bool,
    /// Whether the card model supports digital signatures.
    pub signature_supported: bool,

    /// Whether at least one physical smart card is present in an attached card reader.
    /// When true, the physical card reader overrides RAPP, and the Phone page/tab is suppressed.
    pub has_local_card: bool,
    /// Whether the currently selected card is hosted on a local PC/SC reader.
    /// When false (e.g. remote phone over RAPP), photo loading via local CAN is unavailable
    /// and credentials must be handled directly on the phone.
    pub selected_card_is_local: bool,

    /// Entered 6-digit Card Access Number.
    pub can_text: String,
    /// Decoded card portrait image.
    pub portrait: Option<Arc<RgbaImageBuffer>>,
    /// Decoded card signature image.
    pub signature: Option<Arc<RgbaImageBuffer>>,

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
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            window_title: format!("RefineID {}", env!("REFINEID_VERSION")),
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
            legacy_activation: false,
            pin1_unblock_available: false,
            pin2_unblock_available: false,
            unblock_uses_activation_code: false,
            signature_supported: false,
            has_local_card: false,
            selected_card_is_local: false,
            can_text: String::new(),
            portrait: None,
            signature: None,
            pdf_documents: Vec::new(),
            sign_format: SignFormat::Pades,
            sign_result: None,
            pairing: None,
            phone: None,
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
    /// Request reading portrait and signature images with the given CAN.
    LoadImages {
        /// 6-digit CAN bytes.
        can: PinBytes,
    },
    /// Add documents to the signing queue.
    AddDocuments(Vec<PathBuf>),
    /// Clear the signing queue.
    ClearDocuments,
    /// Set signing format (PAdES or ASiC-E).
    SetSignFormat(SignFormat),
    /// Sign all queued documents.
    SignDocuments {
        /// Qualified signature PIN2 bytes.
        pin2: PinBytes,
    },
    /// Pair with the phone showing this code.
    StartPairing {
        /// The code as the user typed it.
        code: String,
    },
    /// Forget the paired phone.
    ForgetPhone,
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
    fn only_a_usable_pairing_is_a_phone() {
        let phone =
            PairedPhone::from_summary(&summary(PairingState::PairedDisconnected)).expect("phone");
        assert_eq!(phone.name, "Alpha Phone");
        assert!(!phone.certificate_cached);
        assert!(PairedPhone::from_summary(&summary(PairingState::StorageConfirming)).is_none());
        assert!(PairedPhone::from_summary(&summary(PairingState::Revoking)).is_none());
    }
}
