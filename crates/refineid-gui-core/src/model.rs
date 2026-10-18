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
use refineid_lib_core::auth::{PinStatus, PukStatus};
use refineid_lib_core::identity::TokenSerial;
use refineid_lib_core::pin::PinBytes;
use refineid_lib_core::pkcs15::CardGeneration;
use refineid_lib_core::sign::document::Format;
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::remote::PairSummary;

use crate::image::RgbaImageBuffer;

/// A managed smart card detected on the local host or via a remote RAPP pair.
#[derive(Clone, Debug)]
pub struct ManagedCard {
    /// Full inspection report.
    pub report: CardCheckReport,
    /// Factory activation context for cards that require initial activation.
    pub activation_context: Option<ActivationCardContext>,
}

impl ManagedCard {
    /// Person name string.
    pub fn person_name(&self) -> String {
        self.report.identity.person_string()
    }

    /// The cardholder line: the certificate subject's common name as
    /// the card carries it, or the person string when the certificate
    /// was not read.
    pub fn display_name(&self) -> String {
        self.report
            .identity
            .common_name
            .as_ref()
            .map_or_else(|| self.person_name(), |cn| cn.as_str().to_owned())
    }

    /// Display label for card selector tabs / dropdowns.
    pub fn label(&self) -> String {
        let reader_short = condense_reader_name(&self.report.reader);
        let name = self.person_name();
        if name.is_empty() {
            reader_short
        } else {
            format!("{name} ({reader_short})")
        }
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

    /// Check if PIN change is available.
    pub fn pin_change_available(&self, status: Option<&PinStatus>) -> bool {
        match status {
            Some(PinStatus::Remaining(tries)) => !tries.is_exhausted(),
            Some(PinStatus::Verified) => true,
            Some(PinStatus::Locked | PinStatus::NoInfo | PinStatus::Other(_)) | None => false,
        }
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

/// Condense a PC/SC reader name for display.
pub fn condense_reader_name(reader: &str) -> String {
    let mut name = reader.trim().to_owned();
    if let (Some(open), Some(close)) = (name.find('['), name.rfind(']'))
        && open < close
    {
        let inner = name[open + 1..close].trim().to_lowercase();
        let outer = format!("{} {}", &name[..open], &name[close + 1..]).to_lowercase();
        if !inner.is_empty() && outer.contains(&inner) {
            name.replace_range(open..=close, "");
        }
    }
    let mut words: Vec<&str> = name.split_whitespace().collect();
    if words.ends_with(&["00", "00"]) {
        words.truncate(words.len() - 2);
    }
    words.join(" ")
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

/// Timestamp authority configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimestampConfig {
    /// Hostname and path of RFC 3161 timestamp endpoint.
    pub host_path: String,
    /// Optional HTTP basic authentication username.
    pub username: Option<String>,
    /// Optional HTTP basic authentication password.
    pub password: Option<String>,
}

impl Default for TimestampConfig {
    fn default() -> Self {
        Self {
            host_path: "timestamp.sectigo.com/qualified".into(),
            username: None,
            password: None,
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

/// What a stored pairing with a phone is to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhoneState {
    /// The pairing opens sessions.
    Paired,
    /// Stored before the phone confirmed its own storage; it opens no
    /// session until pairing runs again.
    Unconfirmed,
    /// The phone forgot this computer or rejected the credential.
    ForgottenByPhone,
    /// Revoked on this computer.
    Revoked,
}

impl PhoneState {
    /// The state as the phone list shows it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Paired => "paired",
            Self::Unconfirmed => "unconfirmed",
            Self::ForgottenByPhone => "forgotten by the phone",
            Self::Revoked => "revoked",
        }
    }

    /// Whether a pairing in this state can serve a card.
    #[must_use]
    pub const fn usable(self) -> bool {
        matches!(self, Self::Paired)
    }
}

/// One phone this workstation has paired with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairedPhone {
    /// The pair identifier.
    pub pair_id: PairId,
    /// The name the phone introduced itself with.
    pub name: String,
    /// The platform the phone introduced itself with.
    pub platform: String,
    /// The pairing's state.
    pub state: PhoneState,
}

impl PairedPhone {
    /// The phone as its stored pairing describes it.
    #[must_use]
    pub fn from_summary(summary: &PairSummary) -> Self {
        let state = if summary.forgotten_by_phone {
            PhoneState::ForgottenByPhone
        } else if summary.revoked {
            PhoneState::Revoked
        } else if summary.unconfirmed {
            PhoneState::Unconfirmed
        } else {
            PhoneState::Paired
        };
        Self {
            pair_id: summary.pair_id,
            name: summary.peer_display_name.clone(),
            platform: summary.peer_platform.clone(),
            state,
        }
    }

    /// The one line the phone list shows for this phone.
    #[must_use]
    pub fn line(&self) -> String {
        if self.platform.is_empty() {
            format!("{}: {}", self.name, self.state.label())
        } else {
            format!("{} ({}): {}", self.name, self.platform, self.state.label())
        }
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
    /// Active timestamp server configuration.
    pub timestamp_config: TimestampConfig,
    /// Outcome of the last signing operation.
    pub sign_result: Option<String>,

    /// Active RAPP phone pairing state.
    pub pairing: Option<RappPairingState>,
    /// Every phone this workstation has paired with, newest first.
    pub phones: Vec<PairedPhone>,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            window_title: format!("RefineID {}", env!("CARGO_PKG_VERSION")),
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
            can_text: String::new(),
            portrait: None,
            signature: None,
            pdf_documents: Vec::new(),
            sign_format: SignFormat::Pades,
            timestamp_config: TimestampConfig::default(),
            sign_result: None,
            pairing: None,
            phones: Vec::new(),
        }
    }
}

/// High-level user actions dispatched from the presentation driver to the controller.
#[derive(Debug)]
pub enum UserIntent {
    /// Select a card by index.
    SelectCard(usize),
    /// Request immediate card re-inspection.
    RefreshCards,
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
    /// Update timestamp configuration.
    SetTimestampConfig(TimestampConfig),
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
    /// Cancel active RAPP pairing.
    CancelPairing,
    /// Forget one paired phone.
    ForgetPhone(PairId),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(revoked: bool, unconfirmed: bool, forgotten: bool) -> PairSummary {
        PairSummary {
            pair_id: PairId::from_array([0; 16]),
            peer_display_name: "Alpha Phone".to_owned(),
            peer_platform: "Android".to_owned(),
            granted_profiles: Vec::new(),
            auth_cert: None,
            revoked,
            unconfirmed,
            forgotten_by_phone: forgotten,
        }
    }

    #[test]
    fn a_pairing_maps_to_one_state() {
        assert_eq!(
            PairedPhone::from_summary(&summary(false, false, false)).state,
            PhoneState::Paired
        );
        assert_eq!(
            PairedPhone::from_summary(&summary(false, true, false)).state,
            PhoneState::Unconfirmed
        );
        assert_eq!(
            PairedPhone::from_summary(&summary(true, false, true)).state,
            PhoneState::ForgottenByPhone
        );
        assert_eq!(
            PairedPhone::from_summary(&summary(true, false, false)).state,
            PhoneState::Revoked
        );
    }

    #[test]
    fn the_phone_line_names_the_phone_and_its_state() {
        let phone = PairedPhone::from_summary(&summary(false, true, false));
        assert_eq!(phone.line(), "Alpha Phone (Android): unconfirmed");
        assert!(!phone.state.usable());
        assert!(PhoneState::Paired.usable());
    }
}
