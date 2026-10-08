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

    /// Clean cardholder display name (e.g. "Petri Koistinen").
    pub fn display_name(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref f) = self.report.identity.first_name {
            parts.push(f.as_str());
        }
        for g in self.report.identity.iter_given_names().skip(1) {
            parts.push(g);
        }
        if let Some(ref s) = self.report.identity.surname {
            parts.push(s.as_str());
        }
        if parts.is_empty() {
            self.person_name()
        } else {
            parts.join(" ")
        }
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
    /// 2D boolean grid representing the QR code matrix (true = dark module).
    pub qr_modules: Option<Vec<Vec<bool>>>,
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
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            window_title: format!("RefineID {}", env!("CARGO_PKG_VERSION")),
            status_message: "Insert a FINEID card.".into(),
            busy: false,
            cards: Vec::new(),
            selected_card: None,
            card_serial: None,
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
}
