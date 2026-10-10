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

//! Headless controller: smart-card monitoring, PIN operations, and ceremony execution.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use refineid_client::card_check::CardCheckReport;
use refineid_client::card_pin::{
    ActivateOptions, ChangePinOptions, PinManageSlot, UnblockPinOptions,
};
use refineid_lib_core::auth::{ChangePinOutcome, PinStatus, UnblockOutcome};
use refineid_lib_core::backend::ReaderFilter;
use refineid_lib_core::identity::render_token_serial;
use refineid_lib_core::pin::{
    ActivationCode, ActivationPinEight, ActivationPinSeven, PinBytes, Puk,
};
use refineid_lib_core::pkcs15::CardGeneration;
use refineid_rapp_core::offer::{format_pairing_code, normalize_pairing_code};
use refineid_rapp_core::remote::{RemoteError, RemoteReader};

use crate::error::GuiCoreError;
use crate::image::{RgbaImageBuffer, decode_document_image};
use crate::model::{
    ManagedCard, RappPairingState, SignFormat, TimestampConfig, UiState, UserIntent,
};

const DENIED_PINS: &[&[u8]] = &[
    b"1122", b"1004", b"2000", b"2001", b"2002", b"2020", b"2580", b"5683", b"0852", b"112233",
    b"123321", b"147258", b"159753", b"258036", b"654321",
];

const CARD_PRESENCE_WAIT: Duration = Duration::from_secs(30);
const CARD_PRESENCE_SETTLE: Duration = Duration::from_millis(300);
const CARD_PRESENCE_ERROR_BACKOFF: Duration = Duration::from_secs(5);

/// Cached document images (portrait, signature).
pub type CachedImages = (Option<Arc<RgbaImageBuffer>>, Option<Arc<RgbaImageBuffer>>);

/// Controller managing card state, background presence monitoring, and operations.
pub struct RefineIdController {
    state: Mutex<UiState>,
    image_cache: Mutex<HashMap<String, CachedImages>>,
    presence_stop: AtomicBool,
    inspection_in_flight: AtomicBool,
    on_state_change: Box<dyn Fn(&UiState) + Send + Sync + 'static>,
}

impl std::fmt::Debug for RefineIdController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefineIdController")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl RefineIdController {
    /// Create a new controller with the specified state change callback.
    pub fn new(on_state_change: impl Fn(&UiState) + Send + Sync + 'static) -> Arc<Self> {
        let initial_state = UiState::default();
        on_state_change(&initial_state);

        Arc::new(Self {
            state: Mutex::new(initial_state),
            image_cache: Mutex::new(HashMap::new()),
            presence_stop: AtomicBool::new(false),
            inspection_in_flight: AtomicBool::new(false),
            on_state_change: Box::new(on_state_change),
        })
    }

    /// Read the current UI state snapshot.
    pub fn state(&self) -> UiState {
        self.state.lock().expect("mutex lock").clone()
    }

    /// Mutate state and notify the presentation driver.
    fn update_state<F>(&self, f: F)
    where
        F: FnOnce(&mut UiState),
    {
        let snapshot = {
            let mut state = self.state.lock().expect("mutex lock");
            f(&mut state);
            state.clone()
        };
        (self.on_state_change)(&snapshot);
    }

    /// Start the background card presence monitor and inspect cards.
    pub fn start(self: &Arc<Self>) {
        self.refresh_cards();

        let controller = Arc::clone(self);
        thread::spawn(move || {
            controller.run_presence_monitor();
        });
    }

    /// Stop the background card presence monitor.
    pub fn stop(&self) {
        self.presence_stop.store(true, Ordering::Release);
    }

    /// Handle a user action dispatched from a presentation driver.
    pub fn handle_intent(self: &Arc<Self>, intent: UserIntent) {
        match intent {
            UserIntent::SelectCard(index) => self.select_card(index),
            UserIntent::RefreshCards => self.refresh_cards(),
            UserIntent::ActivateCard {
                activation_code,
                new_pin1,
                new_pin2,
            } => self.activate_card(activation_code, new_pin1, new_pin2),
            UserIntent::ChangePin {
                slot,
                current_pin,
                new_pin,
            } => self.change_pin(slot, current_pin, new_pin),
            UserIntent::ReactivatePin { slot, puk, new_pin } => {
                self.reactivate_pin(slot, puk, new_pin)
            }
            UserIntent::LoadImages { can } => self.load_images(can),
            UserIntent::AddDocuments(paths) => self.add_documents(paths),
            UserIntent::ClearDocuments => self.clear_documents(),
            UserIntent::SetSignFormat(format) => self.set_sign_format(format),
            UserIntent::SetTimestampConfig(config) => self.set_timestamp_config(config),
            UserIntent::SignDocuments { pin2 } => self.sign_documents(pin2),
            UserIntent::StartPairing { code } => self.start_pairing(&code),
            UserIntent::CancelPairing => self.cancel_pairing(),
        }
    }

    fn select_card(&self, index: usize) {
        self.update_state(|state| {
            if index < state.cards.len() {
                state.selected_card = Some(index);
                let card = &state.cards[index];
                state.card_serial = card.report.token_info.serial_number_hex.clone();
                state.pin1_status = card.report.pin1;
                state.pin2_status = card.report.pin2;
                state.puk_status = card.report.puk;
                state.pin1_change_available = card.pin_change_available(card.report.pin1.as_ref());
                state.pin2_change_available = card.pin_change_available(card.report.pin2.as_ref());
                state.activation_available = card.activation_available();
                state.legacy_activation = card.legacy_activation_required();
                let (p1_rec, p2_rec) = card.recovery_availability();
                state.pin1_unblock_available = p1_rec;
                state.pin2_unblock_available = p2_rec;
                state.unblock_uses_activation_code = card
                    .activation_context
                    .as_ref()
                    .is_some_and(|ctx| ctx.generation == CardGeneration::Older);
                state.signature_supported = card
                    .activation_context
                    .as_ref()
                    .is_some_and(|ctx| ctx.generation == CardGeneration::Newer);

                // Look up cached images
                let key = card.key();
                let cache = self.image_cache.lock().expect("mutex lock");
                if let Some((p, s)) = cache.get(&key) {
                    state.portrait = p.clone();
                    state.signature = s.clone();
                } else {
                    state.portrait = None;
                    state.signature = None;
                }
            } else {
                state.selected_card = None;
                state.card_serial = None;
                state.pin1_status = None;
                state.pin2_status = None;
                state.puk_status = None;
                state.portrait = None;
                state.signature = None;
            }
        });
    }

    /// Refresh and inspect all available cards.
    pub fn refresh_cards(self: &Arc<Self>) {
        if self
            .inspection_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        self.update_state(|state| {
            state.busy = true;
        });

        let controller = Arc::clone(self);
        thread::spawn(move || {
            let result = refineid_client::card_manager::inspect_cards(None)
                .map(deduplicate_cards)
                .map_err(|e| e.to_string());

            controller
                .inspection_in_flight
                .store(false, Ordering::Release);
            match result {
                Ok(cards) => {
                    controller.update_state(|state| {
                        state.busy = false;
                        state.cards = cards;
                        state.status_message = if state.cards.is_empty() {
                            "No FINEID card is present.".into()
                        } else {
                            String::new()
                        };
                    });
                    if !controller.state().cards.is_empty() {
                        let selected = controller.state().selected_card.unwrap_or(0);
                        controller.select_card(selected);
                    }
                }
                Err(err) => {
                    controller.update_state(|state| {
                        state.busy = false;
                        state.cards.clear();
                        state.selected_card = None;
                        state.status_message = format!("Card inspection error: {err}");
                    });
                }
            }
        });
    }

    fn run_presence_monitor(&self) {
        let mut baseline = refineid_lib_pcsc::presence_signature().unwrap_or_default();
        while !self.presence_stop.load(Ordering::Acquire) {
            match refineid_lib_pcsc::wait_for_presence_change(&baseline, CARD_PRESENCE_WAIT) {
                Ok(true) => {
                    thread::sleep(CARD_PRESENCE_SETTLE);
                    baseline = refineid_lib_pcsc::presence_signature().unwrap_or(baseline);
                    if !self.presence_stop.load(Ordering::Acquire) {
                        let result = refineid_client::card_manager::inspect_cards(None)
                            .map(deduplicate_cards);
                        if let Ok(cards) = result {
                            self.update_state(|state| {
                                state.cards = cards;
                                if state.cards.is_empty() {
                                    state.selected_card = None;
                                    state.status_message = "No FINEID card is present.".into();
                                }
                            });
                            if !self.state().cards.is_empty() {
                                let selected = self.state().selected_card.unwrap_or(0);
                                self.select_card(selected);
                            }
                        }
                    }
                }
                Ok(false) => {}
                Err(_service_down) => {
                    thread::sleep(CARD_PRESENCE_ERROR_BACKOFF);
                }
            }
        }
    }

    fn activate_card(
        self: &Arc<Self>,
        activation_code_bytes: PinBytes,
        new_pin1: PinBytes,
        new_pin2: PinBytes,
    ) {
        let reader = {
            let state = self.state();
            let Some(card) = state.selected_card.and_then(|idx| state.cards.get(idx)) else {
                self.update_state(|s| s.status_message = "No card selected for activation.".into());
                return;
            };
            card.report.reader.clone()
        };

        self.update_state(|s| s.busy = true);
        let controller = Arc::clone(self);

        thread::spawn(move || {
            let res = (|| {
                let reader_filter = Some(ReaderFilter::new(&reader));
                let context =
                    refineid_client::card_manager::prepare_activation(reader_filter.as_ref())
                        .map_err(|e| e.to_string())?;
                let expected = context.expected_activation_pin_length().ok_or_else(|| {
                    "Card generation did not determine activation-code length".to_owned()
                })?;
                let activation_pin = match expected {
                    ActivationPinSeven::LENGTH => ActivationPinSeven::new(activation_code_bytes)
                        .map(ActivationCode::Seven)
                        .map_err(|e| e.to_string())?,
                    ActivationPinEight::LENGTH => ActivationPinEight::new(activation_code_bytes)
                        .map(ActivationCode::Eight)
                        .map_err(|e| e.to_string())?,
                    other => return Err(format!("Unsupported activation-code length {other}")),
                };

                refineid_client::card_manager::activate(
                    context,
                    ActivateOptions {
                        activation_pin,
                        new_pin1,
                        new_pin2,
                        allow_reactivate: false,
                    },
                )
                .map_err(|e| e.to_string())
            })();

            controller.update_state(|s| {
                s.busy = false;
                match res {
                    Ok(report) => {
                        s.status_message = format!(
                            "Card activated. PIN1: {:?}; PIN2: {:?}",
                            report.pin1_outcome, report.pin2_outcome
                        );
                    }
                    Err(err) => {
                        s.status_message = format!("Card activation failed: {err}");
                    }
                }
            });
            controller.refresh_cards();
        });
    }

    fn change_pin(self: &Arc<Self>, slot: PinManageSlot, current_pin: PinBytes, new_pin: PinBytes) {
        let (reader, serial) = {
            let state = self.state();
            let Some(card) = state.selected_card.and_then(|idx| state.cards.get(idx)) else {
                self.update_state(|s| s.status_message = "No card selected.".into());
                return;
            };
            (
                card.report.reader.clone(),
                card.report.token_info.serial_number_hex.clone(),
            )
        };

        let Some(serial) = serial else {
            self.update_state(|s| s.status_message = "Missing card serial number.".into());
            return;
        };

        if let Err(e) = validate_gui_pin(
            &new_pin,
            slot.label(),
            if slot == PinManageSlot::Pin1 { 4 } else { 6 },
        ) {
            self.update_state(|s| s.status_message = format!("Invalid new PIN: {e}"));
            return;
        }

        self.update_state(|s| s.busy = true);
        let controller = Arc::clone(self);

        thread::spawn(move || {
            let res = refineid_client::card_manager::change_pin(
                &render_token_serial(serial),
                ChangePinOptions {
                    slot,
                    current: current_pin,
                    new: new_pin,
                    reader_filter: Some(reader),
                },
            );

            controller.update_state(|s| {
                s.busy = false;
                match res {
                    Ok(report) if report.outcome == ChangePinOutcome::Ok => {
                        s.status_message = format!("{} changed successfully.", slot.label());
                    }
                    Ok(report) => {
                        s.status_message =
                            format!("{} change rejected: {:?}", slot.label(), report.outcome);
                    }
                    Err(err) => {
                        s.status_message = format!("{} change error: {err}", slot.label());
                    }
                }
            });
            controller.refresh_cards();
        });
    }

    fn reactivate_pin(self: &Arc<Self>, slot: PinManageSlot, puk: PinBytes, new_pin: PinBytes) {
        let (reader, serial) = {
            let state = self.state();
            let Some(card) = state.selected_card.and_then(|idx| state.cards.get(idx)) else {
                self.update_state(|s| s.status_message = "No card selected.".into());
                return;
            };
            (
                card.report.reader.clone(),
                card.report.token_info.serial_number_hex.clone(),
            )
        };

        let Some(serial) = serial else {
            self.update_state(|s| s.status_message = "Missing card serial number.".into());
            return;
        };

        let min_len = if slot == PinManageSlot::Pin1 { 4 } else { 6 };
        if let Err(e) = validate_gui_pin(&new_pin, slot.label(), min_len) {
            self.update_state(|s| s.status_message = format!("Invalid new PIN: {e}"));
            return;
        }

        self.update_state(|s| s.busy = true);
        let controller = Arc::clone(self);

        thread::spawn(move || {
            let res = (|| {
                let puk_parsed = Puk::new(puk).map_err(|e| format!("Invalid PUK: {e}"))?;
                refineid_client::card_manager::unblock_pin(
                    &render_token_serial(serial),
                    UnblockPinOptions {
                        slot,
                        puk: puk_parsed,
                        new_pin,
                        reader_filter: Some(reader),
                    },
                )
                .map_err(|e| e.to_string())
            })();

            controller.update_state(|s| {
                s.busy = false;
                match res {
                    Ok(report) if report.outcome == UnblockOutcome::Ok => {
                        s.status_message = format!("{} reactivated successfully.", slot.label());
                    }
                    Ok(report) => {
                        s.status_message = format!("Reactivation rejected: {:?}", report.outcome);
                    }
                    Err(err) => {
                        s.status_message = format!("Reactivation error: {err}");
                    }
                }
            });
            controller.refresh_cards();
        });
    }

    fn load_images(self: &Arc<Self>, can: PinBytes) {
        let (reader, card_key) = {
            let state = self.state();
            let Some(card) = state.selected_card.and_then(|idx| state.cards.get(idx)) else {
                self.update_state(|s| s.status_message = "No card selected.".into());
                return;
            };
            (card.report.reader.clone(), card.key())
        };

        self.update_state(|s| s.busy = true);
        let controller = Arc::clone(self);

        thread::spawn(move || {
            let res = (|| -> Result<CachedImages, GuiCoreError> {
                let can_str = std::str::from_utf8(can.as_bytes())
                    .map_err(|_| GuiCoreError::Validation("CAN must be ASCII digits".into()))?;
                let can_parsed = refineid_lib_core::can::Can::new(can_str)
                    .map_err(|e| GuiCoreError::Validation(format!("invalid CAN: {e}")))?;
                let images =
                    refineid_client::card_manager::read_images(can_parsed, Some(reader))
                        .map_err(|e| GuiCoreError::Card(format!("PACE image read failed: {e}")))?;

                let portrait = images
                    .data
                    .face
                    .as_ref()
                    .map(decode_document_image)
                    .transpose()?;

                let signature = images
                    .data
                    .signature_image
                    .as_ref()
                    .map(decode_document_image)
                    .transpose()?;

                Ok((portrait, signature))
            })();

            controller.update_state(|s| {
                s.busy = false;
                match res {
                    Ok((p, sig)) => {
                        s.portrait = p.clone();
                        s.signature = sig.clone();
                        s.status_message = "Card portrait and signature loaded.".into();
                        let mut cache = controller.image_cache.lock().expect("mutex lock");
                        cache.insert(card_key, (p, sig));
                    }
                    Err(err) => {
                        s.status_message = format!("{err}");
                    }
                }
            });
        });
    }

    fn add_documents(&self, paths: Vec<PathBuf>) {
        self.update_state(|state| {
            for p in paths {
                if !state.pdf_documents.contains(&p) {
                    state.pdf_documents.push(p);
                }
            }
        });
    }

    fn clear_documents(&self) {
        self.update_state(|state| {
            state.pdf_documents.clear();
            state.sign_result = None;
        });
    }

    fn set_sign_format(&self, format: SignFormat) {
        self.update_state(|state| {
            state.sign_format = format;
        });
    }

    fn set_timestamp_config(&self, config: TimestampConfig) {
        self.update_state(|state| {
            state.timestamp_config = config;
        });
    }

    fn sign_documents(self: &Arc<Self>, pin2: PinBytes) {
        let (reader, serial, signature_buf, documents, format, ts_config) = {
            let state = self.state();
            let Some(card) = state.selected_card.and_then(|idx| state.cards.get(idx)) else {
                self.update_state(|s| s.status_message = "No card selected for signing.".into());
                return;
            };
            (
                card.report.reader.clone(),
                card.report.token_info.serial_number_hex.clone(),
                state.signature.clone(),
                state.pdf_documents.clone(),
                state.sign_format,
                state.timestamp_config.clone(),
            )
        };

        let Some(serial) = serial else {
            self.update_state(|s| s.status_message = "Card serial missing.".into());
            return;
        };

        if documents.is_empty() {
            self.update_state(|s| s.status_message = "No documents queued for signing.".into());
            return;
        }

        self.update_state(|s| s.busy = true);
        let controller = Arc::clone(self);

        thread::spawn(move || {
            let handwriting = signature_buf.as_ref().and_then(|buf| buf.signature_ink());
            let mut results = Vec::new();

            for doc in &documents {
                let out_path = doc.with_extension(format!(
                    "signed.{}",
                    doc.extension().and_then(|s| s.to_str()).unwrap_or("pdf")
                ));
                let res = if format == SignFormat::AsicE {
                    refineid_client::card_manager::sign_asice(
                        refineid_client::card_manager::AsicSignOptions {
                            input: doc.clone(),
                            additional_inputs: Vec::new(),
                            output: out_path.clone(),
                            pin2: pin2.clone(),
                            can: None,
                            reader_filter: Some(reader.clone()),
                            expected_serial: render_token_serial(serial.clone()),
                            timestamp_authority: ts_config.host_path.clone(),
                            timestamp_credentials: None,
                        },
                    )
                    .map(|_| out_path.display().to_string())
                    .map_err(|e| e.to_string())
                } else {
                    refineid_client::card_manager::sign_pdf(
                        refineid_client::card_manager::PdfSignOptions {
                            input: doc.clone(),
                            output: out_path.clone(),
                            pin2: pin2.clone(),
                            can: None,
                            reader_filter: Some(reader.clone()),
                            expected_serial: render_token_serial(serial.clone()),
                            handwriting: handwriting.clone(),
                            timestamp_authority: ts_config.host_path.clone(),
                            timestamp_credentials: None,
                        },
                    )
                    .map(|_| out_path.display().to_string())
                    .map_err(|e| e.to_string())
                };
                results.push(res);
            }

            controller.update_state(|s| {
                s.busy = false;
                let successes = results.iter().filter(|r| r.is_ok()).count();
                if successes == results.len() {
                    s.status_message = format!("Successfully signed {successes} document(s).");
                    s.sign_result = Some(format!("Signed {successes} file(s)."));
                } else {
                    s.status_message = format!(
                        "Signed {successes}/{} document(s) with errors.",
                        results.len()
                    );
                    s.sign_result = Some("Signing failed for some documents.".to_string());
                }
            });
        });
    }

    /// Pairs with the phone showing `code` (RAPP v26.10.9: the phone shows
    /// the code and this workstation types it).
    fn start_pairing(self: &Arc<Self>, code: &str) {
        let Some(normalized) = normalize_pairing_code(code) else {
            self.update_state(|s| {
                s.status_message = "That is not the code your phone shows.".into();
            });
            return;
        };
        self.update_state(|s| {
            s.pairing = Some(RappPairingState {
                code: format_pairing_code(&normalized),
                status: "Looking for your phone on the local network...".into(),
                qr_modules: None,
            });
        });

        let controller = Arc::clone(self);
        thread::spawn(move || {
            let mut reader = match RemoteReader::open_local() {
                Ok(reader) => reader,
                Err(e) => {
                    controller.update_state(|s| {
                        s.pairing = None;
                        s.status_message = format!("Pairing store error: {e}");
                    });
                    return;
                }
            };
            let pair = match reader.pair_with_code(&normalized, PAIRING_DISCOVERY_TIMEOUT) {
                Ok(pair) => pair,
                Err(RemoteError::Pairing(
                    refineid_rapp_core::engine::PairingError::CodeMismatch,
                )) => {
                    controller.update_state(|s| {
                        s.pairing = None;
                        s.status_message = "The code does not match the one on your phone.".into();
                    });
                    return;
                }
                Err(e) => {
                    controller.update_state(|s| {
                        s.pairing = None;
                        s.status_message = format!("Pairing failed: {e}");
                    });
                    return;
                }
            };

            controller.update_state(|s| {
                if let Some(p) = &mut s.pairing {
                    p.status = "Paired. Reading the authentication certificate...".into();
                }
            });
            let _ = reader.refresh_auth_cert(pair.pair_id, PAIRING_DISCOVERY_TIMEOUT);

            controller.update_state(|s| {
                s.pairing = None;
                s.status_message = "Phone paired successfully! Remote card is available.".into();
            });
            controller.refresh_cards();
        });
    }

    fn cancel_pairing(&self) {
        self.update_state(|s| {
            s.pairing = None;
            s.status_message = "Pairing cancelled.".into();
        });
    }
}

/// How long pairing browses for the phone showing the code.
const PAIRING_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(60);

fn validate_gui_pin(pin: &PinBytes, label: &str, minimum_length: usize) -> Result<(), String> {
    let bytes = pin.as_bytes();
    if bytes.len() < minimum_length {
        return Err(format!("{label} must be at least {minimum_length} digits"));
    }
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(format!("{label} must contain digits only"));
    }
    if is_predictable_pin(bytes) {
        return Err(format!("{label} is too easy to guess"));
    }
    Ok(())
}

fn is_predictable_pin(pin: &[u8]) -> bool {
    if DENIED_PINS.contains(&pin) {
        return true;
    }
    if pin.windows(2).all(|w| w[0] == w[1]) {
        return true;
    }
    if pin.windows(2).all(|w| w[0] + 1 == w[1]) {
        return true;
    }
    if pin.windows(2).all(|w| w[0].saturating_sub(1) == w[1]) {
        return true;
    }
    false
}

fn card_key(card: &CardCheckReport) -> String {
    card.token_info.serial_number_hex.as_ref().map_or_else(
        || {
            format!(
                "fallback:{}\u{1f}{}",
                card.identity.person_string(),
                card.atr_hex
            )
        },
        |serial| format!("serial:{serial}"),
    )
}

fn deduplicate_cards(reports: Vec<CardCheckReport>) -> Vec<ManagedCard> {
    let mut cards = Vec::new();
    for report in reports {
        if !cards
            .iter()
            .any(|card: &ManagedCard| card_key(&card.report) == card_key(&report))
        {
            let reader_filter = ReaderFilter::new(&report.reader);
            let activation_context =
                refineid_client::card_manager::prepare_activation(Some(&reader_filter)).ok();
            cards.push(ManagedCard {
                report,
                activation_context,
            });
        }
    }

    // Include paired phones whose authentication certificate is cached.
    if let Ok(reader) = RemoteReader::open_local() {
        for pair in reader.pairs().into_iter().filter(|pair| !pair.revoked) {
            if let Some(cached_der) = pair.auth_cert
                && let Ok(owned_cert) = refineid_lib_core::x509::OwnedCert::from_der(cached_der)
            {
                let view = owned_cert.view();
                let dev_name = pair.peer_display_name;
                let reader = format!("Mobile: {dev_name}");
                let serial = owned_cert.serial().to_string();
                let token_info = refineid_lib_core::pkcs15::TokenInfo {
                    serial_number_hex: Some(refineid_lib_core::identity::TokenSerial::new(serial)),
                    label: Some(format!("Mobile NFC ({dev_name})")),
                    ..Default::default()
                };

                let mut identity = refineid_lib_core::identity::CredentialIdentity::new();
                if let Some(cn) = view.subject.common_name() {
                    let name_str = cn.as_str();
                    if let Some((first, last)) = name_str.split_once(' ') {
                        if let Ok(fn_val) =
                            refineid_lib_core::identity::FirstName::new(first.to_owned())
                        {
                            identity = identity.with_first_name(fn_val);
                        }
                        if let Ok(sn_val) =
                            refineid_lib_core::identity::Surname::new(last.to_owned())
                        {
                            identity = identity.with_surname(sn_val);
                        }
                    } else if let Ok(sn_val) =
                        refineid_lib_core::identity::Surname::new(name_str.to_owned())
                    {
                        identity = identity.with_surname(sn_val);
                    }
                }

                let report = CardCheckReport {
                    reader,
                    identity,
                    atr_hex: String::new(),
                    token_info,
                    card_access: refineid_lib_core::card_access::CardAccess::default(),
                    certs: Vec::new(),
                    pin_reference_scheme: refineid_lib_core::auth::PinReferenceScheme::Citizen,
                    pin1: Some(PinStatus::Verified),
                    pin2: Some(PinStatus::Verified),
                    puk: None,
                    pin1_policy: None,
                    pin2_policy: None,
                    puk_policy: None,
                    pin1_changed: Some(true),
                    pin2_changed: Some(true),
                    emrtd: None,
                    emrtd_error: None,
                    dsc_csca_check: None,
                };
                cards.push(ManagedCard {
                    report,
                    activation_context: None,
                });
            }
        }
    }

    cards
}
