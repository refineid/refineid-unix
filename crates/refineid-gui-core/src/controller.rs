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

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use refineid_client::card_check::{CardCheckError, CardCheckReport};
use refineid_client::card_pin::{
    ActivateOptions, ChangePinOptions, PinManageSlot, UnblockPinOptions,
};
use refineid_doc_sign::service::{DEFAULT_TIMESTAMP_AUTHORITY, SignOutput};
use refineid_doc_sign::signed_name::PendingSignedName;
use refineid_doc_sign::x509::DateTime;
use refineid_lib_core::auth::{ActivationScheme, ChangePinOutcome, PinSlot, UnblockOutcome};
use refineid_lib_core::backend::{ReaderFilter, ReaderPickError};
use refineid_lib_core::can::Can;
use refineid_lib_core::identity::{CredentialIdentity, TokenSerial, render_token_serial};
use refineid_lib_core::pin::{
    ActivationCode, ActivationPinEight, ActivationPinSeven, PinBytes, Puk,
};
use refineid_rapp_core::engine::{OperationOutcome, PairingSearchError};
use refineid_rapp_core::ids::PairId;

use refineid_rapp_core::offer::{format_pairing_code, normalize_pairing_code};
use refineid_rapp_core::remote::{CardRequest, RemoteError, RemoteReader};

use crate::model::{
    CanRequest, CardSource, ManagedCard, PairedPhone, RappPairingState, ReaderPresence, SignFormat,
    UiState, UserIntent,
};

/// Where the signed form of `documents` goes: its default name, carrying
/// the signature's best-signature-time once signed, else `clock`.
fn signed_output(documents: &[PathBuf], format: SignFormat, clock: DateTime) -> SignOutput {
    SignOutput::SignedName(PendingSignedName::new(
        documents.to_vec(),
        format.into(),
        clock,
    ))
}

/// The name a document is listed under in an outcome line.
fn document_name(document: &Path) -> String {
    document.file_name().map_or_else(
        || document.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// What one inspection of the readers found.
enum Inspection {
    /// The cards read, none when no reader holds one.
    Cards(Vec<CardCheckReport>),
    /// A contactless card waits for its card access number.
    Can(CanRequest),
    /// The inspection failed.
    Failed(String),
}

const DENIED_PINS: &[&[u8]] = &[
    b"1122", b"1004", b"2000", b"2001", b"2002", b"2020", b"2580", b"5683", b"0852", b"112233",
    b"123321", b"147258", b"159753", b"258036", b"654321",
];

const CARD_PRESENCE_WAIT: Duration = Duration::from_secs(30);
const CARD_PRESENCE_SETTLE: Duration = Duration::from_millis(300);
const CARD_PRESENCE_ERROR_BACKOFF: Duration = Duration::from_secs(5);
/// How many times an inspection that finds no card is repeated while a
/// reader still reports one: a freshly inserted card answers its first
/// commands only once the reader has powered it.
const CARD_SETTLE_RETRIES: u32 = 5;
/// The wait before each repeated inspection, doubling every time.
const CARD_SETTLE_FIRST_RETRY: Duration = Duration::from_millis(400);

/// Controller managing card state, background presence monitoring, and operations.
pub struct RefineIdController {
    state: Mutex<UiState>,
    /// The card access number typed for the contactless card in the
    /// reader, held until that card leaves.
    can: Mutex<Option<Can>>,
    /// The readers' last presence signature; a change forgets the number.
    last_signature: Mutex<Vec<(String, bool)>>,
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
            can: Mutex::new(None),
            last_signature: Mutex::new(Vec::new()),
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
    ///
    /// The stored pairings are read first: their cards are listed
    /// beside the local readers.
    pub fn start(self: &Arc<Self>) {
        self.refresh_phones();
        self.refresh_cards();

        let controller = Arc::clone(self);
        thread::spawn(move || {
            controller.run_presence_monitor();
        });
        let controller = Arc::clone(self);
        thread::spawn(move || {
            controller.run_phone_watch();
        });
    }

    /// Keeps the paired phone's line true while the GUI holds no session: at each
    /// round it tells a phone this computer forgot, when that phone is in
    /// sight (RAPP v26.10.29 section 4.6 item 2); browses for the paired
    /// phone's record; reads the authentication certificate when none is
    /// cached yet and the phone is on the network; and re-reads the
    /// pairing record, which another program on this computer may have
    /// rewritten.
    ///
    /// When a physical card reader with an inserted card is connected, the local
    /// card reader overrides RAPP completely, and phone polling is suppressed.
    fn run_phone_watch(self: &Arc<Self>) {
        while !self.presence_stop.load(Ordering::Acquire) {
            let local_card_present = self.state().has_local_card
                || refineid_lib_pcsc::presence_signature()
                    .is_ok_and(|sig| sig.iter().any(|(_, present)| *present));

            // The round stands aside while the user pairs or while a local card is connected.
            if !local_card_present && self.state().pairing.is_none() {
                self.refresh_phones();
                let phone = self
                    .state()
                    .phone
                    .as_ref()
                    .map(|phone| (phone.pair_id, phone.name.clone(), phone.certificate_cached));
                if let Ok(mut reader) = RemoteReader::open_local() {
                    reader.deliver_revocation_notices();
                    if let Some((pair_id, name, certificate_cached)) = phone {
                        let seen = reader.observe(pair_id);
                        if !certificate_cached && seen == Ok(true) {
                            let read = reader.refresh_auth_cert(pair_id, CERTIFICATE_FETCH_TIMEOUT);
                            self.note_phone_read(&name, read.as_ref().err());
                        }
                        if seen != Ok(false) {
                            self.refresh_phones();
                        }
                    }
                }
                self.refresh_cards();
            }
            thread::sleep(PHONE_WATCH_INTERVAL);
        }
    }

    /// Stop the background card presence monitor.
    pub fn stop(&self) {
        self.presence_stop.store(true, Ordering::Release);
    }

    /// Handle a user action dispatched from a presentation driver.
    pub fn handle_intent(self: &Arc<Self>, intent: UserIntent) {
        match intent {
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
            UserIntent::EnterCan(can) => self.enter_can(can),
            UserIntent::AddDocuments(paths) => self.add_documents(paths),
            UserIntent::RemoveDocument(path) => self.remove_document(&path),
            UserIntent::ClearDocuments => self.clear_documents(),
            UserIntent::SetSignFormat(format) => self.set_sign_format(format),
            UserIntent::SignDocuments { pin2 } => self.sign_documents(pin2),
            UserIntent::StartPairing { code } => self.start_pairing(&code),
            UserIntent::SetRemoteUse(on) => self.set_remote_use(on),
        }
    }

    /// Reads the paired phone from the store. Remote use is on while a
    /// phone is paired, and turns off when the last pairing ends.
    pub fn refresh_phones(&self) {
        let phone = RemoteReader::open_local()
            .ok()
            .and_then(|reader| reader.phone())
            .and_then(|summary| PairedPhone::from_summary(&summary));
        self.update_state(|state| {
            if phone.is_some() {
                state.remote_use = true;
                state.phone_that_forgot = None;
            } else if state.phone.is_some() {
                state.remote_use = false;
                state.phone_reader_empty = false;
            }
            state.phone = phone;
        });
    }

    /// Turns remote use on, which shows the pairing prompt while no phone
    /// is paired, or off, which forgets the paired phone at once.
    fn set_remote_use(self: &Arc<Self>, on: bool) {
        self.update_state(|state| state.remote_use = on);
        if !on && self.has_usable_phone() {
            self.forget_phone();
        }
    }

    /// Notes what a read through the paired phone said about it.
    fn note_phone_read(&self, phone: &str, read: Option<&RemoteError>) {
        self.update_state(|state| match read {
            None => state.phone_reader_empty = false,
            Some(RemoteError::CardAbsent(CardRequest::InPhoneReader)) => {
                state.phone_reader_empty = true;
            }
            Some(RemoteError::RevokedByPhone) => {
                state.phone_that_forgot = Some(phone.to_owned());
            }
            Some(_) => {}
        });
    }

    /// Whether a paired phone can serve its card: the phone is dialed
    /// only while a pairing exists.
    fn has_usable_phone(&self) -> bool {
        self.state().phone.is_some()
    }

    fn forget_phone(self: &Arc<Self>) {
        let name = self
            .state()
            .phone
            .as_ref()
            .map(|phone| phone.name.clone())
            .unwrap_or_default();
        let outcome = RemoteReader::open_local().and_then(|mut reader| reader.forget());
        self.update_state(|state| {
            state.status_message = match &outcome {
                Ok(()) => String::new(),
                Err(error) => format!("Could not forget {name}: {error}"),
            };
        });
        self.refresh_phones();
        self.refresh_cards();
    }

    /// Replaces the listed cards and selects the card in use: a card in a
    /// reader attached to this computer before the phone's card, the
    /// first of either. The cards and the selected card's state change in
    /// one update, so no window shows one card's list with another card's
    /// activation or organization state.
    fn replace_cards(&self, cards: Vec<ManagedCard>) {
        let index = cards
            .iter()
            .position(|card| card.source == CardSource::Local)
            .or_else(|| (!cards.is_empty()).then_some(0))
            .unwrap_or(0);
        let has_local_card = cards.iter().any(|card| card.source == CardSource::Local);
        self.update_state(|state| {
            state.has_local_card = has_local_card;
            state.cards = cards;
            Self::select_card(state, index);
        });
    }

    /// Sets the selected card's state from the card at `index`, or clears
    /// it when there is none.
    fn select_card(state: &mut UiState, index: usize) {
        if index < state.cards.len() {
            state.selected_card = Some(index);
            let card = &state.cards[index];
            let is_local = card.source == CardSource::Local;
            state.selected_card_is_local = is_local;
            state.card_serial = card.report.token_info.serial_number_hex.clone();
            state.pin1_changed = card.report.pin1_changed;
            state.pin2_changed = card.report.pin2_changed;
            state.pin1_status = card.report.pin1;
            state.pin2_status = card.report.pin2;
            state.puk_status = card.report.puk;
            state.pin1_change_available =
                is_local && card.pin_change_available(PinSlot::Pin1, card.report.pin1.as_ref());
            state.pin2_change_available =
                is_local && card.pin_change_available(PinSlot::Pin2, card.report.pin2.as_ref());
            state.activation_available = is_local && card.activation_available();
            let (p1_rec, p2_rec) = if is_local {
                card.recovery_availability()
            } else {
                (false, false)
            };
            state.pin1_unblock_available = p1_rec;
            state.pin2_unblock_available = p2_rec;
            state.unblock_uses_activation_code = is_local
                && card
                    .activation_context
                    .as_ref()
                    .is_some_and(|ctx| ctx.scheme == ActivationScheme::ActivationCodeIsPuk);
            state.organization_card = card.is_organization_card();
            // A card here signs whatever its activation scheme; the
            // phone's card signs when the pairing grants it.
            state.signature_supported = if is_local {
                true
            } else {
                state
                    .phone
                    .as_ref()
                    .is_some_and(|phone| phone.signs_documents)
            };
        } else {
            state.selected_card = None;
            state.selected_card_is_local = false;
            state.card_serial = None;
            state.pin1_changed = None;
            state.pin2_changed = None;
            state.pin1_status = None;
            state.pin2_status = None;
            state.puk_status = None;
            state.pin1_change_available = false;
            state.pin2_change_available = false;
            state.activation_available = false;
            state.organization_card = false;
            state.pin1_unblock_available = false;
            state.pin2_unblock_available = false;
            state.unblock_uses_activation_code = false;
            state.signature_supported = false;
        }
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
            let signature = refineid_lib_pcsc::presence_signature().unwrap_or_default();
            controller.forget_can_on_change(&signature);
            let inspection = controller.inspect();
            controller
                .inspection_in_flight
                .store(false, Ordering::Release);
            controller.update_state(|state| state.busy = false);
            controller.apply_inspection(&signature, inspection);
        });
    }

    /// Inspects the readers with the card access number typed for the
    /// card in them, if any. No reader, or none with a card, is an empty
    /// list, not an error.
    fn inspect(&self) -> Inspection {
        let can = *self.can.lock().expect("mutex lock");
        match refineid_client::card_manager::inspect_cards(None, can.as_ref()) {
            Ok(reports) => Inspection::Cards(reports),
            Err(CardCheckError::ReaderPick(
                ReaderPickError::NoReaders | ReaderPickError::NoCardPresent,
            )) => Inspection::Cards(Vec::new()),
            Err(CardCheckError::NeedCan) => Inspection::Can(CanRequest::Needed),
            Err(CardCheckError::BadCan) => {
                refineid_dev_errors::report!(Gui, "card access number refused", "BadCan");
                *self.can.lock().expect("mutex lock") = None;
                Inspection::Can(CanRequest::Refused)
            }
            Err(error) => {
                refineid_dev_errors::report!(Gui, "card inspection failed", error);
                Inspection::Failed(error.to_string())
            }
        }
    }

    /// Forgets the typed card access number when the readers' `signature`
    /// differs from the last one seen: the number was typed for the card
    /// that was in the reader then.
    fn forget_can_on_change(&self, signature: &[(String, bool)]) {
        let mut last = self.last_signature.lock().expect("mutex lock");
        if *last != signature {
            *self.can.lock().expect("mutex lock") = None;
            last.clear();
            last.extend_from_slice(signature);
        }
    }

    /// Shows what an inspection found against the readers' `signature`.
    /// A card in a reader here overrides the phone, which is listed only
    /// while no reader holds a card.
    fn apply_inspection(&self, signature: &[(String, bool)], inspection: Inspection) {
        let reader = ReaderPresence::from_signature(signature);
        let include_phones = reader != ReaderPresence::Card && self.has_usable_phone();
        let (reports, can_request, failure) = match inspection {
            Inspection::Cards(reports) => (reports, None, None),
            Inspection::Can(request) => (Vec::new(), Some(request), None),
            Inspection::Failed(error) => (Vec::new(), None, Some(error)),
        };
        let cards = deduplicate_cards(reports, include_phones);
        let card_read = cards.iter().any(|card| card.source == CardSource::Local);
        self.update_state(|state| {
            state.reader = reader;
            state.can_request = can_request.filter(|_| reader == ReaderPresence::Card);
            state.card_unread =
                reader == ReaderPresence::Card && !card_read && state.can_request.is_none();
            if let Some(error) = failure {
                state.status_message = format!("Card inspection error: {error}");
            }
        });
        self.replace_cards(cards);
    }

    fn run_presence_monitor(&self) {
        let mut baseline = refineid_lib_pcsc::presence_signature().unwrap_or_default();
        while !self.presence_stop.load(Ordering::Acquire) {
            match refineid_lib_pcsc::wait_for_presence_change(&baseline, CARD_PRESENCE_WAIT) {
                Ok(true) => {
                    thread::sleep(CARD_PRESENCE_SETTLE);
                    baseline = refineid_lib_pcsc::presence_signature().unwrap_or(baseline);
                    if !self.presence_stop.load(Ordering::Acquire) {
                        let reader = ReaderPresence::from_signature(&baseline);
                        self.forget_can_on_change(&baseline);
                        self.update_state(|state| {
                            state.reader = reader;
                            state.card_unread = false;
                            if reader != ReaderPresence::Card {
                                state.can_request = None;
                            }
                        });
                        let inspection = self.inspect_until_settled(&baseline);
                        self.apply_inspection(&baseline, inspection);
                    }
                }
                Ok(false) => {}
                Err(service_down) => {
                    refineid_dev_errors::report!(Gui, "card presence not watched", service_down);
                    thread::sleep(CARD_PRESENCE_ERROR_BACKOFF);
                }
            }
        }
    }

    /// Inspects the readers, repeating while a reader reports a card that
    /// the inspection did not yet find, so a card still powering up is
    /// read once it answers. The repetition stops when the readers'
    /// report changes; the presence monitor picks that change up.
    fn inspect_until_settled(&self, signature: &[(String, bool)]) -> Inspection {
        let mut wait = CARD_SETTLE_FIRST_RETRY;
        let mut attempt = 0;
        loop {
            let inspection = self.inspect();
            let settled = match &inspection {
                Inspection::Cards(reports) => {
                    let readers: Vec<&str> = reports
                        .iter()
                        .map(|report| report.reader.as_str())
                        .collect();
                    inspection_settled(signature, &readers)
                }
                Inspection::Can(_) | Inspection::Failed(_) => true,
            };
            if settled
                || attempt >= CARD_SETTLE_RETRIES
                || self.presence_stop.load(Ordering::Acquire)
            {
                return inspection;
            }
            attempt += 1;
            thread::sleep(wait);
            wait = wait.saturating_mul(2);
            if refineid_lib_pcsc::presence_signature().is_ok_and(|now| now != signature) {
                return inspection;
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
                let activation_pin = match context.scheme {
                    ActivationScheme::PresetActivationPin => {
                        ActivationPinSeven::new(activation_code_bytes).map(ActivationCode::Seven)
                    }
                    ActivationScheme::ActivationCodeIsPuk => {
                        ActivationPinEight::new(activation_code_bytes).map(ActivationCode::Eight)
                    }
                }
                .map_err(|e| e.to_string())?;

                refineid_client::card_manager::activate(
                    context,
                    ActivateOptions {
                        activation_pin,
                        new_pin1,
                        new_pin2,
                        allow_reactivate: false,
                    },
                )
                .inspect_err(|error| {
                    refineid_dev_errors::report!(Gui, "card activation failed", error)
                })
                .map_err(|e| e.to_string())
            })();

            controller.update_state(|s| {
                s.busy = false;
                s.status_message = match res {
                    Ok(_) => String::new(),
                    Err(err) => format!("Card activation failed: {err}"),
                };
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
                        s.status_message = String::new();
                    }
                    Ok(report) => {
                        let outcome = report.outcome;
                        refineid_dev_errors::report!(Gui, "PIN change rejected", outcome);
                        s.status_message =
                            format!("{} change rejected: {:?}", slot.label(), report.outcome);
                    }
                    Err(err) => {
                        refineid_dev_errors::report!(Gui, "PIN change failed", err);
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
                .inspect_err(|error| refineid_dev_errors::report!(Gui, "PIN unblock failed", error))
                .map_err(|e| e.to_string())
            })();

            controller.update_state(|s| {
                s.busy = false;
                match res {
                    Ok(report) if report.outcome == UnblockOutcome::Ok => {
                        s.status_message = String::new();
                    }
                    Ok(report) => {
                        let outcome = report.outcome;
                        refineid_dev_errors::report!(Gui, "PIN unblock rejected", outcome);
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

    /// Opens the contactless card in the reader with `can`.
    fn enter_can(self: &Arc<Self>, can: Can) {
        *self.can.lock().expect("mutex lock") = Some(can);
        self.update_state(|state| state.can_request = None);
        self.refresh_cards();
    }

    /// Adds `paths` to the queue; the signing method becomes the one
    /// every queued document can take.
    fn add_documents(&self, paths: Vec<PathBuf>) {
        self.update_state(|state| {
            for p in paths {
                if !state.pdf_documents.contains(&p) {
                    state.pdf_documents.push(p);
                }
            }
            state.sign_format = SignFormat::shared(&state.pdf_documents);
        });
    }

    fn remove_document(&self, path: &Path) {
        self.update_state(|state| {
            state.pdf_documents.retain(|document| document != path);
            state.sign_format = SignFormat::shared(&state.pdf_documents);
        });
    }

    fn clear_documents(&self) {
        self.update_state(|state| {
            state.pdf_documents.clear();
            state.sign_format = SignFormat::Pades;
        });
    }

    /// Sets the signing method; a pile with anything but PDFs in it
    /// takes only the package.
    fn set_sign_format(&self, format: SignFormat) {
        self.update_state(|state| {
            if SignFormat::shared(&state.pdf_documents) == SignFormat::Pades {
                state.sign_format = format;
            }
        });
    }

    fn sign_documents(self: &Arc<Self>, pin2: Option<PinBytes>) {
        let (source, reader, serial, documents, format, phone) = {
            let state = self.state();
            if !state.signature_supported {
                return;
            }
            let Some(card) = state.selected_card.and_then(|idx| state.cards.get(idx)) else {
                self.update_state(|s| s.status_message = "No card selected for signing.".into());
                return;
            };
            (
                card.source,
                card.report.reader.clone(),
                card.report.token_info.serial_number_hex.clone(),
                state.pdf_documents.clone(),
                state.sign_format,
                state.phone.as_ref().map(|phone| phone.pair_id),
            )
        };

        // The phone's card is listed only while no reader here holds a
        // card, so a phone card in use means the phone signs.
        if source == CardSource::Phone {
            if let Some(pair_id) = phone {
                self.sign_on_phone(pair_id, documents, format);
            }
            return;
        }
        let Some(pin2) = pin2 else {
            return;
        };

        let Some(serial) = serial else {
            self.update_state(|s| s.status_message = "Card serial missing.".into());
            return;
        };

        if documents.is_empty() {
            self.update_state(|s| s.status_message = "No documents queued for signing.".into());
            return;
        }

        let can = *self.can.lock().expect("mutex lock");
        self.update_state(|s| {
            s.busy = true;
            s.status_message.clear();
            s.sign_result = None;
        });
        let controller = Arc::clone(self);

        thread::spawn(move || {
            // A package is one container over every document; separately,
            // each PDF carries its own signature.
            let batches: Vec<Vec<PathBuf>> = if format == SignFormat::AsicE {
                vec![documents.clone()]
            } else {
                documents.iter().map(|doc| vec![doc.clone()]).collect()
            };
            let mut results = Vec::new();

            for batch in &batches {
                let output = signed_output(batch, format, refineid_doc_sign::now_date_time());
                let res = if format == SignFormat::AsicE {
                    refineid_client::card_manager::sign_asice(
                        refineid_client::card_manager::AsicSignOptions {
                            input: batch[0].clone(),
                            additional_inputs: batch[1..].to_vec(),
                            output: output.clone(),
                            pin2: pin2.clone(),
                            can,
                            reader_filter: Some(reader.clone()),
                            expected_serial: render_token_serial(serial.clone()),
                            timestamp_authority: DEFAULT_TIMESTAMP_AUTHORITY.to_owned(),
                            timestamp_credentials: None,
                        },
                    )
                    .map(|_| ())
                    .inspect_err(|error| {
                        refineid_dev_errors::report!(Gui, "document not signed", error)
                    })
                    .map_err(|e| e.to_string())
                } else {
                    refineid_client::card_manager::sign_pdf(
                        refineid_client::card_manager::PdfSignOptions {
                            input: batch[0].clone(),
                            output: output.clone(),
                            pin2: pin2.clone(),
                            can,
                            reader_filter: Some(reader.clone()),
                            expected_serial: render_token_serial(serial.clone()),
                            timestamp_authority: DEFAULT_TIMESTAMP_AUTHORITY.to_owned(),
                            timestamp_credentials: None,
                        },
                    )
                    .map(|_| ())
                    .inspect_err(|error| {
                        refineid_dev_errors::report!(Gui, "document not signed", error)
                    })
                    .map_err(|e| e.to_string())
                };
                results.push((batch.clone(), res));
            }

            controller.show_sign_outcome(&results);
        });
    }

    /// Shows how each batch of documents fared: "*name* signed" for every
    /// signed document, the failure for each other; signed documents
    /// leave the pile.
    fn show_sign_outcome(&self, results: &[(Vec<PathBuf>, Result<(), String>)]) {
        self.update_state(|s| {
            s.busy = false;
            let mut signed = Vec::new();
            let mut failed = Vec::new();
            for (batch, result) in results {
                for document in batch {
                    let name = document_name(document);
                    match result {
                        Ok(()) => signed.push(crate::window::document_signed(&name)),
                        Err(error) => failed.push(format!("{name}: {error}")),
                    }
                }
            }
            if !signed.is_empty() {
                s.pdf_documents.retain(|document| {
                    !results
                        .iter()
                        .any(|(batch, result)| result.is_ok() && batch.contains(document))
                });
                s.sign_format = SignFormat::shared(&s.pdf_documents);
            }
            s.sign_result = (!signed.is_empty()).then(|| signed.join("\n"));
            s.status_message = failed.join("\n");
        });
    }

    /// Signs every queued document with the paired phone's card in one
    /// request: one consent and one PIN 2 entry, both on the phone.
    fn sign_on_phone(
        self: &Arc<Self>,
        pair_id: PairId,
        documents: Vec<PathBuf>,
        format: SignFormat,
    ) {
        if documents.is_empty() {
            self.update_state(|s| s.status_message = "No documents queued for signing.".into());
            return;
        }
        self.update_state(|s| {
            s.busy = true;
            s.status_message.clear();
            s.sign_result = None;
        });
        let controller = Arc::clone(self);
        thread::spawn(move || {
            let now = refineid_doc_sign::now_date_time();
            // A package is one container over every document, as from a
            // card here; separately, each PDF carries its own signature.
            let batches: Vec<Vec<PathBuf>> = if format == SignFormat::AsicE {
                vec![documents]
            } else {
                documents.into_iter().map(|doc| vec![doc]).collect()
            };
            let requests = batches
                .iter()
                .map(|batch| refineid_client::card_manager::PhoneSignDocument {
                    input: batch[0].clone(),
                    additional_inputs: batch[1..].to_vec(),
                    output: signed_output(batch, format, now),
                    format: format.into(),
                })
                .collect();
            let outcome = refineid_client::card_manager::sign_on_phone(
                pair_id,
                requests,
                DEFAULT_TIMESTAMP_AUTHORITY,
            );
            let results: Vec<(Vec<PathBuf>, Result<(), String>)> = match outcome {
                Ok(results) => batches
                    .iter()
                    .zip(results)
                    .map(|(batch, result)| {
                        let result = result
                            .map(|_| ())
                            .inspect_err(|error| {
                                refineid_dev_errors::report!(Gui, "document not signed", error);
                            })
                            .map_err(|error| error.to_string());
                        (batch.clone(), result)
                    })
                    .collect(),
                Err(failure) => {
                    refineid_dev_errors::report!(Gui, "document not signed", failure);
                    vec![(batches.concat(), Err(failure.to_string()))]
                }
            };
            controller.show_sign_outcome(&results);
        });
    }

    /// Pairs with the phone showing `code` (RAPP v26.10.29: the phone shows
    /// the code and this workstation types it). One ceremony runs at a time.
    fn start_pairing(self: &Arc<Self>, code: &str) {
        if self.state().pairing.is_some() {
            return;
        }
        let Some(normalized) = normalize_pairing_code(code) else {
            self.update_state(|s| {
                s.status_message = PAIRING_CODE_INVALID.into();
            });
            return;
        };
        self.update_state(|s| {
            s.status_message.clear();
            s.pairing = Some(RappPairingState {
                code: format_pairing_code(&normalized),
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
                Err(e) => {
                    controller.update_state(|s| {
                        s.pairing = None;
                        s.status_message = pairing_failure_line(&e);
                    });
                    return;
                }
            };

            let phone = pair.peer_display_name.clone();
            let read = reader.refresh_auth_cert(pair.pair_id, PAIRING_DISCOVERY_TIMEOUT);

            controller.update_state(|s| {
                s.pairing = None;
                s.status_message = pairing_outcome_line(&phone, read.as_ref().err());
            });
            controller.refresh_phones();
            controller.note_phone_read(&phone, read.as_ref().err());
            // Remote use turned off while the code was tried forgets the
            // phone it paired with.
            if !controller.state().remote_use {
                controller.set_remote_use(false);
            }
            controller.refresh_cards();
        });
    }
}

/// The line for a typed code that is no pairing code.
const PAIRING_CODE_INVALID: &str = "The pairing code is invalid";
/// How long pairing browses for the phone showing the code.
const PAIRING_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(60);
/// How long one certificate fetch browses for a paired phone.
const CERTIFICATE_FETCH_TIMEOUT: Duration = Duration::from_secs(6);
/// The pause between rounds of certificate fetches.
const PHONE_WATCH_INTERVAL: Duration = Duration::from_secs(10);

/// The status line after a typed code paired with no phone. It names no
/// phone: none has authenticated itself before a code is accepted.
fn pairing_failure_line(error: &RemoteError) -> String {
    match error {
        RemoteError::Pairing(PairingSearchError::NotAccepted) => {
            "The pairing code was not accepted".into()
        }
        RemoteError::Pairing(PairingSearchError::NoneInPairingMode) => {
            "No phone in pairing mode was found".into()
        }
        error => format!("Pairing failed: {error}"),
    }
}

/// The status line after a pairing: nothing when the card was read or
/// when the identity line says what stands in the way (no card at the
/// phone, the phone forgot this computer), otherwise the failure.
fn pairing_outcome_line(phone: &str, read_error: Option<&RemoteError>) -> String {
    match read_error {
        None | Some(RemoteError::CardAbsent(_) | RemoteError::RevokedByPhone) => String::new(),
        Some(RemoteError::Withdrawn) => format!("{phone} turned remote card access off"),
        Some(RemoteError::Outcome(outcome))
            if matches!(**outcome, OperationOutcome::Cancelled(_)) =>
        {
            format!("{phone} ended the read before a card was read")
        }
        Some(RemoteError::Outcome(outcome)) if matches!(**outcome, OperationOutcome::Lost) => {
            format!("The connection to {phone} ended before the card was read")
        }
        Some(RemoteError::Outcome(outcome)) if matches!(**outcome, OperationOutcome::Refused) => {
            format!("{phone}'s message was not understood")
        }
        Some(error) => format!("{phone}: {error}"),
    }
}

/// Whether an inspection agrees with the presence signature: the readers
/// that report a card are exactly `readers`, the readers a card was read
/// in.
fn inspection_settled(signature: &[(String, bool)], readers: &[&str]) -> bool {
    signature
        .iter()
        .all(|(reader, present)| *present == readers.contains(&reader.as_str()))
        && readers
            .iter()
            .all(|reader| signature.iter().any(|(name, _)| name == reader))
}

/// The reader name of a card served by a paired phone: this prefix and
/// the phone's display name.
const PHONE_READER_PREFIX: &str = "Phone: ";

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

fn deduplicate_cards(reports: Vec<CardCheckReport>, include_phones: bool) -> Vec<ManagedCard> {
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
                source: CardSource::Local,
                report,
                activation_context,
            });
        }
    }

    // Include paired phones only when no local physical card is present.
    // An attached card reader with an inserted card overrides RAPP.
    if include_phones
        && cards.is_empty()
        && let Ok(reader) = RemoteReader::open_local()
        && let Some(pair) = reader.phone()
        && let Some(cached_der) = pair.auth_cert
        && let Ok(owned_cert) = refineid_lib_core::x509::OwnedCert::from_der(cached_der)
    {
        let view = owned_cert.view();
        let serial = TokenSerial::new(owned_cert.serial().to_string());
        let mut identity = CredentialIdentity::new();
        if let Some(cn) = view.subject.common_name() {
            identity = identity.with_common_name(cn.clone());
        }
        if let Some(peuin) = view.subject.peuin() {
            identity = identity.with_peuin(peuin);
        }
        cards.push(phone_card(&pair.peer_display_name, serial, identity));
    }

    cards
}

/// The card a paired phone serves, as the pairing record describes it:
/// the holder from the cached authentication certificate and nothing
/// from the card itself. No PIN was probed, so every PIN field is
/// `None`.
fn phone_card(dev_name: &str, serial: TokenSerial, identity: CredentialIdentity) -> ManagedCard {
    let token_info = refineid_lib_core::pkcs15::TokenInfo {
        serial_number_hex: Some(serial),
        label: Some(format!("Phone ({dev_name})")),
        ..Default::default()
    };
    let report = CardCheckReport {
        reader: format!("{PHONE_READER_PREFIX}{dev_name}"),
        identity,
        atr_hex: String::new(),
        token_info,
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
    };
    ManagedCard {
        source: CardSource::Phone,
        report,
        activation_context: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use refineid_lib_core::auth::PinStatus;
    use refineid_rapp_core::message::ResultError;

    /// A synthetic signature timestamp generation time,
    /// 2001-09-09T01:46:40Z.
    const SIGNATURE_TIMESTAMP_AT: u64 = 1_000_000_000;
    /// How much later a synthetic clock reads.
    const CLOCK_DELAY: u64 = 3_600;

    fn instant(seconds: u64) -> DateTime {
        DateTime::from_unix_duration(Duration::from_secs(seconds))
            .unwrap_or_else(|e| panic!("synthetic instant: {e}"))
    }

    #[test]
    fn a_signed_document_is_named_by_its_signature_timestamp_else_the_clock() {
        use refineid_doc_sign::signed_name::BestSignatureTime;
        use refineid_doc_sign::timestamp::VerifiedTimestampToken;
        use refineid_doc_sign::x509::OwnedCert;

        /// A public DVV intermediate, standing in for the authority.
        const AUTHORITY_DER: &[u8] = include_bytes!(
            "../../refineid-client/test-vectors/fineid-intermediate-01-citizen-g4e.der"
        );

        let clock = instant(SIGNATURE_TIMESTAMP_AT.saturating_add(CLOCK_DELAY));
        let authority = OwnedCert::from_der(AUTHORITY_DER)
            .unwrap_or_else(|e| panic!("synthetic authority: {e}"));
        let token = VerifiedTimestampToken::from_parts_for_test(
            Vec::new(),
            authority,
            Vec::new(),
            instant(SIGNATURE_TIMESTAMP_AT),
        );
        let best = BestSignatureTime::of_signature_timestamps(core::slice::from_ref(&token));
        let pdf = signed_output(&["/documents/report.pdf".into()], SignFormat::Pades, clock);
        assert_eq!(
            pdf.path(best),
            PathBuf::from("/documents/report-signed-2001-09-09T01-46-40Z.pdf")
        );
        assert_eq!(
            pdf.path(None),
            PathBuf::from("/documents/report-signed-2001-09-09T02-46-40Z.pdf")
        );
        let container = signed_output(&["/documents/notes.txt".into()], SignFormat::AsicE, clock);
        assert_eq!(
            container.path(best),
            PathBuf::from("/documents/notes-signed-2001-09-09T01-46-40Z.asice")
        );
    }

    #[test]
    fn the_pairing_line_says_only_what_stands_in_the_way() {
        assert_eq!(pairing_outcome_line("Alpha Phone", None), "");
        assert_eq!(
            pairing_outcome_line(
                "Alpha Phone",
                Some(&RemoteError::CardAbsent(CardRequest::InPhoneReader))
            ),
            ""
        );
        assert_eq!(
            pairing_outcome_line(
                "Alpha Phone",
                Some(&RemoteError::CardAbsent(CardRequest::ToPhone))
            ),
            ""
        );
        assert_eq!(
            pairing_outcome_line(
                "Alpha Phone",
                Some(&RemoteError::Outcome(Box::new(
                    OperationOutcome::Cancelled(ResultError::OperationExpired)
                )))
            ),
            "Alpha Phone ended the read before a card was read"
        );
        assert_eq!(
            pairing_outcome_line(
                "Alpha Phone",
                Some(&RemoteError::Outcome(Box::new(OperationOutcome::Lost)))
            ),
            "The connection to Alpha Phone ended before the card was read"
        );
        assert_eq!(
            pairing_outcome_line(
                "Alpha Phone",
                Some(&RemoteError::Outcome(Box::new(OperationOutcome::Refused)))
            ),
            "Alpha Phone's message was not understood"
        );
        assert_eq!(
            pairing_outcome_line("Alpha Phone", Some(&RemoteError::RevokedByPhone)),
            ""
        );
    }

    #[test]
    fn a_failed_pairing_names_no_phone() {
        assert_eq!(
            pairing_failure_line(&RemoteError::Pairing(PairingSearchError::NotAccepted)),
            "The pairing code was not accepted"
        );
        assert_eq!(
            pairing_failure_line(&RemoteError::Pairing(PairingSearchError::NoneInPairingMode)),
            "No phone in pairing mode was found"
        );
        assert_eq!(
            pairing_failure_line(&RemoteError::Busy),
            "Pairing failed: the phone session is held by another program on this computer"
        );
    }

    #[test]
    fn an_inspection_settles_when_it_agrees_with_the_readers() {
        let card_in_reader = vec![("Reader".to_owned(), true)];
        let empty_reader = vec![("Reader".to_owned(), false)];
        let two_readers = vec![("Reader".to_owned(), true), ("Second".to_owned(), true)];
        assert!(inspection_settled(&card_in_reader, &["Reader"]));
        assert!(!inspection_settled(&card_in_reader, &[]));
        assert!(inspection_settled(&empty_reader, &[]));
        assert!(!inspection_settled(&empty_reader, &["Reader"]));
        assert!(inspection_settled(&[], &[]));
        assert!(!inspection_settled(&[], &["Reader"]));
        assert!(!inspection_settled(&two_readers, &["Reader"]));
        assert!(inspection_settled(&two_readers, &["Second", "Reader"]));
    }

    #[test]
    fn connected_card_reader_overrides_rapp_in_card_deduplication() {
        let physical_report = CardCheckReport {
            reader: "Synthetic Card Reader".to_owned(),
            identity: CredentialIdentity::new(),
            atr_hex: "3b00".to_owned(),
            token_info: refineid_lib_core::pkcs15::TokenInfo::default(),
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
        };

        // When a physical card is present, phone is never added even if include_phones is true
        let cards = deduplicate_cards(vec![physical_report], true);
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].source, CardSource::Local);
        assert_eq!(cards[0].report.reader, "Synthetic Card Reader");

        // When no physical card is present and include_phones is false, cards is empty
        let empty_cards = deduplicate_cards(Vec::new(), false);
        assert!(empty_cards.is_empty());
    }

    #[test]
    fn a_phone_card_claims_no_pin_state_and_offers_no_pin_action() {
        let card = phone_card(
            "custodian-1",
            TokenSerial::new("1".to_owned()),
            CredentialIdentity::new(),
        );
        assert_eq!(card.source, CardSource::Phone);
        assert_eq!(card.report.pin1, None);
        assert_eq!(card.report.pin2, None);
        assert_eq!(card.report.pin1_changed, None);
        assert_eq!(card.report.pin2_changed, None);

        let controller = RefineIdController::new(|_| {});
        controller.replace_cards(vec![card]);
        let state = controller.state();
        assert_eq!(state.selected_card, Some(0));
        assert!(!state.has_local_card);
        assert!(!state.selected_card_is_local);
        assert_eq!(state.pin1_status, None);
        assert_eq!(state.pin2_status, None);
        assert_eq!(state.pin1_changed, None);
        assert_eq!(state.pin2_changed, None);
        assert!(!state.pin1_change_available);
        assert!(!state.pin2_change_available);
        assert!(!state.activation_available);
        assert!(!state.organization_card);
        assert!(!state.pin1_unblock_available);
        assert!(!state.pin2_unblock_available);
        assert!(!state.unblock_uses_activation_code);
    }

    /// The window sees the new cards and the selected card's state in
    /// one change, never the list beside the previous card's state.
    #[test]
    fn replacing_the_cards_is_one_state_change() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let changes = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&changes);
        let controller = RefineIdController::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
        });
        let before = changes.load(Ordering::SeqCst);
        controller.replace_cards(vec![phone_card(
            "custodian-1",
            TokenSerial::new("1".to_owned()),
            CredentialIdentity::new(),
        )]);
        assert_eq!(changes.load(Ordering::SeqCst) - before, 1);
        assert_eq!(controller.state().selected_card, Some(0));
    }

    /// Signing does not depend on the activation scheme: a card here
    /// signs whether or not an activation context was built for it.
    #[test]
    fn a_card_here_signs_whatever_its_activation_scheme() {
        let report = CardCheckReport {
            reader: "Synthetic Card Reader".to_owned(),
            identity: CredentialIdentity::new(),
            atr_hex: "3b00".to_owned(),
            token_info: refineid_lib_core::pkcs15::TokenInfo::default(),
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
        };
        let controller = RefineIdController::new(|_| {});
        controller.replace_cards(vec![ManagedCard {
            source: CardSource::Local,
            report,
            activation_context: None,
        }]);
        let state = controller.state();
        assert!(state.selected_card_is_local);
        assert!(state.signature_supported);
        assert!(!state.activation_available);
    }

    #[test]
    fn the_phone_card_signs_when_the_pairing_grants_signing() {
        use refineid_rapp_core::ids::PairId;
        for signs_documents in [true, false] {
            let controller = RefineIdController::new(|_| {});
            controller.update_state(|state| {
                state.phone = Some(PairedPhone {
                    pair_id: PairId::from_array(*b"synthetic-pair-1"),
                    name: "custodian-1".to_owned(),
                    platform: "Synthetic".to_owned(),
                    certificate_cached: false,
                    signs_documents,
                });
            });
            controller.replace_cards(vec![phone_card(
                "custodian-1",
                TokenSerial::new("1".to_owned()),
                CredentialIdentity::new(),
            )]);
            let state = controller.state();
            assert!(!state.selected_card_is_local);
            assert_eq!(state.phone_signs(), signs_documents);
            assert_eq!(state.signature_supported, signs_documents);
        }
    }

    #[test]
    fn signed_documents_leave_the_pile_and_the_rest_stay() {
        let controller = RefineIdController::new(|_| {});
        let report = PathBuf::from("/documents/report.pdf");
        let notes = PathBuf::from("/documents/notes.pdf");
        let added_while_signing = PathBuf::from("/documents/later.pdf");
        controller.handle_intent(UserIntent::AddDocuments(vec![
            report.clone(),
            notes.clone(),
            added_while_signing.clone(),
        ]));
        controller.show_sign_outcome(&[
            (vec![report], Ok(())),
            (vec![notes.clone()], Err("refused".to_owned())),
        ]);
        let state = controller.state();
        assert_eq!(state.pdf_documents, vec![notes, added_while_signing]);
        assert_eq!(state.sign_result.as_deref(), Some("report.pdf signed"));
        assert_eq!(state.status_message, "notes.pdf: refused");
    }

    #[test]
    fn a_change_of_readers_forgets_the_access_number() {
        let controller = RefineIdController::new(|_| {});
        let two_cards = vec![
            ("Synthetic Card Reader".to_owned(), true),
            ("Second Synthetic Card Reader".to_owned(), true),
        ];
        let one_card = vec![
            ("Synthetic Card Reader".to_owned(), false),
            ("Second Synthetic Card Reader".to_owned(), true),
        ];
        controller.forget_can_on_change(&two_cards);
        *controller.can.lock().expect("mutex lock") =
            Some(Can::new("123456").expect("synthetic access number"));
        controller.forget_can_on_change(&two_cards);
        assert!(controller.can.lock().expect("mutex lock").is_some());
        controller.forget_can_on_change(&one_card);
        assert!(controller.can.lock().expect("mutex lock").is_none());
    }

    #[test]
    fn the_pile_decides_the_signing_method() {
        let controller = RefineIdController::new(|_| {});
        let report = PathBuf::from("/documents/report.pdf");
        let notes = PathBuf::from("/documents/notes.txt");
        controller.handle_intent(UserIntent::AddDocuments(vec![report.clone()]));
        controller.handle_intent(UserIntent::SetSignFormat(SignFormat::AsicE));
        assert_eq!(controller.state().sign_format, SignFormat::AsicE);
        controller.handle_intent(UserIntent::AddDocuments(vec![
            notes.clone(),
            report.clone(),
        ]));
        let state = controller.state();
        assert_eq!(state.pdf_documents, vec![report.clone(), notes.clone()]);
        assert_eq!(state.sign_format, SignFormat::AsicE);
        controller.handle_intent(UserIntent::SetSignFormat(SignFormat::Pades));
        assert_eq!(controller.state().sign_format, SignFormat::AsicE);
        controller.handle_intent(UserIntent::RemoveDocument(notes));
        let state = controller.state();
        assert_eq!(state.pdf_documents, vec![report]);
        assert_eq!(state.sign_format, SignFormat::Pades);
        controller.handle_intent(UserIntent::ClearDocuments);
        assert!(controller.state().pdf_documents.is_empty());
    }

    #[test]
    fn remote_use_turns_on_without_a_phone() {
        let controller = RefineIdController::new(|_| {});
        controller.handle_intent(UserIntent::SetRemoteUse(true));
        assert!(controller.state().remote_use);
        controller.handle_intent(UserIntent::SetRemoteUse(false));
        assert!(!controller.state().remote_use);
    }

    #[test]
    fn predictable_pins_are_refused() {
        assert!(is_predictable_pin(b"1234"));
        assert!(is_predictable_pin(b"1111"));
        assert!(!is_predictable_pin(b"2719"));
    }
}
