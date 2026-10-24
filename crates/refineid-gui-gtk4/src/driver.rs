// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

//! GTK 4 presentation driver for RefineID.
//!
//! Faithful reproduction of the native Apple application (`refineid-apple`):
//! - Compact 560x400 status window matching `window-card-en.png` and `window-phone-en.png`.
//! - Titlebar with "RefineID" and trailing circular `RemoteUseButton` (PIN Codes / remote switch).
//! - Inset grouped form (`.apple-card`) with rounded corners and dark theme palette:
//!   - Card 1: Identity / Status row (`IdentityStateView`): holder name (`DOE JANE` or
//!     `DOE JANE (via phone)`), card/reader detection status, or inline 6-box RAPP pairing code.
//!   - Card 2: Document Signing section (`StatusDocumentSection`): empty drop invitation
//!     with `doc.badge.plus`, "Drop documents here to sign them", "Choose..." link button,
//!     queued document pile, format toggle (PAdES / ASiC-E), PIN 2 masked entry, and "Sign..." action.
//! - Auxiliary `PinCodesWindow`: Separate focused card management window (`CardManagementView`)
//!   for changing PIN 1/2, unblocking with PUK, and card activation.
//! - Masked `PasswordEntry` with peek eye icon, zero PIN logging, and explicit buffer clearance.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use refineid_gui_core::PinManageSlot;
use refineid_gui_core::controller::RefineIdController;
use refineid_gui_core::driver::UiDriver;
use refineid_gui_core::error::GuiCoreError;
use refineid_gui_core::model::{SignFormat, UiState, UserIntent};
use refineid_lib_core::auth::{PIN_TRY_LIMIT, PinStatus, PukStatus};
use refineid_lib_core::pin::{ActivationPinEight, ActivationPinSeven, PinBytes, Puk};
use refineid_rapp_core::offer::{
    PAIRING_CODE_GROUP_SIZE, PAIRING_CODE_LENGTH, pairing_code_character,
};

use gtk4::gdk;
use gtk4::gio;
use gtk4::glib;
use gtk4::prelude::*;

/// Full pristine retry limit for PIN and PUK (FINEID S4-1).
const RETRY_FULL_THRESHOLD: usize = PIN_TRY_LIMIT as usize;

/// Retry counter warning threshold (FINEID S4-1 / card policy).
/// When fewer than 3 attempts remain, warning styling is highlighted to prevent accidental lockout.
const RETRY_WARN_THRESHOLD: usize = 3;

/// Minimum and maximum PUK length (8..=12 digits, FINEID S4-1 §8.1.5).
const MIN_PUK_DIGITS: usize = Puk::MIN_LENGTH;
const MAX_PUK_DIGITS: usize = Puk::MAX_LENGTH;

/// Minimum and maximum Activation Code length (7 digits for newer cards, 8 for older cards).
const MIN_ACTIVATION_CODE_DIGITS: usize = ActivationPinSeven::LENGTH;
const MAX_ACTIVATION_CODE_DIGITS: usize = ActivationPinEight::LENGTH;

/// Minimum and maximum allowed digits for PIN 1.
const MIN_PIN1_DIGITS: usize = PinBytes::MIN_LENGTH;
const MAX_PIN1_DIGITS: usize = PinBytes::MAX_LENGTH;

/// Minimum and maximum allowed digits for PIN 2.
const MIN_PIN2_DIGITS: usize = 6;
const MAX_PIN2_DIGITS: usize = PinBytes::MAX_LENGTH;

/// Total characters for RAPP pairing code.
const PAIRING_CODE_LEN: usize = PAIRING_CODE_LENGTH;

/// Action represented by the titlebar remote switch / key button.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RemoteButtonAction {
    /// Card is present in local reader: button opens auxiliary PIN codes window.
    OpenPinCodes,
    /// No card or phone connected: button toggles the inline RAPP pairing code ceremony.
    TogglePairing,
    /// Remote phone is connected: button permits disconnecting / forgetting the paired phone.
    ForgetPhone,
}

/// Safely construct [`PinBytes`] from user input.
fn to_pin_bytes(s: &str) -> Option<PinBytes> {
    PinBytes::new(s.as_bytes().to_vec()).ok()
}

/// Filter string to valid pairing-code characters up to [`PAIRING_CODE_LEN`].
fn filter_pairing_code(text: &str) -> String {
    text.chars()
        .filter_map(pairing_code_character)
        .take(PAIRING_CODE_LEN)
        .collect()
}

/// Filter string to numeric ASCII digits up to `max` count.
fn filter_digits(text: &str, max: usize) -> String {
    text.chars()
        .filter(|c| c.is_ascii_digit())
        .take(max)
        .collect()
}

/// Format PIN retry counter and status.
fn format_pin_status(status: Option<&PinStatus>, changed: Option<bool>) -> (String, &'static str) {
    match status {
        Some(PinStatus::Remaining(retries)) => {
            let count = retries.get() as usize;
            let limit = RETRY_FULL_THRESHOLD;
            let note = if changed == Some(false) {
                " • Factory"
            } else {
                ""
            };
            if count >= RETRY_FULL_THRESHOLD {
                (format!("{count} / {limit}{note}"), "status-pill-green")
            } else if count >= RETRY_WARN_THRESHOLD {
                (format!("{count} / {limit}{note}"), "status-pill-orange")
            } else {
                (format!("{count} / {limit}{note}"), "status-pill-red")
            }
        }
        Some(PinStatus::Locked) => ("Blocked".to_string(), "status-pill-red"),
        Some(PinStatus::Verified) => ("Verified".to_string(), "status-pill-green"),
        Some(PinStatus::NoInfo) => ("No retry count".to_string(), "status-pill-gray"),
        Some(PinStatus::Other(sw)) => (format!("Status {sw:04X}"), "status-pill-gray"),
        None => ("No card".to_string(), "status-pill-gray"),
    }
}

/// Human-readable PUK status formatting.
fn format_puk_status(status: Option<&PukStatus>) -> (String, &'static str) {
    match status {
        Some(PukStatus::Remaining(retries)) => {
            let count = retries.get() as usize;
            if count >= RETRY_FULL_THRESHOLD {
                (format!("{count} remaining"), "status-pill-green")
            } else if count >= RETRY_WARN_THRESHOLD {
                (format!("{count} remaining"), "status-pill-orange")
            } else {
                (format!("{count} remaining"), "status-pill-red")
            }
        }
        Some(PukStatus::Locked) => ("Blocked".to_string(), "status-pill-red"),
        Some(PukStatus::Invalidated) => ("Invalidated".to_string(), "status-pill-red"),
        Some(PukStatus::NoInfo) => ("No count".to_string(), "status-pill-gray"),
        Some(PukStatus::Other(sw)) => (format!("Status {sw:04X}"), "status-pill-gray"),
        None => ("No card".to_string(), "status-pill-gray"),
    }
}

/// Helper alert modal dialog.
fn show_alert(parent: &impl IsA<gtk4::Window>, message: &str) {
    let dialog = gtk4::MessageDialog::builder()
        .transient_for(parent)
        .modal(true)
        .title("RefineID")
        .text(message)
        .message_type(gtk4::MessageType::Warning)
        .buttons(gtk4::ButtonsType::Ok)
        .build();
    dialog.connect_response(|d, _| {
        d.close();
    });
    dialog.present();
}

/// Helper confirmation modal dialog.
fn show_confirm(
    parent: &impl IsA<gtk4::Window>,
    message: &str,
    on_confirm: impl FnOnce() + 'static,
) {
    let dialog = gtk4::MessageDialog::builder()
        .transient_for(parent)
        .modal(true)
        .title("RefineID")
        .text(message)
        .message_type(gtk4::MessageType::Question)
        .buttons(gtk4::ButtonsType::OkCancel)
        .build();
    let cb = RefCell::new(Some(on_confirm));
    dialog.connect_response(move |d, resp| {
        if resp == gtk4::ResponseType::Ok
            && let Some(action) = cb.borrow_mut().take()
        {
            action();
        }
        d.close();
    });
    dialog.present();
}

// ---------------------------------------------------------------------------
// 6-Box Pairing Code Entry Component
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CodeBoxes {
    overlay: gtk4::Overlay,
    labels: Vec<gtk4::Label>,
    entry: gtk4::Entry,
    is_focused: Rc<Cell<bool>>,
}

fn render_code_boxes(labels: &[gtk4::Label], code: &str, is_focused: bool) {
    let chars: Vec<char> = code.chars().filter_map(pairing_code_character).collect();
    let current_len = chars.len();
    for (i, lbl) in labels.iter().enumerate() {
        if let Some(&c) = chars.get(i) {
            lbl.set_label(&c.to_string());
            lbl.add_css_class("code-box-filled");
            lbl.remove_css_class("code-box-active");
        } else {
            lbl.set_label("");
            lbl.remove_css_class("code-box-filled");
            if i == current_len && is_focused {
                lbl.add_css_class("code-box-active");
            } else {
                lbl.remove_css_class("code-box-active");
            }
        }
    }
}

impl CodeBoxes {
    fn new() -> Self {
        let boxes_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(6)
            .halign(gtk4::Align::Center)
            .valign(gtk4::Align::Center)
            .build();

        let mut boxes = Vec::with_capacity(PAIRING_CODE_LEN);
        for i in 0..PAIRING_CODE_LEN {
            if i > 0 && i % PAIRING_CODE_GROUP_SIZE == 0 {
                let spacer = gtk4::Box::builder().width_request(14).build();
                boxes_box.append(&spacer);
            }
            let lbl = gtk4::Label::builder()
                .label("")
                .width_request(44)
                .height_request(52)
                .halign(gtk4::Align::Center)
                .valign(gtk4::Align::Center)
                .build();
            lbl.add_css_class("code-box");
            boxes_box.append(&lbl);
            boxes.push(lbl);
        }

        let entry = gtk4::Entry::builder()
            .can_focus(true)
            .max_length(PAIRING_CODE_LEN as i32)
            .halign(gtk4::Align::Fill)
            .valign(gtk4::Align::Fill)
            .build();
        entry.add_css_class("code-box-entry-overlay");

        let overlay = gtk4::Overlay::builder()
            .halign(gtk4::Align::Center)
            .valign(gtk4::Align::Center)
            .child(&boxes_box)
            .build();
        overlay.add_overlay(&entry);

        let click_gesture = gtk4::GestureClick::new();
        let e_click = entry.clone();
        click_gesture.connect_pressed(move |_, _, _, _| {
            e_click.grab_focus();
            e_click.select_region(-1, -1);
            e_click.set_position(-1);
        });
        overlay.add_controller(click_gesture);

        let is_focused = Rc::new(Cell::new(false));
        let focus_ctrl = gtk4::EventControllerFocus::new();
        {
            let foc = Rc::clone(&is_focused);
            let e_ent = entry.clone();
            let lbls = boxes.clone();
            focus_ctrl.connect_enter(move |_| {
                foc.set(true);
                e_ent.select_region(-1, -1);
                e_ent.set_position(-1);
                render_code_boxes(&lbls, &e_ent.text(), true);
            });
        }
        {
            let foc = Rc::clone(&is_focused);
            let e_ent = entry.clone();
            let lbls = boxes.clone();
            focus_ctrl.connect_leave(move |_| {
                foc.set(false);
                render_code_boxes(&lbls, &e_ent.text(), false);
            });
        }
        entry.add_controller(focus_ctrl);

        Self {
            overlay,
            labels: boxes,
            entry,
            is_focused,
        }
    }

    fn update(&self, code: &str) {
        render_code_boxes(&self.labels, code, self.is_focused.get());
    }

    fn clear(&self) {
        self.entry.set_text("");
        self.update("");
    }
}

/// Unified logic for determining whether the Sign button can be enabled.
fn compute_sign_sensitivity(state: &UiState, pin_len: usize) -> bool {
    (state.has_local_card || state.phone.is_some())
        && state.signature_supported
        && !state.pdf_documents.is_empty()
        && (MIN_PIN2_DIGITS..=MAX_PIN2_DIGITS).contains(&pin_len)
        && !state.busy
}

// ---------------------------------------------------------------------------
// Main Status View Widgets
// ---------------------------------------------------------------------------

struct StatusWidgets {
    // Top bar / Remote Use
    key_button: gtk4::Button,
    key_icon: gtk4::Image,
    remote_action: Rc<RefCell<RemoteButtonAction>>,

    // Identity Section
    normal_identity_box: gtk4::Box,
    holder_name_label: gtk4::Label,
    status_pill_label: gtk4::Label,

    // Pairing prompt view
    pairing_box: gtk4::Box,
    pairing_code_boxes: CodeBoxes,
    pairing_status_label: gtk4::Label,
    pairing_spinner: gtk4::Spinner,

    // Document Section
    drop_invitation_box: gtk4::Box,
    document_pile_box: gtk4::Box,
    doc_list: gtk4::ListBox,

    // Format & PIN 2 & Action
    btn_format_pades: gtk4::CheckButton,
    btn_format_asice: gtk4::CheckButton,
    pin2_entry: gtk4::PasswordEntry,
    sign_spinner: gtk4::Spinner,
    sign_note_label: gtk4::Label,
    sign_button: gtk4::Button,

    // State Trackers
    current_ui_state: Rc<RefCell<UiState>>,
    last_pdf_documents: RefCell<Vec<PathBuf>>,
    showing_pairing: Rc<RefCell<bool>>,
}

// ---------------------------------------------------------------------------
// PIN Codes Auxiliary Window Widgets
// ---------------------------------------------------------------------------

struct PinCodesWidgets {
    attempts_bar: gtk4::Box,
    attempts_label: gtk4::Label,
    change_pin1_button: gtk4::Button,
    change_pin2_button: gtk4::Button,
    unblock_button: gtk4::Button,
    activate_button: gtk4::Button,
}

// ---------------------------------------------------------------------------
// GTK4 Presentation Driver
// ---------------------------------------------------------------------------

/// Presentation driver using GTK 4.
pub struct Gtk4Driver {
    initial_tab: Option<String>,
    receiver: Option<std::sync::mpsc::Receiver<UiState>>,
}

impl std::fmt::Debug for Gtk4Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gtk4Driver")
            .field("initial_tab", &self.initial_tab)
            .finish_non_exhaustive()
    }
}

/// Notification callback invoked on state changes.
pub type StateChangeCallback = Box<dyn Fn(&UiState) + Send + Sync + 'static>;

impl Gtk4Driver {
    /// Set the tab to display when the window opens (`identity`, `pins`, `sign`, `phone`).
    pub fn set_initial_tab(&mut self, tab: &str) {
        self.initial_tab = Some(tab.to_string());
    }

    /// Opens the window on the Phone tab with the code boxes focused.
    pub fn open_on_phone_tab(&mut self) {
        self.set_initial_tab("phone");
    }

    /// Construct a new driver and its state notification callback.
    pub fn create() -> (Self, StateChangeCallback) {
        let (sender, receiver) = std::sync::mpsc::channel::<UiState>();
        let on_state_change: StateChangeCallback = Box::new(move |state: &UiState| {
            let _ = sender.send(state.clone());
        });

        let driver = Self {
            initial_tab: None,
            receiver: Some(receiver),
        };

        (driver, on_state_change)
    }

    /// Update status widgets with new [`UiState`].
    fn apply_status_state(sw: &StatusWidgets, state: &UiState) {
        *sw.current_ui_state.borrow_mut() = state.clone();

        // 1. RemoteUseButton update
        if state.has_local_card {
            *sw.remote_action.borrow_mut() = RemoteButtonAction::OpenPinCodes;
            sw.key_icon.set_icon_name(Some("dialog-password-symbolic"));
            sw.key_button.set_tooltip_text(Some("PIN Codes"));
            sw.key_button.remove_css_class("apple-circle-button-active");
            sw.key_button.set_sensitive(!state.busy);
        } else if let Some(ref phone) = state.phone {
            *sw.remote_action.borrow_mut() = RemoteButtonAction::ForgetPhone;
            sw.key_icon.set_icon_name(Some("network-wireless-symbolic"));
            sw.key_button
                .set_tooltip_text(Some(&format!("{} connected (click to forget)", phone.name)));
            sw.key_button.add_css_class("apple-circle-button-active");
            sw.key_button.set_sensitive(!state.busy);
        } else {
            *sw.remote_action.borrow_mut() = RemoteButtonAction::TogglePairing;
            sw.key_icon.set_icon_name(Some("network-wireless-symbolic"));
            sw.key_button.set_tooltip_text(Some("Pair Phone"));
            sw.key_button.remove_css_class("apple-circle-button-active");
            sw.key_button.set_sensitive(!state.busy);
        }

        // 2. Identity Card View (Pairing Prompt vs Normal Identity Line)
        let is_pairing =
            *sw.showing_pairing.borrow() || (state.pairing.is_some() && !state.has_local_card);
        if is_pairing {
            sw.normal_identity_box.set_visible(false);
            sw.pairing_box.set_visible(true);

            if let Some(ref pairing) = state.pairing {
                sw.pairing_code_boxes.update(&pairing.code);
                sw.pairing_status_label.set_text(&pairing.status);
            } else {
                sw.pairing_code_boxes
                    .update(&sw.pairing_code_boxes.entry.text());
                sw.pairing_status_label.set_text(&state.status_message);
            }
            if state.busy {
                sw.pairing_spinner.start();
                sw.pairing_spinner.set_visible(true);
            } else {
                sw.pairing_spinner.stop();
                sw.pairing_spinner.set_visible(false);
            }
        } else {
            sw.pairing_box.set_visible(false);
            sw.normal_identity_box.set_visible(true);

            if state.has_local_card {
                if let Some(card) = state.cards.first() {
                    let name = card.display_name();
                    sw.holder_name_label.set_text(&name);
                    sw.holder_name_label
                        .remove_css_class("apple-secondary-text");
                    sw.holder_name_label.remove_css_class("apple-warning-text");
                    sw.status_pill_label.set_text("Local Card");
                    sw.status_pill_label
                        .set_css_classes(&["status-pill", "status-pill-green"]);
                } else if state.busy {
                    sw.holder_name_label.set_text("Reading information…");
                    sw.holder_name_label
                        .set_css_classes(&["apple-secondary-text"]);
                    sw.status_pill_label.set_text("Reading");
                    sw.status_pill_label
                        .set_css_classes(&["status-pill", "status-pill-orange"]);
                } else {
                    sw.holder_name_label
                        .set_text("Card detected, not ready - if this lasts, re-insert it");
                    sw.holder_name_label
                        .set_css_classes(&["apple-warning-text"]);
                    sw.status_pill_label.set_text("Not Ready");
                    sw.status_pill_label
                        .set_css_classes(&["status-pill", "status-pill-orange"]);
                }
            } else if let Some(ref phone) = state.phone {
                if let Some(card) = state.cards.first() {
                    let name = format!("{} (via phone)", card.display_name());
                    sw.holder_name_label.set_text(&name);
                } else {
                    sw.holder_name_label
                        .set_text(&format!("Connected to {}", phone.name));
                }
                sw.holder_name_label
                    .remove_css_class("apple-secondary-text");
                sw.holder_name_label.remove_css_class("apple-warning-text");
                sw.status_pill_label.set_text("Via Phone");
                sw.status_pill_label
                    .set_css_classes(&["status-pill", "status-pill-green"]);
            } else if state.reader_connected {
                sw.holder_name_label
                    .set_text("Insert the card into the reader.");
                sw.holder_name_label
                    .set_css_classes(&["apple-secondary-text"]);
                sw.status_pill_label.set_text("No Card");
                sw.status_pill_label
                    .set_css_classes(&["status-pill", "status-pill-gray"]);
            } else {
                sw.holder_name_label.set_text("Connect a card reader.");
                sw.holder_name_label
                    .set_css_classes(&["apple-secondary-text"]);
                sw.status_pill_label.set_text("No Reader");
                sw.status_pill_label
                    .set_css_classes(&["status-pill", "status-pill-gray"]);
            }
        }

        // 3. Document Signing Section
        let has_docs = !state.pdf_documents.is_empty();
        sw.drop_invitation_box.set_visible(!has_docs);
        sw.document_pile_box.set_visible(has_docs);

        if has_docs {
            let mut last = sw.last_pdf_documents.borrow_mut();
            if *last != state.pdf_documents {
                *last = state.pdf_documents.clone();
                while let Some(child) = sw.doc_list.first_child() {
                    sw.doc_list.remove(&child);
                }
                for doc in &state.pdf_documents {
                    let row = gtk4::ListBoxRow::builder().build();
                    let row_box = gtk4::Box::builder()
                        .orientation(gtk4::Orientation::Horizontal)
                        .spacing(8)
                        .margin_top(4)
                        .margin_bottom(4)
                        .margin_start(6)
                        .margin_end(6)
                        .build();

                    let icon = gtk4::Image::from_icon_name("x-office-document-symbolic");
                    icon.set_pixel_size(16);

                    let name = doc
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("document.pdf");
                    let name_label = gtk4::Label::builder()
                        .label(name)
                        .hexpand(true)
                        .halign(gtk4::Align::Start)
                        .ellipsize(gtk4::pango::EllipsizeMode::Middle)
                        .build();

                    row_box.append(&icon);
                    row_box.append(&name_label);
                    row.set_child(Some(&row_box));
                    sw.doc_list.append(&row);
                }
            }

            match state.sign_format {
                SignFormat::Pades => sw.btn_format_pades.set_active(true),
                SignFormat::AsicE => sw.btn_format_asice.set_active(true),
            }
        }

        // Update unified sign button sensitivity
        Self::update_sign_button_sensitivity(sw);

        if state.busy {
            sw.sign_spinner.start();
            sw.sign_spinner.set_visible(true);
            sw.sign_note_label.set_text("Signing document…");
        } else {
            sw.sign_spinner.stop();
            sw.sign_spinner.set_visible(false);
            if let Some(ref res) = state.sign_result {
                sw.sign_note_label.set_text(res);
            } else {
                sw.sign_note_label.set_text("");
            }
        }
    }

    /// Single unified source of truth for Sign button sensitivity.
    fn update_sign_button_sensitivity(sw: &StatusWidgets) {
        let pin_len = sw.pin2_entry.text().chars().count();
        let can_sign = compute_sign_sensitivity(&sw.current_ui_state.borrow(), pin_len);
        sw.sign_button.set_sensitive(can_sign);
    }

    /// Update PIN Codes auxiliary window with [`UiState`].
    fn apply_pincodes_state(pw: &PinCodesWidgets, state: &UiState) {
        let (p1_text, _) = format_pin_status(state.pin1_status.as_ref(), state.pin1_changed);
        let (p2_text, _) = format_pin_status(state.pin2_status.as_ref(), state.pin2_changed);
        let (puk_text, _) = format_puk_status(state.puk_status.as_ref());
        pw.attempts_label.set_text(&format!(
            "PIN 1: {p1_text}  •  PIN 2: {p2_text}  •  PUK: {puk_text}"
        ));

        let is_below_full = matches!(state.pin1_status, Some(PinStatus::Remaining(r)) if (r.get() as usize) < RETRY_FULL_THRESHOLD)
            || matches!(state.pin2_status, Some(PinStatus::Remaining(r)) if (r.get() as usize) < RETRY_FULL_THRESHOLD)
            || matches!(state.puk_status, Some(PukStatus::Remaining(r)) if (r.get() as usize) < RETRY_FULL_THRESHOLD);
        pw.attempts_bar.set_visible(is_below_full);

        pw.change_pin1_button
            .set_sensitive(state.pin1_change_available && !state.busy);
        pw.change_pin2_button
            .set_sensitive(state.pin2_change_available && !state.busy);
        pw.unblock_button.set_sensitive(
            (state.pin1_unblock_available || state.pin2_unblock_available) && !state.busy,
        );
        pw.activate_button
            .set_sensitive(state.activation_available && !state.busy);
    }

    /// Load Apple macOS Human Interface Guidelines CSS styling into GTK display.
    fn load_css() {
        let provider = gtk4::CssProvider::new();
        provider.load_from_data(
            "
            window {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Helvetica Neue', sans-serif;
            }
            headerbar {
                background-color: #1e1e1e;
                border-bottom: 1px solid rgba(255, 255, 255, 0.08);
                box-shadow: none;
                color: #ffffff;
                min-height: 44px;
            }
            .apple-title {
                font-weight: 600;
                font-size: 14px;
                color: #ffffff;
            }
            .apple-card {
                background-color: #2c2c2e;
                border-radius: 10px;
                border: 1px solid rgba(255, 255, 255, 0.08);
                padding: 14px 16px;
            }
            .apple-warning-card {
                background-color: rgba(255, 159, 10, 0.12);
                border: 1px solid rgba(255, 159, 10, 0.3);
                border-radius: 8px;
                padding: 8px 12px;
            }
            .apple-card-title {
                font-weight: 600;
                font-size: 13px;
                color: #ffffff;
            }
            .apple-secondary-text {
                color: #98989d;
                font-size: 13px;
            }
            .apple-warning-text {
                color: #ff9f0a;
                font-size: 13px;
                font-weight: 500;
            }
            .apple-drop-invitation {
                border: 1px dashed rgba(255, 255, 255, 0.18);
                border-radius: 8px;
                background-color: rgba(255, 255, 255, 0.02);
                padding: 24px;
            }
            .apple-link-button {
                color: #0a84ff;
                background: transparent;
                border: none;
                box-shadow: none;
                font-size: 13px;
                font-weight: 500;
                padding: 2px 4px;
            }
            .apple-link-button:hover {
                color: #409cff;
                text-decoration: underline;
            }
            .apple-primary-button {
                background-color: #0a84ff;
                color: #ffffff;
                border-radius: 6px;
                font-weight: 600;
                font-size: 13px;
                padding: 6px 16px;
                border: none;
            }
            .apple-primary-button:hover {
                background-color: #0071e3;
            }
            .apple-primary-button:disabled {
                background-color: #3a3a3c;
                color: #636366;
            }
            .apple-circle-button {
                border-radius: 50%;
                min-width: 32px;
                min-height: 32px;
                padding: 6px;
                background-color: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.1);
                color: #ffffff;
            }
            .apple-circle-button:hover {
                background-color: rgba(255, 255, 255, 0.16);
            }
            .apple-circle-button-active {
                background-color: rgba(48, 209, 88, 0.2);
                border-color: rgba(48, 209, 88, 0.5);
                color: #30d158;
            }
            .apple-segmented-group {
                background-color: rgba(255, 255, 255, 0.08);
                border-radius: 8px;
                padding: 2px;
            }
            .apple-segmented-button {
                background: transparent;
                color: #98989d;
                border: none;
                box-shadow: none;
                border-radius: 6px;
                font-size: 12px;
                font-weight: 500;
                padding: 4px 10px;
            }
            .apple-segmented-active {
                background-color: #636366;
                color: #ffffff;
                font-weight: 600;
            }
            .code-box {
                background: #1c1c1e;
                border: 1px solid #3a3a3c;
                border-radius: 8px;
                min-width: 44px;
                min-height: 52px;
                font-size: 24px;
                font-weight: 700;
                color: #ffffff;
            }
            .code-box-filled {
                border-color: #0a84ff;
                background: #2c2c2e;
            }
            .code-box-active {
                border-color: #0a84ff;
                border-width: 2px;
            }
            .code-box-entry-overlay {
                opacity: 0.01;
                background: transparent;
                border: none;
                box-shadow: none;
                caret-color: transparent;
                color: transparent;
            }
            .code-box-entry-overlay:focus {
                opacity: 0.01;
                background: transparent;
                border: none;
                box-shadow: none;
                caret-color: transparent;
                color: transparent;
            }
            .status-pill {
                border-radius: 12px;
                font-size: 11px;
                font-weight: 600;
                padding: 2px 8px;
            }
            .status-pill-green {
                background-color: rgba(48, 209, 88, 0.15);
                color: #30d158;
            }
            .status-pill-orange {
                background-color: rgba(255, 159, 10, 0.15);
                color: #ff9f0a;
            }
            .status-pill-red {
                background-color: rgba(255, 69, 58, 0.15);
                color: #ff453a;
            }
            .status-pill-gray {
                background-color: rgba(142, 142, 147, 0.15);
                color: #8e8e93;
            }
            .apple-doc-list {
                background-color: transparent;
            }
            passwordentry, entry {
                border-radius: 6px;
                background-color: #1c1c1e;
                border: 1px solid rgba(255, 255, 255, 0.12);
                color: #ffffff;
                padding: 4px 8px;
            }
            passwordentry:focus-within, entry:focus {
                border-color: #0a84ff;
            }
            ",
        );

        if let Some(display) = gdk::Display::default() {
            gtk4::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    }
}

impl UiDriver for Gtk4Driver {
    fn init(&mut self) -> Result<(), GuiCoreError> {
        Ok(())
    }

    fn render(&mut self, _state: &UiState) {}

    fn run(mut self, controller: Arc<RefineIdController>) -> Result<(), GuiCoreError> {
        gtk4::init().map_err(|e| GuiCoreError::Driver(e.to_string()))?;
        Self::load_css();

        let context = glib::MainContext::default();

        // Build main window
        let window = gtk4::ApplicationWindow::builder()
            .title("RefineID")
            .default_width(560)
            .default_height(400)
            .resizable(false)
            .build();

        let header = gtk4::HeaderBar::new();
        header.set_show_title_buttons(true);
        let title_lbl = gtk4::Label::builder()
            .label("RefineID")
            .css_classes(["apple-title"])
            .build();
        header.set_title_widget(Some(&title_lbl));

        let key_button = gtk4::Button::builder()
            .css_classes(["apple-circle-button"])
            .build();
        let key_icon = gtk4::Image::from_icon_name("dialog-password-symbolic");
        key_icon.set_pixel_size(16);
        key_button.set_child(Some(&key_icon));
        header.pack_end(&key_button);

        window.set_titlebar(Some(&header));

        // Build auxiliary PIN Codes window
        let (pincodes_win, pw) = build_pincodes_window(&controller, &window);
        let pw_cell = Rc::new(RefCell::new(pw));

        // Build main Status View
        let (main_box, sw) =
            build_status_view(&controller, &window, &pincodes_win, key_button, key_icon);
        let sw_cell = Rc::new(RefCell::new(sw));

        window.set_child(Some(&main_box));

        // Initial state render
        Self::apply_status_state(&sw_cell.borrow(), &controller.state());
        Self::apply_pincodes_state(&pw_cell.borrow(), &controller.state());

        // Connect reactive state receiver
        if let Some(receiver) = self.receiver.take() {
            let sw_poll = Rc::clone(&sw_cell);
            let pw_poll = Rc::clone(&pw_cell);
            glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
                while let Ok(state) = receiver.try_recv() {
                    Self::apply_status_state(&sw_poll.borrow(), &state);
                    Self::apply_pincodes_state(&pw_poll.borrow(), &state);
                }
                glib::ControlFlow::Continue
            });
        }

        // Handle initial tab selection
        if let Some(ref tab) = self.initial_tab {
            match tab.as_str() {
                "phone" | "pair" => {
                    *sw_cell.borrow().showing_pairing.borrow_mut() = true;
                    sw_cell.borrow().normal_identity_box.set_visible(false);
                    sw_cell.borrow().pairing_box.set_visible(true);
                    let e = sw_cell.borrow().pairing_code_boxes.entry.clone();
                    glib::idle_add_local_once(move || {
                        e.grab_focus();
                    });
                }
                "pins" | "pin" => {
                    pincodes_win.present();
                }
                _ => {}
            }
        }

        let main_loop = glib::MainLoop::new(Some(&context), false);
        let loop_for_close = main_loop.clone();

        window.connect_close_request(move |_| {
            loop_for_close.quit();
            glib::Propagation::Proceed
        });

        window.present();
        main_loop.run();

        controller.stop();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// View Builders: Main Status View
// ---------------------------------------------------------------------------

fn build_status_view(
    controller: &Arc<RefineIdController>,
    window: &gtk4::ApplicationWindow,
    pincodes_win: &gtk4::Window,
    key_button: gtk4::Button,
    key_icon: gtk4::Image,
) -> (gtk4::Box, StatusWidgets) {
    let main_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(14)
        .margin_top(20)
        .margin_bottom(20)
        .margin_start(24)
        .margin_end(24)
        .build();

    let remote_action = Rc::new(RefCell::new(RemoteButtonAction::TogglePairing));

    // -----------------------------------------------------------------------
    // Card 1: Identity / Status
    // -----------------------------------------------------------------------
    let identity_card = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(8)
        .build();
    identity_card.add_css_class("apple-card");

    // Normal identity row
    let normal_identity_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .build();

    let id_icon = gtk4::Image::from_icon_name("avatar-default-symbolic");
    id_icon.set_pixel_size(20);

    let holder_name_label = gtk4::Label::builder()
        .label("Connect a card reader.")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .ellipsize(gtk4::pango::EllipsizeMode::End)
        .build();
    holder_name_label.add_css_class("apple-secondary-text");

    let status_pill_label = gtk4::Label::builder().label("No Card").build();
    status_pill_label.set_css_classes(&["status-pill", "status-pill-gray"]);

    normal_identity_box.append(&id_icon);
    normal_identity_box.append(&holder_name_label);
    normal_identity_box.append(&status_pill_label);

    // Pairing prompt view
    let pairing_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(10)
        .visible(false)
        .build();

    let pairing_prompt_lbl = gtk4::Label::builder()
        .label("Open RefineID remote access on your phone and enter the pairing code:")
        .halign(gtk4::Align::Start)
        .wrap(true)
        .build();
    pairing_prompt_lbl.add_css_class("apple-secondary-text");

    let pairing_code_boxes = CodeBoxes::new();
    let pairing_status_label = gtk4::Label::builder()
        .label("")
        .halign(gtk4::Align::Center)
        .build();
    pairing_status_label.add_css_class("apple-secondary-text");

    let pairing_spinner = gtk4::Spinner::builder()
        .halign(gtk4::Align::Center)
        .visible(false)
        .build();

    let btn_cancel_pair = gtk4::Button::builder()
        .label("Cancel")
        .halign(gtk4::Align::Center)
        .build();
    btn_cancel_pair.add_css_class("apple-link-button");

    pairing_box.append(&pairing_prompt_lbl);
    pairing_box.append(&pairing_code_boxes.overlay);
    pairing_box.append(&pairing_status_label);
    pairing_box.append(&pairing_spinner);
    pairing_box.append(&btn_cancel_pair);

    identity_card.append(&normal_identity_box);
    identity_card.append(&pairing_box);
    main_box.append(&identity_card);

    // -----------------------------------------------------------------------
    // Card 2: Document Signing Section
    // -----------------------------------------------------------------------
    let signing_card = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .build();
    signing_card.add_css_class("apple-card");

    // Drop Invitation (empty state)
    let drop_invitation_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(6)
        .halign(gtk4::Align::Fill)
        .valign(gtk4::Align::Center)
        .height_request(160)
        .build();
    drop_invitation_box.add_css_class("apple-drop-invitation");

    let doc_icon = gtk4::Image::from_icon_name("document-new-symbolic");
    doc_icon.set_pixel_size(32);
    doc_icon.set_opacity(0.6);

    let drop_label = gtk4::Label::builder()
        .label("Drop documents here to sign them")
        .halign(gtk4::Align::Center)
        .build();
    drop_label.add_css_class("apple-secondary-text");

    let btn_choose_empty = gtk4::Button::builder()
        .label("Choose…")
        .halign(gtk4::Align::Center)
        .build();
    btn_choose_empty.add_css_class("apple-link-button");

    drop_invitation_box.append(&doc_icon);
    drop_invitation_box.append(&drop_label);
    drop_invitation_box.append(&btn_choose_empty);

    // Document Pile (queued state)
    let document_pile_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(10)
        .visible(false)
        .build();

    let doc_scroller = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .max_content_height(132)
        .propagate_natural_height(true)
        .build();

    let doc_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .build();
    doc_list.add_css_class("apple-doc-list");
    doc_scroller.set_child(Some(&doc_list));

    let pile_footer = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .halign(gtk4::Align::End)
        .build();

    let btn_add_more = gtk4::Button::builder().label("Add…").build();
    btn_add_more.add_css_class("apple-link-button");

    let btn_clear_docs = gtk4::Button::builder().label("Clear").build();
    btn_clear_docs.add_css_class("apple-link-button");

    pile_footer.append(&btn_add_more);
    pile_footer.append(&btn_clear_docs);

    let divider = gtk4::Separator::new(gtk4::Orientation::Horizontal);

    // Format selection
    let format_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .build();
    let format_label = gtk4::Label::builder()
        .label("Format")
        .halign(gtk4::Align::Start)
        .build();
    format_label.add_css_class("apple-card-title");

    let btn_format_pades = gtk4::CheckButton::builder()
        .label("PAdES")
        .active(true)
        .build();
    let btn_format_asice = gtk4::CheckButton::builder()
        .label("ASiC-E")
        .group(&btn_format_pades)
        .build();

    format_row.append(&format_label);
    format_row.append(&btn_format_pades);
    format_row.append(&btn_format_asice);

    // PIN 2 Row
    let pin2_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .build();
    let pin2_label = gtk4::Label::builder()
        .label("PIN 2")
        .halign(gtk4::Align::Start)
        .width_request(60)
        .build();
    pin2_label.add_css_class("apple-card-title");

    let pin2_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Qualified Signature PIN")
        .show_peek_icon(true)
        .hexpand(true)
        .build();

    pin2_row.append(&pin2_label);
    pin2_row.append(&pin2_entry);

    // Action row
    let action_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .margin_top(4)
        .build();

    let sign_spinner = gtk4::Spinner::builder().visible(false).build();
    let sign_note_label = gtk4::Label::builder()
        .label("")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    sign_note_label.add_css_class("apple-secondary-text");

    let sign_button = gtk4::Button::builder()
        .label("Sign…")
        .halign(gtk4::Align::End)
        .sensitive(false)
        .build();
    sign_button.add_css_class("apple-primary-button");

    action_row.append(&sign_spinner);
    action_row.append(&sign_note_label);
    action_row.append(&sign_button);

    document_pile_box.append(&doc_scroller);
    document_pile_box.append(&pile_footer);
    document_pile_box.append(&divider);
    document_pile_box.append(&format_row);
    document_pile_box.append(&pin2_row);
    document_pile_box.append(&action_row);

    signing_card.append(&drop_invitation_box);
    signing_card.append(&document_pile_box);

    // Attach DropTarget across the entire signing card (empty drop zone or active pile)
    let drop_target = gtk4::DropTarget::new(gio::File::static_type(), gdk::DragAction::COPY);
    {
        let c_drop = Arc::clone(controller);
        drop_target.connect_drop(move |_, value, _, _| {
            if let Ok(file) = value.get::<gio::File>()
                && let Some(path) = file.path()
            {
                c_drop.handle_intent(UserIntent::AddDocuments(vec![path]));
                return true;
            }
            false
        });
    }
    signing_card.add_controller(drop_target);

    main_box.append(&signing_card);

    // Wire up events
    let showing_pairing = Rc::new(RefCell::new(false));

    // Key button (titlebar)
    {
        let pw_win = pincodes_win.clone();
        let sp = Rc::clone(&showing_pairing);
        let n_box = normal_identity_box.clone();
        let p_box = pairing_box.clone();
        let c_boxes = pairing_code_boxes.entry.clone();
        let c_key = Arc::clone(controller);
        let win_clone = window.clone();
        let ra_action = Rc::clone(&remote_action);
        key_button.connect_clicked(move |_| match *ra_action.borrow() {
            RemoteButtonAction::OpenPinCodes => {
                pw_win.present();
            }
            RemoteButtonAction::TogglePairing => {
                let cur = *sp.borrow();
                *sp.borrow_mut() = !cur;
                n_box.set_visible(cur);
                p_box.set_visible(!cur);
                if !cur {
                    c_boxes.grab_focus();
                }
            }
            RemoteButtonAction::ForgetPhone => {
                let c_forget = Arc::clone(&c_key);
                show_confirm(
                    &win_clone,
                    "Disconnect and forget this paired phone?",
                    move || {
                        c_forget.handle_intent(UserIntent::ForgetPhone);
                    },
                );
            }
        });
    }

    // Cancel pairing button
    {
        let sp = Rc::clone(&showing_pairing);
        let n_box = normal_identity_box.clone();
        let p_box = pairing_box.clone();
        let cb = pairing_code_boxes.clone();
        btn_cancel_pair.connect_clicked(move |_| {
            *sp.borrow_mut() = false;
            p_box.set_visible(false);
            n_box.set_visible(true);
            cb.clear();
        });
    }

    // Attach key listener to window to focus entry automatically on any key press when pairing
    {
        let key_ctrl = gtk4::EventControllerKey::new();
        let e_key = pairing_code_boxes.entry.clone();
        let foc = Rc::clone(&pairing_code_boxes.is_focused);
        let sp = Rc::clone(&showing_pairing);
        key_ctrl.connect_key_pressed(move |_, _, _, _| {
            if *sp.borrow() && !foc.get() {
                e_key.grab_focus();
                e_key.select_region(-1, -1);
                e_key.set_position(-1);
            }
            glib::Propagation::Proceed
        });
        window.add_controller(key_ctrl);
    }

    // Pairing code entry
    {
        let c = Arc::clone(controller);
        let last_submitted: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
        let cb = pairing_code_boxes.clone();
        pairing_code_boxes.entry.connect_changed(move |e| {
            let cur = e.text();
            let filtered = filter_pairing_code(&cur);
            if cur != filtered {
                e.set_text(&filtered);
                e.select_region(-1, -1);
                e.set_position(-1);
                return;
            }
            cb.update(&filtered);
            if filtered.chars().count() == PAIRING_CODE_LEN {
                let mut prev = last_submitted.borrow_mut();
                if prev.as_deref() == Some(&filtered) {
                    return;
                }
                *prev = Some(filtered.clone());
                c.handle_intent(UserIntent::StartPairing { code: filtered });
            } else {
                *last_submitted.borrow_mut() = None;
            }
        });
    }

    // File chooser helper
    let choose_files = {
        let c = Arc::clone(controller);
        let win = window.clone();
        move || {
            let chooser = gtk4::FileChooserNative::new(
                Some("Select Documents to Sign"),
                Some(&win),
                gtk4::FileChooserAction::Open,
                Some("Choose"),
                Some("Cancel"),
            );
            chooser.set_select_multiple(true);
            let filter = gtk4::FileFilter::new();
            filter.set_name(Some("PDF Documents (*.pdf)"));
            filter.add_mime_type("application/pdf");
            filter.add_pattern("*.pdf");
            filter.add_pattern("*.PDF");
            chooser.add_filter(&filter);

            let c_open = Arc::clone(&c);
            chooser.connect_response(move |d, resp| {
                if resp == gtk4::ResponseType::Accept {
                    let files = d.files();
                    let mut paths = Vec::new();
                    for i in 0..files.n_items() {
                        if let Some(file) =
                            files.item(i).and_then(|o| o.downcast::<gio::File>().ok())
                            && let Some(p) = file.path()
                        {
                            paths.push(p);
                        }
                    }
                    if !paths.is_empty() {
                        c_open.handle_intent(UserIntent::AddDocuments(paths));
                    }
                }
            });
            chooser.show();
        }
    };

    let cf1 = choose_files.clone();
    btn_choose_empty.connect_clicked(move |_| cf1());
    let cf2 = choose_files;
    btn_add_more.connect_clicked(move |_| cf2());

    // Clear documents (immediate Apple HIG action)
    {
        let c = Arc::clone(controller);
        btn_clear_docs.connect_clicked(move |_| {
            c.handle_intent(UserIntent::ClearDocuments);
        });
    }

    // Format switches
    {
        let c = Arc::clone(controller);
        btn_format_pades.connect_toggled(move |btn| {
            if btn.is_active() {
                c.handle_intent(UserIntent::SetSignFormat(SignFormat::Pades));
            }
        });
    }
    {
        let c = Arc::clone(controller);
        btn_format_asice.connect_toggled(move |btn| {
            if btn.is_active() {
                c.handle_intent(UserIntent::SetSignFormat(SignFormat::AsicE));
            }
        });
    }

    // PIN 2 Filter & Sign button sensitivity
    let current_ui_state = Rc::new(RefCell::new(UiState::default()));
    {
        let s_btn = sign_button.clone();
        let state_ref = Rc::clone(&current_ui_state);
        pin2_entry.connect_changed(move |e| {
            let cur = e.text();
            let filtered = filter_digits(&cur, MAX_PIN2_DIGITS);
            if cur != filtered {
                e.set_text(&filtered);
                return;
            }
            let pin_len = filtered.chars().count();
            let can_sign = compute_sign_sensitivity(&state_ref.borrow(), pin_len);
            s_btn.set_sensitive(can_sign);
        });
    }

    // Sign action
    {
        let c = Arc::clone(controller);
        let p2_in = pin2_entry.clone();
        let win = window.clone();
        sign_button.connect_clicked(move |_| {
            let pin_text = p2_in.text();
            let count = pin_text.chars().count();
            if !(MIN_PIN2_DIGITS..=MAX_PIN2_DIGITS).contains(&count) {
                p2_in.set_text("");
                show_alert(
                    &win,
                    &format!(
                        "PIN 2 must be between {MIN_PIN2_DIGITS} and {MAX_PIN2_DIGITS} digits."
                    ),
                );
                return;
            }
            if let Some(pin_bytes) = to_pin_bytes(&pin_text) {
                p2_in.set_text("");
                c.handle_intent(UserIntent::SignDocuments { pin2: pin_bytes });
            }
        });
    }

    (
        main_box,
        StatusWidgets {
            key_button,
            key_icon,
            remote_action,
            normal_identity_box,
            holder_name_label,
            status_pill_label,
            pairing_box,
            pairing_code_boxes,
            pairing_status_label,
            pairing_spinner,
            drop_invitation_box,
            document_pile_box,
            doc_list,
            btn_format_pades,
            btn_format_asice,
            pin2_entry,
            sign_spinner,
            sign_note_label,
            sign_button,
            current_ui_state,
            last_pdf_documents: RefCell::new(Vec::new()),
            showing_pairing,
        },
    )
}

// ---------------------------------------------------------------------------
// View Builders: Auxiliary PIN Codes Window
// ---------------------------------------------------------------------------

fn build_pincodes_window(
    controller: &Arc<RefineIdController>,
    parent: &gtk4::ApplicationWindow,
) -> (gtk4::Window, PinCodesWidgets) {
    let window = gtk4::Window::builder()
        .title("PIN Codes")
        .transient_for(parent)
        .modal(false)
        .default_width(500)
        .default_height(420)
        .hide_on_close(true)
        .build();

    let root = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(14)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(20)
        .margin_end(20)
        .build();

    // Attempts warning bar (shown only if retry count < pristine threshold)
    let attempts_bar = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .margin_bottom(4)
        .visible(false)
        .build();
    attempts_bar.add_css_class("apple-warning-card");

    let warn_icon = gtk4::Image::from_icon_name("dialog-warning-symbolic");
    warn_icon.set_pixel_size(16);

    let attempts_label = gtk4::Label::builder()
        .label("PIN 1: 5 / 5  •  PIN 2: 5 / 5  •  PUK: 5 remaining")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    attempts_label.add_css_class("apple-secondary-text");

    attempts_bar.append(&warn_icon);
    attempts_bar.append(&attempts_label);
    root.append(&attempts_bar);

    // Segmented Task Switcher
    let task_switcher = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(2)
        .halign(gtk4::Align::Center)
        .build();
    task_switcher.add_css_class("apple-segmented-group");

    let btn_task_p1 = gtk4::ToggleButton::builder()
        .label("Change PIN 1")
        .active(true)
        .build();
    let btn_task_p2 = gtk4::ToggleButton::builder().label("Change PIN 2").build();
    let btn_task_unblock = gtk4::ToggleButton::builder().label("Unblock PIN").build();
    let btn_task_activate = gtk4::ToggleButton::builder().label("Activate Card").build();

    btn_task_p1.set_css_classes(&["apple-segmented-button", "apple-segmented-active"]);
    btn_task_p2.add_css_class("apple-segmented-button");
    btn_task_unblock.add_css_class("apple-segmented-button");
    btn_task_activate.add_css_class("apple-segmented-button");

    task_switcher.append(&btn_task_p1);
    task_switcher.append(&btn_task_p2);
    task_switcher.append(&btn_task_unblock);
    task_switcher.append(&btn_task_activate);
    root.append(&task_switcher);

    // Task Stack
    let task_stack = gtk4::Stack::builder()
        .transition_type(gtk4::StackTransitionType::Crossfade)
        .build();

    // 1. Change PIN 1
    let p1_form = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(10)
        .margin_top(8)
        .build();
    p1_form.add_css_class("apple-card");

    let p1_current_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Current PIN 1")
        .show_peek_icon(true)
        .build();
    let p1_new_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("New PIN 1 (4..12 digits)")
        .show_peek_icon(true)
        .build();
    let p1_confirm_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Confirm New PIN 1")
        .show_peek_icon(true)
        .build();
    let change_pin1_button = gtk4::Button::builder().label("Change PIN 1").build();
    change_pin1_button.add_css_class("apple-primary-button");

    p1_form.append(&p1_current_entry);
    p1_form.append(&p1_new_entry);
    p1_form.append(&p1_confirm_entry);
    p1_form.append(&change_pin1_button);
    task_stack.add_named(&p1_form, Some("pin1"));

    // 2. Change PIN 2
    let p2_form = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(10)
        .margin_top(8)
        .build();
    p2_form.add_css_class("apple-card");

    let p2_current_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Current PIN 2")
        .show_peek_icon(true)
        .build();
    let p2_new_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("New PIN 2 (6..12 digits)")
        .show_peek_icon(true)
        .build();
    let p2_confirm_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Confirm New PIN 2")
        .show_peek_icon(true)
        .build();
    let change_pin2_button = gtk4::Button::builder().label("Change PIN 2").build();
    change_pin2_button.add_css_class("apple-primary-button");

    p2_form.append(&p2_current_entry);
    p2_form.append(&p2_new_entry);
    p2_form.append(&p2_confirm_entry);
    p2_form.append(&change_pin2_button);
    task_stack.add_named(&p2_form, Some("pin2"));

    // 3. Unblock PIN
    let unblock_form = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(10)
        .margin_top(8)
        .build();
    unblock_form.add_css_class("apple-card");

    let unblock_slot_combo =
        gtk4::DropDown::from_strings(&["PIN 1 (Authentication)", "PIN 2 (Signature)"]);
    let puk_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("PUK Code")
        .show_peek_icon(true)
        .build();
    let unblock_new_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("New PIN")
        .show_peek_icon(true)
        .build();
    let unblock_confirm_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Confirm New PIN")
        .show_peek_icon(true)
        .build();
    let unblock_button = gtk4::Button::builder().label("Unblock PIN").build();
    unblock_button.add_css_class("apple-primary-button");

    unblock_form.append(&unblock_slot_combo);
    unblock_form.append(&puk_entry);
    unblock_form.append(&unblock_new_entry);
    unblock_form.append(&unblock_confirm_entry);
    unblock_form.append(&unblock_button);
    task_stack.add_named(&unblock_form, Some("unblock"));

    // 4. Activate Card
    let act_form = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(10)
        .margin_top(8)
        .build();
    act_form.add_css_class("apple-card");

    let act_code_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Activation Code")
        .show_peek_icon(true)
        .build();
    let act_p1_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("New PIN 1")
        .show_peek_icon(true)
        .build();
    let act_p1_confirm_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Confirm New PIN 1")
        .show_peek_icon(true)
        .build();
    let act_p2_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("New PIN 2")
        .show_peek_icon(true)
        .build();
    let act_p2_confirm_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Confirm New PIN 2")
        .show_peek_icon(true)
        .build();
    let activate_button = gtk4::Button::builder().label("Activate Card").build();
    activate_button.add_css_class("apple-primary-button");

    act_form.append(&act_code_entry);
    act_form.append(&act_p1_entry);
    act_form.append(&act_p1_confirm_entry);
    act_form.append(&act_p2_entry);
    act_form.append(&act_p2_confirm_entry);
    act_form.append(&activate_button);
    task_stack.add_named(&act_form, Some("activate"));

    root.append(&task_stack);

    // Close button
    let btn_close = gtk4::Button::builder()
        .label("Done")
        .halign(gtk4::Align::End)
        .build();
    btn_close.add_css_class("apple-primary-button");
    let w_close = window.clone();
    btn_close.connect_clicked(move |_| {
        w_close.set_visible(false);
    });
    root.append(&btn_close);

    window.set_child(Some(&root));

    // Wire segmented switcher
    {
        let stack = task_stack.clone();
        let b1 = btn_task_p1.clone();
        let b2 = btn_task_p2.clone();
        let b3 = btn_task_unblock.clone();
        let b4 = btn_task_activate.clone();

        let update_btns = move |active_idx: usize| {
            let btns = [&b1, &b2, &b3, &b4];
            for (idx, b) in btns.iter().enumerate() {
                if idx == active_idx {
                    b.set_active(true);
                    b.add_css_class("apple-segmented-active");
                } else {
                    b.set_active(false);
                    b.remove_css_class("apple-segmented-active");
                }
            }
        };

        let u1 = update_btns.clone();
        let s1 = stack.clone();
        btn_task_p1.connect_toggled(move |b| {
            if b.is_active() {
                u1(0);
                s1.set_visible_child_name("pin1");
            }
        });

        let u2 = update_btns.clone();
        let s2 = stack.clone();
        btn_task_p2.connect_toggled(move |b| {
            if b.is_active() {
                u2(1);
                s2.set_visible_child_name("pin2");
            }
        });

        let u3 = update_btns.clone();
        let s3 = stack.clone();
        btn_task_unblock.connect_toggled(move |b| {
            if b.is_active() {
                u3(2);
                s3.set_visible_child_name("unblock");
            }
        });

        let u4 = update_btns;
        let s4 = stack;
        btn_task_activate.connect_toggled(move |b| {
            if b.is_active() {
                u4(3);
                s4.set_visible_child_name("activate");
            }
        });
    }

    // Change PIN 1 handler
    {
        let c = Arc::clone(controller);
        let cur_in = p1_current_entry.clone();
        let new_in = p1_new_entry.clone();
        let conf_in = p1_confirm_entry.clone();
        let win = window.clone();
        change_pin1_button.connect_clicked(move |_| {
            let cur_v = cur_in.text();
            let new_v = new_in.text();
            let conf_v = conf_in.text();
            if new_v != conf_v {
                new_in.set_text("");
                conf_in.set_text("");
                show_alert(&win, "New PIN entries do not match.");
                return;
            }
            let count = new_v.chars().count();
            if !(MIN_PIN1_DIGITS..=MAX_PIN1_DIGITS).contains(&count) {
                new_in.set_text("");
                conf_in.set_text("");
                show_alert(
                    &win,
                    &format!(
                        "PIN 1 must be between {MIN_PIN1_DIGITS} and {MAX_PIN1_DIGITS} digits."
                    ),
                );
                return;
            }
            if let (Some(cur_pin), Some(new_pin)) = (to_pin_bytes(&cur_v), to_pin_bytes(&new_v)) {
                cur_in.set_text("");
                new_in.set_text("");
                conf_in.set_text("");
                c.handle_intent(UserIntent::ChangePin {
                    slot: PinManageSlot::Pin1,
                    current_pin: cur_pin,
                    new_pin,
                });
            }
        });
    }

    // Change PIN 2 handler
    {
        let c = Arc::clone(controller);
        let cur_in = p2_current_entry.clone();
        let new_in = p2_new_entry.clone();
        let conf_in = p2_confirm_entry.clone();
        let win = window.clone();
        change_pin2_button.connect_clicked(move |_| {
            let cur_v = cur_in.text();
            let new_v = new_in.text();
            let conf_v = conf_in.text();
            if new_v != conf_v {
                new_in.set_text("");
                conf_in.set_text("");
                show_alert(&win, "New PIN entries do not match.");
                return;
            }
            let count = new_v.chars().count();
            if !(MIN_PIN2_DIGITS..=MAX_PIN2_DIGITS).contains(&count) {
                new_in.set_text("");
                conf_in.set_text("");
                show_alert(
                    &win,
                    &format!(
                        "PIN 2 must be between {MIN_PIN2_DIGITS} and {MAX_PIN2_DIGITS} digits."
                    ),
                );
                return;
            }
            if let (Some(cur_pin), Some(new_pin)) = (to_pin_bytes(&cur_v), to_pin_bytes(&new_v)) {
                cur_in.set_text("");
                new_in.set_text("");
                conf_in.set_text("");
                c.handle_intent(UserIntent::ChangePin {
                    slot: PinManageSlot::Pin2,
                    current_pin: cur_pin,
                    new_pin,
                });
            }
        });
    }

    // Unblock PIN handler
    {
        let c = Arc::clone(controller);
        let slot_dd = unblock_slot_combo.clone();
        let puk_in = puk_entry.clone();
        let new_in = unblock_new_entry.clone();
        let conf_in = unblock_confirm_entry.clone();
        let win = window.clone();
        unblock_button.connect_clicked(move |_| {
            let puk_v = puk_in.text();
            let new_v = new_in.text();
            let conf_v = conf_in.text();
            if new_v != conf_v {
                new_in.set_text("");
                conf_in.set_text("");
                show_alert(&win, "New PIN entries do not match.");
                return;
            }
            let puk_count = puk_v.chars().count();
            if !(MIN_PUK_DIGITS..=MAX_PUK_DIGITS).contains(&puk_count) {
                puk_in.set_text("");
                show_alert(
                    &win,
                    &format!("PUK must be between {MIN_PUK_DIGITS} and {MAX_PUK_DIGITS} digits."),
                );
                return;
            }
            let slot = match slot_dd.selected() {
                1 => PinManageSlot::Pin2,
                _ => PinManageSlot::Pin1,
            };
            let (min_len, max_len) = match slot {
                PinManageSlot::Pin1 => (MIN_PIN1_DIGITS, MAX_PIN1_DIGITS),
                PinManageSlot::Pin2 => (MIN_PIN2_DIGITS, MAX_PIN2_DIGITS),
            };
            let count = new_v.chars().count();
            if !(min_len..=max_len).contains(&count) {
                new_in.set_text("");
                conf_in.set_text("");
                show_alert(
                    &win,
                    &format!("PIN must be between {min_len} and {max_len} digits."),
                );
                return;
            }
            if let (Some(puk_pin), Some(new_pin)) = (to_pin_bytes(&puk_v), to_pin_bytes(&new_v)) {
                puk_in.set_text("");
                new_in.set_text("");
                conf_in.set_text("");
                c.handle_intent(UserIntent::ReactivatePin {
                    slot,
                    puk: puk_pin,
                    new_pin,
                });
            }
        });
    }

    // Activate Card handler
    {
        let c = Arc::clone(controller);
        let code_in = act_code_entry.clone();
        let p1_in = act_p1_entry.clone();
        let p1_c_in = act_p1_confirm_entry.clone();
        let p2_in = act_p2_entry.clone();
        let p2_c_in = act_p2_confirm_entry.clone();
        let win = window.clone();
        activate_button.connect_clicked(move |_| {
            let code_v = code_in.text();
            let p1_v = p1_in.text();
            let p1_c_v = p1_c_in.text();
            let p2_v = p2_in.text();
            let p2_c_v = p2_c_in.text();

            if p1_v != p1_c_v {
                p1_in.set_text("");
                p1_c_in.set_text("");
                show_alert(&win, "PIN 1 entries do not match.");
                return;
            }
            if p2_v != p2_c_v {
                p2_in.set_text("");
                p2_c_in.set_text("");
                show_alert(&win, "PIN 2 entries do not match.");
                return;
            }
            let code_count = code_v.chars().count();
            if !(MIN_ACTIVATION_CODE_DIGITS..=MAX_ACTIVATION_CODE_DIGITS).contains(&code_count) {
                code_in.set_text("");
                show_alert(
                    &win,
                    &format!(
                        "Activation code must be between {MIN_ACTIVATION_CODE_DIGITS} and {MAX_ACTIVATION_CODE_DIGITS} digits."
                    ),
                );
                return;
            }
            let p1_count = p1_v.chars().count();
            if !(MIN_PIN1_DIGITS..=MAX_PIN1_DIGITS).contains(&p1_count) {
                p1_in.set_text("");
                p1_c_in.set_text("");
                show_alert(
                    &win,
                    &format!(
                        "PIN 1 must be between {MIN_PIN1_DIGITS} and {MAX_PIN1_DIGITS} digits."
                    ),
                );
                return;
            }
            let p2_count = p2_v.chars().count();
            if !(MIN_PIN2_DIGITS..=MAX_PIN2_DIGITS).contains(&p2_count) {
                p2_in.set_text("");
                p2_c_in.set_text("");
                show_alert(
                    &win,
                    &format!(
                        "PIN 2 must be between {MIN_PIN2_DIGITS} and {MAX_PIN2_DIGITS} digits."
                    ),
                );
                return;
            }
            if let (Some(code_b), Some(p1_b), Some(p2_b)) = (
                to_pin_bytes(&code_v),
                to_pin_bytes(&p1_v),
                to_pin_bytes(&p2_v),
            ) {
                code_in.set_text("");
                p1_in.set_text("");
                p1_c_in.set_text("");
                p2_in.set_text("");
                p2_c_in.set_text("");
                c.handle_intent(UserIntent::ActivateCard {
                    activation_code: code_b,
                    new_pin1: p1_b,
                    new_pin2: p2_b,
                });
            }
        });
    }

    (
        window,
        PinCodesWidgets {
            attempts_bar,
            attempts_label,
            change_pin1_button,
            change_pin2_button,
            unblock_button,
            activate_button,
        },
    )
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use refineid_lib_core::apdu::status_word::PinRetries;

    #[test]
    fn test_filter_digits() {
        assert_eq!(filter_digits("123456", 6), "123456");
        assert_eq!(filter_digits("12a34b567", 6), "123456");
        assert_eq!(filter_digits("abc", 6), "");
        assert_eq!(filter_digits("123", 6), "123");
        assert_eq!(filter_digits("1234567890", 4), "1234");
    }

    #[test]
    fn test_filter_pairing_code() {
        assert_eq!(filter_pairing_code("7KX4M9"), "7KX4M9");
        assert_eq!(filter_pairing_code("7kx4m9"), "7KX4M9");
        assert_eq!(filter_pairing_code("7-K-X-4-M-9"), "7KX4M9");
        assert_eq!(filter_pairing_code("7KX4M9ZZZZ"), "7KX4M9");
        assert_eq!(filter_pairing_code("ILOUilou"), ""); // I, L, O, U are excluded by Crockford Base32
        assert_eq!(filter_pairing_code("!@#$%^&* "), "");
    }

    #[test]
    fn test_format_pin_status() {
        let retries5 = PinRetries::from_nibble(5).expect("valid nibble");
        let retries4 = PinRetries::from_nibble(4).expect("valid nibble");
        let retries3 = PinRetries::from_nibble(3).expect("valid nibble");
        let retries2 = PinRetries::from_nibble(2).expect("valid nibble");
        let retries1 = PinRetries::from_nibble(1).expect("valid nibble");

        assert_eq!(
            format_pin_status(Some(&PinStatus::Remaining(retries5)), None),
            ("5 / 5".to_string(), "status-pill-green")
        );
        assert_eq!(
            format_pin_status(Some(&PinStatus::Remaining(retries5)), Some(false)),
            ("5 / 5 • Factory".to_string(), "status-pill-green")
        );
        assert_eq!(
            format_pin_status(Some(&PinStatus::Remaining(retries4)), None),
            ("4 / 5".to_string(), "status-pill-orange")
        );
        assert_eq!(
            format_pin_status(Some(&PinStatus::Remaining(retries3)), None),
            ("3 / 5".to_string(), "status-pill-orange")
        );
        assert_eq!(
            format_pin_status(Some(&PinStatus::Remaining(retries2)), None),
            ("2 / 5".to_string(), "status-pill-red")
        );
        assert_eq!(
            format_pin_status(Some(&PinStatus::Remaining(retries1)), None),
            ("1 / 5".to_string(), "status-pill-red")
        );
        assert_eq!(
            format_pin_status(Some(&PinStatus::Locked), None),
            ("Blocked".to_string(), "status-pill-red")
        );
        assert_eq!(
            format_pin_status(Some(&PinStatus::Verified), None),
            ("Verified".to_string(), "status-pill-green")
        );
        assert_eq!(
            format_pin_status(Some(&PinStatus::NoInfo), None),
            ("No retry count".to_string(), "status-pill-gray")
        );
        assert_eq!(
            format_pin_status(Some(&PinStatus::Other(0x6984)), None),
            ("Status 6984".to_string(), "status-pill-gray")
        );
        assert_eq!(
            format_pin_status(None, None),
            ("No card".to_string(), "status-pill-gray")
        );
    }

    #[test]
    fn test_format_puk_status() {
        let retries5 = PinRetries::from_nibble(5).expect("valid nibble");
        let retries4 = PinRetries::from_nibble(4).expect("valid nibble");
        let retries3 = PinRetries::from_nibble(3).expect("valid nibble");
        let retries2 = PinRetries::from_nibble(2).expect("valid nibble");
        let retries1 = PinRetries::from_nibble(1).expect("valid nibble");

        assert_eq!(
            format_puk_status(Some(&PukStatus::Remaining(retries5))),
            ("5 remaining".to_string(), "status-pill-green")
        );
        assert_eq!(
            format_puk_status(Some(&PukStatus::Remaining(retries4))),
            ("4 remaining".to_string(), "status-pill-orange")
        );
        assert_eq!(
            format_puk_status(Some(&PukStatus::Remaining(retries3))),
            ("3 remaining".to_string(), "status-pill-orange")
        );
        assert_eq!(
            format_puk_status(Some(&PukStatus::Remaining(retries2))),
            ("2 remaining".to_string(), "status-pill-red")
        );
        assert_eq!(
            format_puk_status(Some(&PukStatus::Remaining(retries1))),
            ("1 remaining".to_string(), "status-pill-red")
        );
        assert_eq!(
            format_puk_status(Some(&PukStatus::Locked)),
            ("Blocked".to_string(), "status-pill-red")
        );
        assert_eq!(
            format_puk_status(Some(&PukStatus::Invalidated)),
            ("Invalidated".to_string(), "status-pill-red")
        );
        assert_eq!(
            format_puk_status(Some(&PukStatus::NoInfo)),
            ("No count".to_string(), "status-pill-gray")
        );
        assert_eq!(
            format_puk_status(Some(&PukStatus::Other(0x6a80))),
            ("Status 6A80".to_string(), "status-pill-gray")
        );
        assert_eq!(
            format_puk_status(None),
            ("No card".to_string(), "status-pill-gray")
        );
    }

    #[test]
    fn test_compute_sign_sensitivity() {
        let mut state = UiState::default();
        // Default: no docs, no card -> false
        assert!(!compute_sign_sensitivity(&state, 6));

        // Add local card and signature support
        state.has_local_card = true;
        state.signature_supported = true;
        assert!(!compute_sign_sensitivity(&state, 6)); // still no docs

        // Add doc
        state.pdf_documents.push(PathBuf::from("/tmp/doc.pdf"));
        assert!(compute_sign_sensitivity(&state, 6)); // 6 digits -> true
        assert!(compute_sign_sensitivity(&state, 12)); // 12 digits -> true
        assert!(!compute_sign_sensitivity(&state, 5)); // 5 digits -> false
        assert!(!compute_sign_sensitivity(&state, 13)); // 13 digits -> false

        // Busy overrides
        state.busy = true;
        assert!(!compute_sign_sensitivity(&state, 6));
        state.busy = false;

        // Missing signature support
        state.signature_supported = false;
        assert!(!compute_sign_sensitivity(&state, 6));
        state.signature_supported = true;

        // Card removed, phone present
        state.has_local_card = false;
        state.phone = Some(PairedPhone {
            pair_id: PairId::from_array(*b"pair-id-test-001"),
            name: "Phone".to_string(),
            platform: "iOS".to_string(),
            certificate_cached: true,
        });
        assert!(compute_sign_sensitivity(&state, 6));
    }

    #[test]
    fn test_code_boxes_in_process() {
        if gtk4::init().is_err() {
            eprintln!("GTK4 init skipped (no display)");
            return;
        }

        let cb = CodeBoxes::new();
        assert_eq!(cb.labels.len(), PAIRING_CODE_LEN);
        for lbl in &cb.labels {
            assert_eq!(lbl.label(), "");
        }

        // Test update
        cb.update("7KX4M9");
        assert_eq!(cb.labels[0].label(), "7");
        assert_eq!(cb.labels[1].label(), "K");
        assert_eq!(cb.labels[2].label(), "X");
        assert_eq!(cb.labels[3].label(), "4");
        assert_eq!(cb.labels[4].label(), "M");
        assert_eq!(cb.labels[5].label(), "9");

        // Test clear
        cb.clear();
        assert_eq!(cb.entry.text(), "");
        for lbl in &cb.labels {
            assert_eq!(lbl.label(), "");
        }
    }

    #[test]
    fn test_status_widgets_lifecycle_in_process() {
        if gtk4::init().is_err() {
            eprintln!("GTK4 init skipped (no display)");
            return;
        }

        let app_win = gtk4::ApplicationWindow::builder().build();
        let controller = RefineIdController::new(|_| {});
        let (pw_win, pw_widgets) = build_pincodes_window(&controller, &app_win);
        let key_button = gtk4::Button::builder().build();
        let key_icon = gtk4::Image::from_icon_name("network-wireless-symbolic");
        let (_main_box, sw) =
            build_status_view(&controller, &app_win, &pw_win, key_button, key_icon);

        // 1. Initial / Disconnected state: no reader
        let mut state = UiState::default();
        state.reader_connected = false;
        Gtk4Driver::apply_status_state(&sw, &state);
        assert_eq!(sw.holder_name_label.text(), "Connect a card reader.");
        assert_eq!(sw.status_pill_label.text(), "No Reader");
        assert!(!sw.sign_button.is_sensitive());
        assert!(!sw.document_pile_box.is_visible());
        assert!(sw.drop_invitation_box.is_visible());

        // 2. Reader connected without card
        state.reader_connected = true;
        Gtk4Driver::apply_status_state(&sw, &state);
        assert_eq!(
            sw.holder_name_label.text(),
            "Insert the card into the reader."
        );
        assert_eq!(sw.status_pill_label.text(), "No Card");

        // 3. Card inserted
        state.has_local_card = true;
        state.signature_supported = true;
        Gtk4Driver::apply_status_state(&sw, &state);
        assert_eq!(sw.status_pill_label.text(), "Not Ready"); // No cards report yet
        assert_eq!(*sw.remote_action.borrow(), RemoteButtonAction::OpenPinCodes);

        // 4. Remote phone connected
        state.has_local_card = false;
        state.phone = Some(PairedPhone {
            pair_id: PairId::from_array(*b"pair-id-test-001"),
            name: "Pixel 9".to_string(),
            platform: "Android".to_string(),
            certificate_cached: true,
        });
        Gtk4Driver::apply_status_state(&sw, &state);
        assert_eq!(sw.status_pill_label.text(), "Via Phone");
        assert_eq!(sw.holder_name_label.text(), "Connected to Pixel 9");
        assert_eq!(*sw.remote_action.borrow(), RemoteButtonAction::ForgetPhone);

        // 5. Pairing ceremony active
        state.phone = None;
        state.pairing = Some(RappPairingState {
            code: "7KX4M9".to_string(),
            status: "Looking for phone...".to_string(),
        });
        Gtk4Driver::apply_status_state(&sw, &state);
        assert!(sw.pairing_box.is_visible());
        assert!(!sw.normal_identity_box.is_visible());
        assert_eq!(sw.pairing_status_label.text(), "Looking for phone...");
        assert_eq!(sw.pairing_code_boxes.labels[0].label(), "7");
        assert_eq!(sw.pairing_code_boxes.labels[5].label(), "9");

        // 6. Documents and signing sensitivity
        state.pairing = None;
        state.has_local_card = true;
        state.pdf_documents.push(PathBuf::from("/tmp/contract.pdf"));
        Gtk4Driver::apply_status_state(&sw, &state);
        assert!(sw.document_pile_box.is_visible());
        assert!(!sw.drop_invitation_box.is_visible());
        assert!(!sw.sign_button.is_sensitive()); // PIN 2 not yet entered

        // Set PIN 2 text
        sw.pin2_entry.set_text("123456");
        Gtk4Driver::update_sign_button_sensitivity(&sw);
        assert!(sw.sign_button.is_sensitive());

        // 7. Auxiliary PIN codes status
        Gtk4Driver::apply_pincodes_state(&pw_widgets, &state);
        assert!(pw_widgets.attempts_label.text().contains("PIN 1:"));
        assert!(pw_widgets.attempts_label.text().contains("PIN 2:"));
        assert!(pw_widgets.attempts_label.text().contains("PUK:"));
    }
}
