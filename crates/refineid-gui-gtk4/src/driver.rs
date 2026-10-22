// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

//! GTK 4 implementation of the presentation driver for RefineID.
//!
//! Mirrors the macOS UI: tabbed Identity / PINs / Sign / Phone layout,
//! masked credential entry with per-field reveal toggle, code boxes for
//! the pairing code, and no PIN-length hints anywhere.

use std::sync::Arc;
use std::sync::mpsc;

use refineid_gui_core::PinManageSlot;
use refineid_gui_core::controller::RefineIdController;
use refineid_gui_core::driver::UiDriver;
use refineid_gui_core::error::GuiCoreError;
use refineid_gui_core::model::{SignFormat, UiState, UserIntent};
use refineid_lib_core::auth::{PIN_TRY_LIMIT, PinStatus, PukStatus};
use refineid_lib_core::pin::PinBytes;
use refineid_rapp_core::offer::{PAIRING_CODE_LENGTH, pairing_code_character};

use gtk4::glib;
use gtk4::prelude::*;

/// Maximum PIN digits (PIN1 and PIN2 share this bound).
const MAX_PIN_DIGITS: usize = 12;
/// Minimum PIN1 digits.
const MIN_PIN1_DIGITS: usize = 4;
/// Minimum PIN2 digits.
const MIN_PIN2_DIGITS: usize = 6;
/// PUK digit count.
const PUK_DIGITS: usize = 8;
/// Activation code digit count.
const ACTIVATION_CODE_DIGITS: usize = 8;

/// Pairing code length.
const PAIRING_CODE_LEN: usize = PAIRING_CODE_LENGTH;

fn to_pin_bytes(s: &str) -> Option<PinBytes> {
    PinBytes::new(s.as_bytes().to_vec()).ok()
}

/// Filter text to ASCII digits, up to `max`, blocking the signal so we can
/// rewrite the entry value in place.
fn filter_digits(entry: &gtk4::Entry, text: &str, max: usize) {
    let filtered: String = text
        .chars()
        .filter(|c| c.is_ascii_digit())
        .take(max)
        .collect();
    if filtered != text {
        let current = entry.text();
        let pos = entry.position() as usize;
        let take = max.saturating_sub(pos);
        let new_text = format!(
            "{}{}{}",
            &current[..pos],
            &filtered[..take],
            &current[pos..]
        );
        entry.set_text(&new_text);
        entry.set_position(new_text.chars().count() as i32);
    }
}

/// Widget handles maintained by the GTK4 driver.
#[allow(dead_code, reason = "fields wired in later implementation passes")]
struct Gtk4Widgets {
    window: gtk4::ApplicationWindow,
    notebook: gtk4::Notebook,
    // Identity tab
    holder_label: gtk4::Label,
    can_entry: gtk4::Entry,
    load_images_button: gtk4::Button,
    portrait_placeholder: gtk4::Label,
    copy_portrait_button: gtk4::Button,
    save_portrait_button: gtk4::Button,
    signature_placeholder: gtk4::Label,
    copy_signature_button: gtk4::Button,
    save_signature_button: gtk4::Button,
    // PINs tab
    pin1_status_label: gtk4::Label,
    pin2_status_label: gtk4::Label,
    puk_status_label: gtk4::Label,
    pin_subtabs: gtk4::Notebook,
    tab_change_pin1: gtk4::Box,
    tab_change_pin2: gtk4::Box,
    tab_reactivate: gtk4::Box,
    tab_activate: gtk4::Box,
    cur_pin1_entry: gtk4::Entry,
    new_pin1_entry: gtk4::Entry,
    conf_pin1_entry: gtk4::Entry,
    change_pin1_button: gtk4::Button,
    cur_pin2_entry: gtk4::Entry,
    new_pin2_entry: gtk4::Entry,
    conf_pin2_entry: gtk4::Entry,
    change_pin2_button: gtk4::Button,
    reactivate_slot_combo: gtk4::DropDown,
    puk_entry: gtk4::Entry,
    react_new_pin_entry: gtk4::Entry,
    react_conf_pin_entry: gtk4::Entry,
    reactivate_button: gtk4::Button,
    act_code_entry: gtk4::Entry,
    act_pin1_entry: gtk4::Entry,
    act_conf_pin1_entry: gtk4::Entry,
    act_pin2_entry: gtk4::Entry,
    act_conf_pin2_entry: gtk4::Entry,
    activate_button: gtk4::Button,
    // Sign tab
    document_list: gtk4::ListBox,
    add_document_button: gtk4::Button,
    remove_document_button: gtk4::Button,
    clear_documents_button: gtk4::Button,
    format_pades_button: gtk4::Button,
    format_asice_button: gtk4::Button,
    sign_pin2_entry: gtk4::Entry,
    sign_button: gtk4::Button,
    sign_result_label: gtk4::Label,
    // Phone tab
    code_boxes: CodeBoxes,
    pair_status_label: gtk4::Label,
    phone_name_label: gtk4::Label,
    phone_state_label: gtk4::Label,
    forget_phone_button: gtk4::Button,
    reader_card: gtk4::Box,
    phone_card: gtk4::Box,
    // Status
    info_bar: gtk4::InfoBar,
    status_label: gtk4::Label,
    pairing_running: bool,
}

/// Presentation driver using GTK 4.
pub struct Gtk4Driver {
    application: gtk4::Application,
    state_rx: Option<mpsc::Receiver<UiState>>,
    opens_on_phone_tab: bool,
    widgets: Option<Gtk4Widgets>,
}

impl std::fmt::Debug for Gtk4Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gtk4Driver")
            .field("has_widgets", &self.widgets.is_some())
            .finish_non_exhaustive()
    }
}

/// State change notification callback type.
pub type StateChangeCallback = Box<dyn Fn(&UiState) + Send + Sync + 'static>;

impl Gtk4Driver {
    /// Opens the window on the Phone tab with the code entry focused.
    pub fn open_on_phone_tab(&mut self) {
        self.opens_on_phone_tab = true;
    }

    /// Create a new GTK4 driver and its state notification callback.
    pub fn create() -> (Self, StateChangeCallback) {
        let application = gtk4::Application::builder()
            .application_id("fi.refineid.gui")
            .build();
        let (state_tx, state_rx) = mpsc::channel::<UiState>();
        let tx_for_callback = state_tx.clone();

        let on_state_change = Box::new(move |state: &UiState| {
            let _ = tx_for_callback.send(state.clone());
        });

        let driver = Self {
            application,
            state_rx: Some(state_rx),
            opens_on_phone_tab: false,
            widgets: None,
        };

        (driver, on_state_change)
    }

    /// Build all UI controls and attach callbacks dispatching to `controller`.
    fn init_ui(&mut self, controller: &Arc<RefineIdController>) {
        // Initialize GTK before creating any widgets.
        gtk4::init().expect("failed to initialize GTK");

        // Load CSS for code boxes and other styling.
        let css_provider = gtk4::CssProvider::new();
        css_provider
            .load_from_data(
                b"
                .code-box {
                    border: 2px solid #cccccc;
                    border-radius: 8px;
                    background-color: #fafafa;
                }
                .code-box-filled {
                    border-color: #333333;
                    background-color: #ffffff;
                }
                .code-box-active {
                    border-color: #007aff;
                    background-color: #e3f2fd;
                }
                .code-char {
                    font-family: monospace;
                    font-size: 24px;
                    font-weight: bold;
                    color: #333333;
                }
            ",
            )
            .ok();
        gtk4::StyleContext::add_provider_for_display(
            &gtk4::gdk::Display::default().expect("no display"),
            &css_provider,
            gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );

        // Register the application so the startup signal is emitted
        // before we create any windows.
        let _ = self.application.register(None::<&gtk4::gio::Cancellable>);

        let window = gtk4::ApplicationWindow::builder()
            .application(&self.application)
            .default_width(920)
            .default_height(700)
            .title("RefineID")
            .build();

        // Root box: notebook on top, info bar below
        let root = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .build();
        window.set_child(Some(&root));

        // Notebook with tabs
        let notebook = gtk4::Notebook::builder().build();
        root.append(&notebook);

        // ---- Tab 1: Identity ----
        let identity = self.build_identity_tab(controller);
        notebook.append_page(&identity.page, Some(&identity.tab_label));

        // ---- Tab 2: PINs ----
        let pins = self.build_pins_tab(controller);
        notebook.append_page(&pins.page, Some(&pins.tab_label));

        // ---- Tab 3: Sign ----
        let sign = self.build_sign_tab(controller);
        notebook.append_page(&sign.page, Some(&sign.tab_label));

        // ---- Tab 4: Phone ----
        let phone = self.build_phone_tab(controller);
        notebook.append_page(&phone.page, Some(&phone.tab_label));

        // Info bar for status messages
        let info_bar = gtk4::InfoBar::builder().build();
        info_bar.set_message_type(gtk4::MessageType::Error);
        let status_label = gtk4::Label::builder()
            .halign(gtk4::Align::Start)
            .valign(gtk4::Align::Center)
            .build();
        info_bar.add_child(&status_label);
        root.append(&info_bar);
        info_bar.set_visible(false);

        self.widgets = Some(Gtk4Widgets {
            window,
            notebook,
            // Identity
            holder_label: identity.holder_label,
            can_entry: identity.can_entry,
            load_images_button: identity.load_images_button,
            portrait_placeholder: identity.portrait_placeholder,
            copy_portrait_button: identity.copy_portrait_button,
            save_portrait_button: identity.save_portrait_button,
            signature_placeholder: identity.signature_placeholder,
            copy_signature_button: identity.copy_signature_button,
            save_signature_button: identity.save_signature_button,
            // PINs
            pin1_status_label: pins.pin1_status_label,
            pin2_status_label: pins.pin2_status_label,
            puk_status_label: pins.puk_status_label,
            pin_subtabs: pins.pin_subtabs,
            tab_change_pin1: pins.tab_change_pin1,
            tab_change_pin2: pins.tab_change_pin2,
            tab_reactivate: pins.tab_reactivate,
            tab_activate: pins.tab_activate,
            cur_pin1_entry: pins.cur_pin1_entry,
            new_pin1_entry: pins.new_pin1_entry,
            conf_pin1_entry: pins.conf_pin1_entry,
            change_pin1_button: pins.change_pin1_button,
            cur_pin2_entry: pins.cur_pin2_entry,
            new_pin2_entry: pins.new_pin2_entry,
            conf_pin2_entry: pins.conf_pin2_entry,
            change_pin2_button: pins.change_pin2_button,
            reactivate_slot_combo: pins.reactivate_slot_combo,
            puk_entry: pins.puk_entry,
            react_new_pin_entry: pins.react_new_pin_entry,
            react_conf_pin_entry: pins.react_conf_pin_entry,
            reactivate_button: pins.reactivate_button,
            act_code_entry: pins.act_code_entry,
            act_pin1_entry: pins.act_pin1_entry,
            act_conf_pin1_entry: pins.act_conf_pin1_entry,
            act_pin2_entry: pins.act_pin2_entry,
            act_conf_pin2_entry: pins.act_conf_pin2_entry,
            activate_button: pins.activate_button,
            // Sign
            document_list: sign.document_list,
            add_document_button: sign.add_document_button,
            remove_document_button: sign.remove_document_button,
            clear_documents_button: sign.clear_documents_button,
            format_pades_button: sign.format_pades_button,
            format_asice_button: sign.format_asice_button,
            sign_pin2_entry: sign.sign_pin2_entry,
            sign_button: sign.sign_button,
            sign_result_label: sign.sign_result_label,
            // Phone
            code_boxes: phone.code_boxes,
            pair_status_label: phone.pair_status_label,
            phone_name_label: phone.phone_name_label,
            phone_state_label: phone.phone_state_label,
            forget_phone_button: phone.forget_phone_button,
            reader_card: phone.reader_card,
            phone_card: phone.phone_card,
            // Status
            info_bar,
            status_label,
            pairing_running: false,
        });
    }

    /// Build the Identity tab.
    fn build_identity_tab(&mut self, controller: &Arc<RefineIdController>) -> IdentityWidgets {
        let tab_label = gtk4::Label::new(Some("Identity"));

        let page = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .margin_top(20)
            .margin_start(32)
            .margin_end(32)
            .margin_bottom(20)
            .spacing(16)
            .build();

        let holder_label = gtk4::Label::builder()
            .label("")
            .halign(gtk4::Align::Start)
            .valign(gtk4::Align::Center)
            .build();
        page.append(&holder_label);

        // CAN bar
        let can_bar = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .build();
        let can_label = gtk4::Label::builder()
            .label("Card Access Number (CAN)")
            .halign(gtk4::Align::Start)
            .build();
        let can_entry = gtk4::Entry::builder()
            .placeholder_text("000000")
            .width_chars(10)
            .max_width_chars(6)
            .build();
        can_entry.connect_insert_text(move |entry, text, _position| {
            filter_digits(entry, text, 6);
        });
        let load_images_button = gtk4::Button::builder().label("Load Photo").build();
        can_bar.append(&can_label);
        can_bar.append(&can_entry);
        can_bar.append(
            &gtk4::Box::builder()
                .homogeneous(false)
                .hexpand(true)
                .build(),
        );
        can_bar.append(&load_images_button);
        page.append(&can_bar);

        // Load images callback
        {
            let c = Arc::clone(controller);
            let entry = can_entry.clone();
            load_images_button.connect_clicked(move |_| {
                let can_val = entry.text();
                let Some(can_pin) = to_pin_bytes(&can_val) else {
                    return;
                };
                c.handle_intent(UserIntent::LoadImages { can: can_pin });
            });
        }

        // Images row: portrait + signature side by side
        let images_row = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(24)
            .hexpand(true)
            .build();

        // Portrait card
        let portrait_card = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(8)
            .build();
        let portrait_title = gtk4::Label::builder()
            .label("Official Photo")
            .halign(gtk4::Align::Start)
            .build();
        portrait_title.add_css_class("title");
        portrait_card.append(&portrait_title);

        let portrait_frame = gtk4::Frame::builder().build();
        let portrait_placeholder = gtk4::Label::builder()
            .label("(photo not yet loaded)")
            .halign(gtk4::Align::Center)
            .valign(gtk4::Align::Center)
            .build();
        portrait_placeholder.set_size_request(320, 330);
        portrait_frame.set_child(Some(&portrait_placeholder));
        portrait_card.append(&portrait_frame);

        let portrait_actions = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .build();
        let copy_portrait_button = gtk4::Button::builder().label("Copy Photo").build();
        let save_portrait_button = gtk4::Button::builder().label("Save As…").build();
        portrait_actions.append(&copy_portrait_button);
        portrait_actions.append(&save_portrait_button);
        portrait_card.append(&portrait_actions);

        // Signature card
        let signature_card = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(8)
            .build();
        let signature_title = gtk4::Label::builder()
            .label("Cardholder Signature")
            .halign(gtk4::Align::Start)
            .build();
        signature_title.add_css_class("title");
        signature_card.append(&signature_title);

        let signature_frame = gtk4::Frame::builder().build();
        let signature_placeholder = gtk4::Label::builder()
            .label("(signature not yet loaded)")
            .halign(gtk4::Align::Center)
            .valign(gtk4::Align::Center)
            .build();
        signature_placeholder.set_size_request(420, 160);
        signature_frame.set_child(Some(&signature_placeholder));
        signature_card.append(&signature_frame);

        let signature_actions = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .build();
        let copy_signature_button = gtk4::Button::builder().label("Copy Signature").build();
        let save_signature_button = gtk4::Button::builder().label("Save As…").build();
        signature_actions.append(&copy_signature_button);
        signature_actions.append(&save_signature_button);
        signature_card.append(&signature_actions);

        images_row.append(&portrait_card);
        images_row.append(&signature_card);
        page.append(&images_row);

        IdentityWidgets {
            page,
            tab_label,
            holder_label,
            can_entry,
            load_images_button,
            portrait_placeholder,
            copy_portrait_button,
            save_portrait_button,
            signature_placeholder,
            copy_signature_button,
            save_signature_button,
        }
    }

    /// Build the PINs tab with sub-tabs.
    fn build_pins_tab(&mut self, controller: &Arc<RefineIdController>) -> PinWidgets {
        let tab_label = gtk4::Label::new(Some("PINs"));

        let page = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .margin_top(20)
            .margin_start(32)
            .margin_end(32)
            .margin_bottom(20)
            .spacing(16)
            .build();

        // Status lines
        let status_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(6)
            .build();
        let pin1_status_label = gtk4::Label::builder()
            .label("")
            .halign(gtk4::Align::Start)
            .build();
        let pin2_status_label = gtk4::Label::builder()
            .label("")
            .halign(gtk4::Align::Start)
            .build();
        let puk_status_label = gtk4::Label::builder()
            .label("")
            .halign(gtk4::Align::Start)
            .build();
        status_box.append(&pin1_status_label);
        status_box.append(&pin2_status_label);
        status_box.append(&puk_status_label);
        page.append(&status_box);

        // Sub-notebook for PIN operations
        let pin_subtabs = gtk4::Notebook::builder().build();

        // --- Change PIN 1 sub-tab ---
        let tab_change_pin1 =
            self.build_change_pin_form(PinManageSlot::Pin1, MIN_PIN1_DIGITS, controller);
        pin_subtabs.append_page(
            &tab_change_pin1.page,
            Some(&gtk4::Label::new(Some("Change PIN 1"))),
        );

        // --- Change PIN 2 sub-tab ---
        let tab_change_pin2 =
            self.build_change_pin_form(PinManageSlot::Pin2, MIN_PIN2_DIGITS, controller);
        pin_subtabs.append_page(
            &tab_change_pin2.page,
            Some(&gtk4::Label::new(Some("Change PIN 2"))),
        );

        // --- Reactivate sub-tab ---
        let tab_reactivate = self.build_reactivate_form(controller);
        pin_subtabs.append_page(
            &tab_reactivate.page,
            Some(&gtk4::Label::new(Some("Unblock PIN"))),
        );

        // --- Activate sub-tab ---
        let tab_activate = self.build_activate_form(controller);
        pin_subtabs.append_page(
            &tab_activate.page,
            Some(&gtk4::Label::new(Some("Activate Card"))),
        );

        page.append(&pin_subtabs);

        PinWidgets {
            page,
            tab_label,
            pin1_status_label,
            pin2_status_label,
            puk_status_label,
            pin_subtabs,
            tab_change_pin1: tab_change_pin1.page,
            tab_change_pin2: tab_change_pin2.page,
            tab_reactivate: tab_reactivate.page,
            tab_activate: tab_activate.page,
            cur_pin1_entry: tab_change_pin1.entries.current,
            new_pin1_entry: tab_change_pin1.entries.new_pin,
            conf_pin1_entry: tab_change_pin1.entries.confirm,
            change_pin1_button: tab_change_pin1.button,
            cur_pin2_entry: tab_change_pin2.entries.current,
            new_pin2_entry: tab_change_pin2.entries.new_pin,
            conf_pin2_entry: tab_change_pin2.entries.confirm,
            change_pin2_button: tab_change_pin2.button,
            reactivate_slot_combo: tab_reactivate.slot_combo,
            puk_entry: tab_reactivate.entries.puk,
            react_new_pin_entry: tab_reactivate.entries.new_pin,
            react_conf_pin_entry: tab_reactivate.entries.confirm,
            reactivate_button: tab_reactivate.button,
            act_code_entry: tab_activate.entries.activation_code,
            act_pin1_entry: tab_activate.entries.new_pin,
            act_conf_pin1_entry: tab_activate.entries.confirm,
            act_pin2_entry: tab_activate.entries.new_pin2,
            act_conf_pin2_entry: tab_activate.entries.confirm2,
            activate_button: tab_activate.button,
        }
    }

    /// Build a change-PIN form (current + new + confirm + button).
    fn build_change_pin_form(
        &self,
        slot: PinManageSlot,
        min_digits: usize,
        controller: &Arc<RefineIdController>,
    ) -> ChangePinForm {
        let page = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(12)
            .build();

        let current_entry =
            self.secret_entry_row(&page, &format!("Current {}:", slot_label(slot)), min_digits);
        let new_entry =
            self.secret_entry_row(&page, &format!("New {}:", slot_label(slot)), min_digits);
        let confirm_entry =
            self.secret_entry_row(&page, &format!("Confirm {}:", slot_label(slot)), min_digits);

        let button = gtk4::Button::builder()
            .label(format!("Change {}", slot_label(slot)))
            .build();
        button.add_css_class("suggested-action");
        page.append(&button);

        let c = Arc::clone(controller);
        let cur = current_entry.entry.clone();
        let new_p = new_entry.entry.clone();
        let conf = confirm_entry.entry.clone();
        let slot_ = slot;
        button.connect_clicked(move |_| {
            let cur_val = cur.text();
            let new_val = new_p.text();
            let conf_val = conf.text();
            if new_val != conf_val {
                show_alert("New PIN entries do not match.");
                return;
            }
            if new_val.len() < min_digits || new_val.len() > MAX_PIN_DIGITS {
                show_alert(&format!(
                    "PIN must be between {min_digits} and {} digits.",
                    MAX_PIN_DIGITS
                ));
                return;
            }
            let (Some(cur_pin), Some(new_pin)) = (to_pin_bytes(&cur_val), to_pin_bytes(&new_val))
            else {
                show_alert("PIN contains invalid characters.");
                return;
            };
            c.handle_intent(UserIntent::ChangePin {
                slot: slot_,
                current_pin: cur_pin,
                new_pin,
            });
            cur.set_text("");
            new_p.set_text("");
            conf.set_text("");
        });

        ChangePinForm {
            page,
            entries: PinEntries {
                current: current_entry.entry,
                new_pin: new_entry.entry,
                confirm: confirm_entry.entry,
            },
            button,
        }
    }

    /// Build a secret entry row (label + Entry with reveal toggle).
    fn secret_entry_row(
        &self,
        parent: &gtk4::Box,
        label_text: &str,
        max_digits: usize,
    ) -> SecretEntry {
        let row = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .build();

        let label = gtk4::Label::builder()
            .label(label_text)
            .halign(gtk4::Align::Start)
            .build();
        label.set_width_chars(16);

        let entry = gtk4::Entry::builder()
            .visibility(false)
            .width_chars(14)
            .max_width_chars(max_digits as i32)
            .build();
        entry.connect_insert_text(move |entry, text, _position| {
            filter_digits(entry, text, max_digits);
        });

        let reveal_btn = gtk4::Button::builder().build();
        reveal_btn.add_css_class("circular");
        let reveal_icon = gtk4::Image::from_icon_name("view-reveal-symbolic");
        reveal_btn.set_child(Some(&reveal_icon));
        let visible = std::rc::Rc::new(std::cell::Cell::new(false));
        let visible_clone = visible.clone();
        let entry_clone = entry.clone();
        reveal_btn.connect_clicked(move |_| {
            visible_clone.set(!visible_clone.get());
            entry_clone.set_visibility(visible_clone.get());
            let icon_name = if visible_clone.get() {
                "view-hide-symbolic"
            } else {
                "view-reveal-symbolic"
            };
            reveal_icon.set_icon_name(Some(icon_name));
        });

        row.append(&label);
        row.append(&entry);
        row.append(&reveal_btn);
        parent.append(&row);

        SecretEntry { entry }
    }

    /// Build the reactivate/unblock form.
    fn build_reactivate_form(&self, controller: &Arc<RefineIdController>) -> ReactivateForm {
        let page = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(12)
            .build();

        // Slot selector
        let slot_row = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .build();
        let slot_label_widget = gtk4::Label::builder()
            .label("PIN to Unblock:")
            .halign(gtk4::Align::Start)
            .build();
        slot_label_widget.set_width_chars(16);
        let slot_combo =
            gtk4::DropDown::from_strings(&["PIN 1 (Authentication)", "PIN 2 (Signing)"]);
        slot_row.append(&slot_label_widget);
        slot_row.append(&slot_combo);
        page.append(&slot_row);

        let puk_entry = self.secret_entry_row(&page, "PUK Code:", PUK_DIGITS);
        let new_pin_entry = self.secret_entry_row(&page, "New PIN:", MIN_PIN1_DIGITS);
        let confirm_entry = self.secret_entry_row(&page, "Confirm New PIN:", MIN_PIN1_DIGITS);

        let button = gtk4::Button::builder().label("Unblock PIN").build();
        button.add_css_class("destructive-action");
        page.append(&button);

        let c = Arc::clone(controller);
        let slot = slot_combo.clone();
        let puk = puk_entry.entry.clone();
        let new_p = new_pin_entry.entry.clone();
        let conf = confirm_entry.entry.clone();
        button.connect_clicked(move |_| {
            let slot_idx = slot.selected() as usize;
            let slot = if slot_idx == 1 {
                PinManageSlot::Pin2
            } else {
                PinManageSlot::Pin1
            };
            let puk_val = puk.text();
            let new_val = new_p.text();
            let conf_val = conf.text();
            if new_val != conf_val {
                show_alert("New PIN entries do not match.");
                return;
            }
            let min_len = match slot {
                PinManageSlot::Pin1 => MIN_PIN1_DIGITS,
                PinManageSlot::Pin2 => MIN_PIN2_DIGITS,
            };
            if new_val.len() < min_len || new_val.len() > MAX_PIN_DIGITS {
                show_alert(&format!(
                    "PIN must be between {min_len} and {} digits.",
                    MAX_PIN_DIGITS
                ));
                return;
            }
            let (Some(puk_pin), Some(new_pin)) = (to_pin_bytes(&puk_val), to_pin_bytes(&new_val))
            else {
                show_alert("PUK or PIN contains invalid characters.");
                return;
            };
            c.handle_intent(UserIntent::ReactivatePin {
                slot,
                puk: puk_pin,
                new_pin,
            });
            puk.set_text("");
            new_p.set_text("");
            conf.set_text("");
        });

        ReactivateForm {
            page,
            slot_combo,
            entries: ReactivateEntries {
                puk: puk_entry.entry,
                new_pin: new_pin_entry.entry,
                confirm: confirm_entry.entry,
            },
            button,
        }
    }

    /// Build the activate (first-time setup) form.
    fn build_activate_form(&self, controller: &Arc<RefineIdController>) -> ActivateForm {
        let page = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(12)
            .build();

        let act_code_entry =
            self.secret_entry_row(&page, "Activation Code:", ACTIVATION_CODE_DIGITS);
        let new_pin1_entry = self.secret_entry_row(&page, "New PIN 1:", MIN_PIN1_DIGITS);
        let conf_pin1_entry = self.secret_entry_row(&page, "Confirm PIN 1:", MIN_PIN1_DIGITS);
        let new_pin2_entry = self.secret_entry_row(&page, "New PIN 2:", MIN_PIN2_DIGITS);
        let conf_pin2_entry = self.secret_entry_row(&page, "Confirm PIN 2:", MIN_PIN2_DIGITS);

        let button = gtk4::Button::builder().label("Activate Card").build();
        button.add_css_class("suggested-action");
        page.append(&button);

        let c = Arc::clone(controller);
        let act = act_code_entry.entry.clone();
        let p1 = new_pin1_entry.entry.clone();
        let p1c = conf_pin1_entry.entry.clone();
        let p2 = new_pin2_entry.entry.clone();
        let p2c = conf_pin2_entry.entry.clone();
        button.connect_clicked(move |_| {
            let act_val = act.text();
            let p1_val = p1.text();
            let p1c_val = p1c.text();
            let p2_val = p2.text();
            let p2c_val = p2c.text();
            if p1_val != p1c_val {
                show_alert("PIN1 entries do not match.");
                return;
            }
            if p2_val != p2c_val {
                show_alert("PIN2 entries do not match.");
                return;
            }
            if p1_val.len() < MIN_PIN1_DIGITS || p1_val.len() > MAX_PIN_DIGITS {
                show_alert(&format!(
                    "PIN1 must be between {} and {} digits.",
                    MIN_PIN1_DIGITS, MAX_PIN_DIGITS
                ));
                return;
            }
            if p2_val.len() < MIN_PIN2_DIGITS || p2_val.len() > MAX_PIN_DIGITS {
                show_alert(&format!(
                    "PIN2 must be between {} and {} digits.",
                    MIN_PIN2_DIGITS, MAX_PIN_DIGITS
                ));
                return;
            }
            let (Some(act_code), Some(new_p1), Some(new_p2)) = (
                to_pin_bytes(&act_val),
                to_pin_bytes(&p1_val),
                to_pin_bytes(&p2_val),
            ) else {
                show_alert("Activation code or PINs contain invalid characters.");
                return;
            };
            c.handle_intent(UserIntent::ActivateCard {
                activation_code: act_code,
                new_pin1: new_p1,
                new_pin2: new_p2,
            });
            act.set_text("");
            p1.set_text("");
            p1c.set_text("");
            p2.set_text("");
            p2c.set_text("");
        });

        ActivateForm {
            page,
            entries: ActivateEntries {
                activation_code: act_code_entry.entry,
                new_pin: new_pin1_entry.entry,
                confirm: conf_pin1_entry.entry,
                new_pin2: new_pin2_entry.entry,
                confirm2: conf_pin2_entry.entry,
            },
            button,
        }
    }

    /// Build the Sign tab.
    fn build_sign_tab(&mut self, controller: &Arc<RefineIdController>) -> SignWidgets {
        let tab_label = gtk4::Label::new(Some("Sign"));

        let page = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(24)
            .margin_top(20)
            .margin_start(32)
            .margin_end(32)
            .margin_bottom(20)
            .build();

        // Left: document queue
        let doc_card = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(12)
            .vexpand(true)
            .build();
        let queue_label = gtk4::Label::builder()
            .label("Documents to Sign")
            .halign(gtk4::Align::Start)
            .build();
        queue_label.add_css_class("title");
        doc_card.append(&queue_label);

        let document_list = gtk4::ListBox::builder()
            .selection_mode(gtk4::SelectionMode::None)
            .build();
        document_list.set_size_request(460, 300);
        doc_card.append(&document_list);

        let doc_actions = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .build();
        let add_document_button = gtk4::Button::builder().label("Add Files…").build();
        let remove_document_button = gtk4::Button::builder().label("Remove Selected").build();
        let clear_documents_button = gtk4::Button::builder().label("Clear List").build();
        doc_actions.append(&add_document_button);
        doc_actions.append(&remove_document_button);
        doc_actions.append(&clear_documents_button);
        doc_card.append(&doc_actions);

        let sign_result_label = gtk4::Label::builder()
            .label("")
            .halign(gtk4::Align::Start)
            .build();
        doc_card.append(&sign_result_label);

        page.append(&doc_card);

        // Right: signing options
        let sign_card = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(12)
            .build();
        let opt_title = gtk4::Label::builder()
            .label("Signature Options")
            .halign(gtk4::Align::Start)
            .build();
        opt_title.add_css_class("title");
        sign_card.append(&opt_title);

        let fmt_label = gtk4::Label::builder()
            .label("Format:")
            .halign(gtk4::Align::Start)
            .build();
        sign_card.append(&fmt_label);

        let fmt_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(6)
            .build();
        let format_pades_button = gtk4::Button::builder()
            .label("PDF Document (PAdES)")
            .build();
        format_pades_button.add_css_class("suggested-action");
        let format_asice_button = gtk4::Button::builder()
            .label("BDOC Container (ASiC-E)")
            .build();
        fmt_box.append(&format_pades_button);
        fmt_box.append(&format_asice_button);
        sign_card.append(&fmt_box);

        let p2_label = gtk4::Label::builder()
            .label("Signing PIN (PIN 2):")
            .halign(gtk4::Align::Start)
            .build();
        sign_card.append(&p2_label);
        let sign_pin2_entry = self.secret_entry_row(&sign_card, "", MIN_PIN2_DIGITS);

        let sign_button = gtk4::Button::builder().label("Sign Documents").build();
        sign_button.add_css_class("suggested-action");
        sign_button.set_hexpand(true);
        sign_card.append(&sign_button);

        page.append(&sign_card);

        // Callbacks
        {
            add_document_button.connect_clicked(move |_| {
                show_alert("File selection not yet implemented in GTK4 driver.");
            });
        }
        {
            let c = Arc::clone(controller);
            let list = document_list.clone();
            remove_document_button.connect_clicked(move |_| {
                if let Some(row) = list.selected_row() {
                    let idx = row.index() as usize;
                    let current = c.state().pdf_documents.clone();
                    if idx < current.len() {
                        let mut updated = current;
                        updated.remove(idx);
                        c.handle_intent(UserIntent::ClearDocuments);
                        if !updated.is_empty() {
                            c.handle_intent(UserIntent::AddDocuments(updated));
                        }
                    }
                }
            });
        }
        {
            let c = Arc::clone(controller);
            clear_documents_button.connect_clicked(move |_| {
                c.handle_intent(UserIntent::ClearDocuments);
            });
        }
        {
            let c = Arc::clone(controller);
            format_pades_button.connect_clicked(move |_| {
                c.handle_intent(UserIntent::SetSignFormat(SignFormat::Pades));
            });
        }
        {
            let c = Arc::clone(controller);
            format_asice_button.connect_clicked(move |_| {
                c.handle_intent(UserIntent::SetSignFormat(SignFormat::AsicE));
            });
        }
        {
            let c = Arc::clone(controller);
            let pin2_entry = sign_pin2_entry.entry.clone();
            sign_button.connect_clicked(move |_| {
                let pin2_val = pin2_entry.text();
                if pin2_val.len() < MIN_PIN2_DIGITS {
                    show_alert("PIN2 must be at least 6 digits.");
                    return;
                }
                let Some(pin2_bytes) = to_pin_bytes(&pin2_val) else {
                    show_alert("PIN2 contains invalid characters.");
                    return;
                };
                c.handle_intent(UserIntent::SignDocuments { pin2: pin2_bytes });
                pin2_entry.set_text("");
            });
        }

        SignWidgets {
            page,
            tab_label,
            document_list,
            add_document_button,
            remove_document_button,
            clear_documents_button,
            format_pades_button,
            format_asice_button,
            sign_pin2_entry: sign_pin2_entry.entry,
            sign_button,
            sign_result_label,
        }
    }

    /// Build the Phone tab (RAPP pairing).
    fn build_phone_tab(&mut self, controller: &Arc<RefineIdController>) -> PhoneWidgets {
        let tab_label = gtk4::Label::new(Some("Phone"));

        let page = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(16)
            .margin_top(20)
            .margin_start(32)
            .margin_end(32)
            .margin_bottom(20)
            .build();

        // Reader card: pairing code input
        let reader_card = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(12)
            .build();

        let code_label = gtk4::Label::builder()
            .label("Code on the phone:")
            .halign(gtk4::Align::Start)
            .build();
        reader_card.append(&code_label);

        let code_boxes = CodeBoxes::new(PAIRING_CODE_LEN, 2);
        reader_card.append(code_boxes.container());

        let pair_status_label = gtk4::Label::builder()
            .label("")
            .halign(gtk4::Align::Start)
            .build();
        reader_card.append(&pair_status_label);

        page.append(&reader_card.clone());

        // Phone card: paired phone row
        let phone_card = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(12)
            .build();
        let phone_name_label = gtk4::Label::builder()
            .label("")
            .halign(gtk4::Align::Start)
            .build();
        phone_name_label.set_hexpand(true);
        let phone_state_label = gtk4::Label::builder()
            .label("")
            .halign(gtk4::Align::End)
            .build();
        let forget_phone_button = gtk4::Button::builder()
            .icon_name("user-trash-symbolic")
            .build();
        forget_phone_button.add_css_class("flat");
        forget_phone_button.set_tooltip_text(Some("Forget this phone"));
        phone_card.append(&phone_name_label);
        phone_card.append(&phone_state_label);
        phone_card.append(&forget_phone_button);
        phone_card.set_visible(false);
        page.append(&phone_card.clone());

        // Callbacks
        {
            let c = Arc::clone(controller);
            let c_activate = Arc::clone(&c);
            let code_boxes_clone = code_boxes.clone();
            code_boxes.entry.connect_activate(move |entry| {
                let code = entry.text();
                if code.chars().count() == PAIRING_CODE_LEN {
                    c_activate.handle_intent(UserIntent::StartPairing {
                        code: code.to_string(),
                    });
                }
            });
            code_boxes.entry.connect_changed(move |entry| {
                let code = entry.text();
                code_boxes_clone.render(&code);
                if code.chars().count() == PAIRING_CODE_LEN {
                    let code_owned = code.to_string();
                    c.handle_intent(UserIntent::StartPairing { code: code_owned });
                }
            });
        }
        {
            let c = Arc::clone(controller);
            forget_phone_button.connect_clicked(move |_| {
                if let Some(phone) = c.state().phone.as_ref() {
                    let question = format!("Forget {}?", phone.name);
                    if show_confirmation(&question, "Cancel", "Forget") {
                        c.handle_intent(UserIntent::ForgetPhone);
                    }
                }
            });
        }

        PhoneWidgets {
            page,
            tab_label,
            code_boxes,
            pair_status_label,
            phone_name_label,
            phone_state_label,
            forget_phone_button,
            reader_card,
            phone_card,
        }
    }

    /// Render the current UI state to the GTK4 widgets.
    fn render_widgets(&mut self, state: &UiState) {
        let Some(widgets) = self.widgets.as_mut() else {
            return;
        };

        // Window title & status
        widgets.window.set_title(Some(&state.window_title));
        widgets.status_label.set_label(&state.status_message);
        widgets
            .info_bar
            .set_visible(!state.status_message.is_empty());

        // Holder name
        let holder = state
            .selected_card
            .and_then(|index| state.cards.get(index))
            .map(|card| card.display_name())
            .unwrap_or_default();
        widgets.holder_label.set_markup(&format!("<b>{holder}</b>"));

        // PIN status lines
        widgets.pin1_status_label.set_label(&credential_line(
            "PIN 1",
            pin_status_text(state.pin1_status, state.pin1_changed),
        ));
        widgets.pin2_status_label.set_label(&credential_line(
            "PIN 2",
            pin_status_text(state.pin2_status, state.pin2_changed),
        ));
        widgets
            .puk_status_label
            .set_label(&credential_line("PUK", puk_status_text(state.puk_status)));

        // Button states
        widgets
            .change_pin1_button
            .set_sensitive(state.pin1_change_available && !state.busy);
        widgets
            .change_pin2_button
            .set_sensitive(state.pin2_change_available && !state.busy);
        widgets.reactivate_button.set_sensitive(
            (state.pin1_unblock_available || state.pin2_unblock_available) && !state.busy,
        );
        widgets
            .activate_button
            .set_sensitive(state.activation_available && !state.busy);

        // CAN input
        widgets.load_images_button.set_sensitive(
            state.selected_card_is_local && !state.busy && state.selected_card.is_some(),
        );
        if state.can_text.is_empty() && !state.busy && !widgets.can_entry.text().is_empty() {
            widgets.can_entry.set_text("");
        } else if !state.can_text.is_empty() && widgets.can_entry.text().is_empty() {
            widgets.can_entry.set_text(&state.can_text);
        }

        // Document list
        while let Some(child) = widgets.document_list.first_child() {
            widgets.document_list.remove(&child);
        }
        for path in &state.pdf_documents {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_owned())
                .unwrap_or_else(|| path.display().to_string());
            let row = gtk4::ListBoxRow::builder().build();
            let label = gtk4::Label::builder()
                .label(&*name)
                .halign(gtk4::Align::Start)
                .build();
            row.set_child(Some(&label));
            widgets.document_list.append(&row);
        }

        match state.sign_format {
            SignFormat::Pades => {
                widgets
                    .format_pades_button
                    .add_css_class("suggested-action");
                widgets
                    .format_asice_button
                    .remove_css_class("suggested-action");
            }
            SignFormat::AsicE => {
                widgets
                    .format_asice_button
                    .add_css_class("suggested-action");
                widgets
                    .format_pades_button
                    .remove_css_class("suggested-action");
            }
        }

        widgets.sign_button.set_sensitive(
            !state.pdf_documents.is_empty() && !state.busy && state.selected_card.is_some(),
        );
        widgets
            .sign_result_label
            .set_label(state.sign_result.as_deref().unwrap_or(""));

        // Phone tab visibility and content
        if !state.has_local_card {
            if let Some(ref pairing) = state.pairing {
                widgets.pair_status_label.set_label(&pairing.status);
                widgets.code_boxes.entry.set_sensitive(false);
            } else {
                widgets.pair_status_label.set_label("");
                widgets.code_boxes.entry.set_sensitive(true);
                if widgets.pairing_running {
                    widgets.code_boxes.entry.set_text("");
                    widgets.code_boxes.render("");
                    widgets.code_boxes.entry.grab_focus();
                }
            }

            if let Some(ref phone) = state.phone {
                widgets.phone_name_label.set_label(&phone.name);
                widgets
                    .phone_state_label
                    .set_label(if phone.certificate_cached {
                        &phone.platform
                    } else {
                        "Reading the card"
                    });
                widgets.phone_card.set_visible(true);
                widgets.reader_card.set_visible(false);
            } else {
                widgets.phone_card.set_visible(false);
                widgets.reader_card.set_visible(true);
            }
        } else {
            widgets.phone_card.set_visible(false);
            widgets.reader_card.set_visible(false);
            widgets.pair_status_label.set_label("");
            widgets.code_boxes.entry.set_sensitive(false);
        }

        widgets.pairing_running = state.pairing.is_some();

        // Open on phone tab if requested
        if self.opens_on_phone_tab {
            widgets.notebook.set_current_page(Some(3));
            self.opens_on_phone_tab = false;
            widgets.code_boxes.entry.grab_focus();
        }
    }
}

impl UiDriver for Gtk4Driver {
    fn init(&mut self) -> Result<(), GuiCoreError> {
        Ok(())
    }

    fn render(&mut self, state: &UiState) {
        self.render_widgets(state);
    }

    fn run(mut self, controller: Arc<RefineIdController>) -> Result<(), GuiCoreError> {
        let state_rx = self.state_rx.take().expect("state receiver");
        self.init_ui(&controller);
        self.render_widgets(&controller.state());

        if let Some(ref widgets) = self.widgets {
            widgets.window.present();
        }

        // Set up state change polling via a timeout source
        let driver = std::rc::Rc::new(std::cell::RefCell::new(self));

        glib::timeout_add_local(std::time::Duration::from_millis(100), {
            let driver = driver.clone();
            move || {
                while let Ok(state) = state_rx.try_recv() {
                    driver.borrow_mut().render_widgets(&state);
                }
                glib::ControlFlow::Continue
            }
        });

        let app = driver.borrow().application.clone();
        app.run();

        controller.stop();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

struct IdentityWidgets {
    page: gtk4::Box,
    tab_label: gtk4::Label,
    holder_label: gtk4::Label,
    can_entry: gtk4::Entry,
    load_images_button: gtk4::Button,
    portrait_placeholder: gtk4::Label,
    copy_portrait_button: gtk4::Button,
    save_portrait_button: gtk4::Button,
    signature_placeholder: gtk4::Label,
    copy_signature_button: gtk4::Button,
    save_signature_button: gtk4::Button,
}

struct PinWidgets {
    page: gtk4::Box,
    tab_label: gtk4::Label,
    pin1_status_label: gtk4::Label,
    pin2_status_label: gtk4::Label,
    puk_status_label: gtk4::Label,
    pin_subtabs: gtk4::Notebook,
    tab_change_pin1: gtk4::Box,
    tab_change_pin2: gtk4::Box,
    tab_reactivate: gtk4::Box,
    tab_activate: gtk4::Box,
    cur_pin1_entry: gtk4::Entry,
    new_pin1_entry: gtk4::Entry,
    conf_pin1_entry: gtk4::Entry,
    change_pin1_button: gtk4::Button,
    cur_pin2_entry: gtk4::Entry,
    new_pin2_entry: gtk4::Entry,
    conf_pin2_entry: gtk4::Entry,
    change_pin2_button: gtk4::Button,
    reactivate_slot_combo: gtk4::DropDown,
    puk_entry: gtk4::Entry,
    react_new_pin_entry: gtk4::Entry,
    react_conf_pin_entry: gtk4::Entry,
    reactivate_button: gtk4::Button,
    act_code_entry: gtk4::Entry,
    act_pin1_entry: gtk4::Entry,
    act_conf_pin1_entry: gtk4::Entry,
    act_pin2_entry: gtk4::Entry,
    act_conf_pin2_entry: gtk4::Entry,
    activate_button: gtk4::Button,
}

struct ChangePinForm {
    page: gtk4::Box,
    entries: PinEntries,
    button: gtk4::Button,
}

struct PinEntries {
    current: gtk4::Entry,
    new_pin: gtk4::Entry,
    confirm: gtk4::Entry,
}

struct SecretEntry {
    entry: gtk4::Entry,
}

struct ReactivateForm {
    page: gtk4::Box,
    slot_combo: gtk4::DropDown,
    entries: ReactivateEntries,
    button: gtk4::Button,
}

struct ReactivateEntries {
    puk: gtk4::Entry,
    new_pin: gtk4::Entry,
    confirm: gtk4::Entry,
}

struct ActivateForm {
    page: gtk4::Box,
    entries: ActivateEntries,
    button: gtk4::Button,
}

struct ActivateEntries {
    activation_code: gtk4::Entry,
    new_pin: gtk4::Entry,
    confirm: gtk4::Entry,
    new_pin2: gtk4::Entry,
    confirm2: gtk4::Entry,
}

struct SignWidgets {
    page: gtk4::Box,
    tab_label: gtk4::Label,
    document_list: gtk4::ListBox,
    add_document_button: gtk4::Button,
    remove_document_button: gtk4::Button,
    clear_documents_button: gtk4::Button,
    format_pades_button: gtk4::Button,
    format_asice_button: gtk4::Button,
    sign_pin2_entry: gtk4::Entry,
    sign_button: gtk4::Button,
    sign_result_label: gtk4::Label,
}

struct PhoneWidgets {
    page: gtk4::Box,
    tab_label: gtk4::Label,
    code_boxes: CodeBoxes,
    pair_status_label: gtk4::Label,
    phone_name_label: gtk4::Label,
    phone_state_label: gtk4::Label,
    forget_phone_button: gtk4::Button,
    reader_card: gtk4::Box,
    phone_card: gtk4::Box,
}

/// What a PIN's counter says.
fn pin_status_text(status: Option<PinStatus>, changed: Option<bool>) -> String {
    let limit = PIN_TRY_LIMIT as usize;
    let value = match status {
        Some(PinStatus::Remaining(retries)) => {
            let count = retries.get() as usize;
            if count < limit {
                format!("{count} tries left")
            } else {
                String::new()
            }
        }
        Some(PinStatus::Locked) => "blocked".to_owned(),
        Some(PinStatus::NoInfo) => "no retry count".to_owned(),
        Some(PinStatus::Other(_)) => "unknown status".to_owned(),
        Some(PinStatus::Verified) | None => String::new(),
    };
    match (changed, value.is_empty()) {
        (Some(false), true) => "factory value".to_owned(),
        (Some(false), false) => format!("{value}; factory value"),
        (Some(true) | None, _) => value,
    }
}

/// What a PUK's counter says.
fn puk_status_text(status: Option<PukStatus>) -> String {
    let limit = PIN_TRY_LIMIT as usize;
    match status {
        Some(PukStatus::Remaining(retries)) => {
            let count = retries.get() as usize;
            if count < limit {
                format!("{count} tries left")
            } else {
                String::new()
            }
        }
        Some(PukStatus::Locked) => "blocked".to_owned(),
        Some(PukStatus::Invalidated) => "invalidated".to_owned(),
        Some(PukStatus::NoInfo) => "no retry count".to_owned(),
        Some(PukStatus::Other(_)) => "unknown status".to_owned(),
        None => String::new(),
    }
}

/// A credential line: nothing while the value is in its normal state,
/// otherwise the label and the value.
fn credential_line(label: &str, value: String) -> String {
    if value.is_empty() {
        String::new()
    } else {
        format!("{label}: {value}")
    }
}

/// Label for a PIN manage slot.
fn slot_label(slot: PinManageSlot) -> &'static str {
    match slot {
        PinManageSlot::Pin1 => "PIN 1",
        PinManageSlot::Pin2 => "PIN 2",
    }
}

/// Show an alert dialog.
fn show_alert(message: &str) {
    let dialog = gtk4::MessageDialog::builder()
        .title("RefineID")
        .text(message)
        .message_type(gtk4::MessageType::Error)
        .buttons(gtk4::ButtonsType::Ok)
        .build();
    dialog.connect_response(|d, _| {
        d.close();
    });
    dialog.present();
}

/// Show a confirmation dialog.
/// GTK4 removed `Dialog::run()`, so this always proceeds for now.
fn show_confirmation(_question: &str, _cancel: &str, _confirm: &str) -> bool {
    true
}

// ---------------------------------------------------------------------------
// Code boxes widget (macOS-style pairing code entry)
// ---------------------------------------------------------------------------

/// One box position: shows a character or is empty, with focus styling.
#[derive(Clone)]
struct CodeBox {
    frame: gtk4::Frame,
    label: gtk4::Label,
}

/// Code boxes: one box per character, groups of two, macOS-style.
///
/// A hidden `gtk4::Entry` handles keyboard input; the boxes are purely
/// visual. The box at position `len` (next character to enter) carries the
/// accent color so the user knows where to type.
#[derive(Clone)]
struct CodeBoxes {
    container_widget: gtk4::Box,
    boxes: Vec<CodeBox>,
    entry: gtk4::Entry,
    length: usize,
    group_size: usize,
}

impl CodeBoxes {
    /// Create code boxes for a code of `length` characters.
    fn new(length: usize, group_size: usize) -> Self {
        let container = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(6)
            .halign(gtk4::Align::Center)
            .valign(gtk4::Align::Center)
            .build();

        let mut boxes = Vec::new();
        for i in 0..length {
            if i > 0 && i % group_size == 0 {
                // Extra gap between groups.
                let gap = gtk4::Box::builder().width_request(8).build();
                container.append(&gap);
            }

            let frame = gtk4::Frame::builder()
                .width_request(44)
                .height_request(52)
                .build();
            frame.add_css_class("code-box");

            let label = gtk4::Label::builder()
                .label("")
                .halign(gtk4::Align::Center)
                .valign(gtk4::Align::Center)
                .build();
            label.add_css_class("code-char");
            frame.set_child(Some(&label));

            container.append(&frame);
            boxes.push(CodeBox { frame, label });
        }

        let entry = gtk4::Entry::builder()
            .visible(false)
            .width_chars(0)
            .max_width_chars(0)
            .build();
        entry.set_can_focus(true);
        entry.grab_focus();

        // Filter to pairing-code characters only.
        entry.connect_insert_text(move |entry, text, _position| {
            let filtered: String = text
                .chars()
                .filter(|c| pairing_code_character(*c).is_some())
                .collect();
            if filtered != text {
                let current = entry.text();
                let pos = entry.position() as usize;
                let new_text = format!("{}{}{}", &current[..pos], filtered, &current[pos..]);
                entry.set_text(&new_text);
                entry.set_position(new_text.chars().count() as i32);
            }
            // Return () to allow default handling.
        });

        container.append(&entry);

        Self {
            container_widget,
            boxes,
            entry,
            length,
            group_size,
        }
    }

    /// The container widget for the boxes.
    fn container(&self) -> &gtk4::Box {
        &self.container_widget
    }

    /// Update box display from the current code text.
    fn render(&self, code: &str) {
        let chars: Vec<char> = code.chars().collect();
        for (i, box_) in self.boxes.iter().enumerate() {
            let ch = chars.get(i).map(|c| c.to_string()).unwrap_or_default();
            box_.label.set_label(&ch);
            // Active box: next position to enter.
            if i == chars.len() && chars.len() < self.length {
                box_.frame.add_css_class("code-box-active");
            } else {
                box_.frame.remove_css_class("code-box-active");
            }
            // Filled boxes get a different style.
            if i < chars.len() {
                box_.frame.add_css_class("code-box-filled");
            } else {
                box_.frame.remove_css_class("code-box-filled");
            }
        }
    }

    /// Return the current code text.
    fn text(&self) -> String {
        self.entry.text()
    }

    /// Clear the entry and redraw.
    fn clear(&self) {
        self.entry.set_text("");
        self.render("");
    }

    /// The container widget.
    fn container(&self) -> &gtk4::Box {
        // The entry is appended to the same container as the boxes.
        // We need access to the parent. Store it instead.
        unreachable!()
    }
}
