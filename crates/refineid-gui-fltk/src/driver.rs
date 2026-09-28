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

//! FLTK implementation of the presentation driver for RefineID.

use std::borrow::Cow;
use std::sync::Arc;

use fltk::app::{self, Receiver, Scheme};
use fltk::browser::HoldBrowser;
use fltk::button::{Button, CheckButton, RadioRoundButton};
use fltk::dialog::{FileDialogType, NativeFileChooser, alert, message};
use fltk::enums::{Align, Color, ColorDepth, Font, FrameType};
use fltk::frame::Frame;
use fltk::group::{Group, Tabs};
use fltk::image::RgbImage;
use fltk::input::{Input, SecretInput};
use fltk::menu::Choice;
use fltk::prelude::*;
use fltk::window::Window;

use refineid_gui_core::PinManageSlot;
use refineid_gui_core::controller::RefineIdController;
use refineid_gui_core::driver::UiDriver;
use refineid_gui_core::error::GuiCoreError;
use refineid_gui_core::image::RgbaImageBuffer;
use refineid_gui_core::model::{SignFormat, TimestampConfig, UiState, UserIntent};
use refineid_lib_core::auth::{PinStatus, PukStatus};
use refineid_lib_core::pin::PinBytes;

fn to_pin_bytes(s: &str) -> Option<PinBytes> {
    PinBytes::new(s.as_bytes().to_vec()).ok()
}

fn set_active<W: WidgetExt>(w: &mut W, active: bool) {
    if active {
        w.activate();
    } else {
        w.deactivate();
    }
}

/// Set of GUI widget handles maintained by the FLTK driver.
#[derive(Clone, Debug)]
struct FltkWidgets {
    window: Window,
    card_choice: Choice,
    card_status_badge: Frame,
    serial_frame: Frame,
    pin1_status_frame: Frame,
    pin2_status_frame: Frame,
    puk_status_frame: Frame,
    change_pin1_btn: Button,
    change_pin2_btn: Button,
    reactivate_btn: Button,
    activate_btn: Button,
    can_input: Input,
    read_images_btn: Button,
    portrait_frame: Frame,
    copy_portrait_btn: Button,
    save_portrait_btn: Button,
    signature_frame: Frame,
    copy_sig_btn: Button,
    save_sig_btn: Button,
    doc_browser: HoldBrowser,
    format_pades: RadioRoundButton,
    format_asice: RadioRoundButton,
    sign_btn: Button,
    sign_result_frame: Frame,
    start_pair_btn: Button,
    cancel_pair_btn: Button,
    pair_code_frame: Frame,
    qr_frame: Frame,
    pair_status_frame: Frame,
    status_frame: Frame,
}

/// Presentation driver using the Fast Light Toolkit (FLTK).
pub struct FltkDriver {
    app: app::App,
    state_rx: Receiver<UiState>,
    widgets: Option<FltkWidgets>,
    cached_portrait: Option<Arc<RgbaImageBuffer>>,
    cached_signature: Option<Arc<RgbaImageBuffer>>,
}

impl std::fmt::Debug for FltkDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FltkDriver")
            .field("has_widgets", &self.widgets.is_some())
            .finish_non_exhaustive()
    }
}

/// State change notification callback type.
pub type StateChangeCallback = Box<dyn Fn(&UiState) + Send + Sync + 'static>;

impl FltkDriver {
    /// Create a new FLTK driver and its state notification callback.
    pub fn create() -> (Self, StateChangeCallback) {
        let app = app::App::default().with_scheme(Scheme::Gtk);
        let (state_tx, state_rx) = app::channel::<UiState>();

        let on_state_change = Box::new(move |state: &UiState| {
            state_tx.send(state.clone());
        });

        let driver = Self {
            app,
            state_rx,
            widgets: None,
            cached_portrait: None,
            cached_signature: None,
        };

        (driver, on_state_change)
    }

    /// Build all UI controls and attach callbacks dispatching to `controller`.
    fn init_ui(&mut self, controller: &Arc<RefineIdController>) {
        let window = Window::default().with_size(920, 700).with_label("RefineID");

        // Top bar: Card Reader selector, Refresh, Status
        let mut card_choice = Choice::new(110, 15, 340, 30, "Card Reader:");
        card_choice.set_align(Align::Left);

        let mut refresh_btn = Button::new(460, 15, 90, 30, "Refresh");
        let mut card_status_badge = Frame::new(560, 15, 345, 30, "No Card Detected");
        card_status_badge.set_frame(FrameType::EngravedBox);

        // Main Tabs
        let tabs = Tabs::new(15, 55, 890, 600, "");

        // ---------------------------------------------------------------------
        // TAB 1: Card & PIN Management
        // ---------------------------------------------------------------------
        let pin_tab = Group::new(15, 85, 890, 565, "Card & PIN\t");

        let mut info_box = Group::new(25, 95, 870, 75, "");
        info_box.set_frame(FrameType::EngravedBox);

        let mut serial_frame = Frame::new(35, 105, 400, 25, "Card Serial: N/A");
        serial_frame.set_align(Align::Left | Align::Inside);

        let mut puk_status_frame = Frame::new(450, 105, 430, 25, "PUK: Unknown");
        puk_status_frame.set_align(Align::Left | Align::Inside);

        let mut pin1_status_frame = Frame::new(35, 135, 400, 25, "PIN1 (Authentication): Unknown");
        pin1_status_frame.set_align(Align::Left | Align::Inside);

        let mut pin2_status_frame = Frame::new(450, 135, 430, 25, "PIN2 (Signing): Unknown");
        pin2_status_frame.set_align(Align::Left | Align::Inside);
        info_box.end();

        // Subtabs for PIN operations
        let pin_subtabs = Tabs::new(25, 180, 870, 465, "");

        // Subtab 1: Change PIN1
        let tab_change_pin1 = Group::new(25, 210, 870, 435, "Change PIN1 (Auth)\t");
        let mut p1_note = Frame::new(
            40,
            220,
            840,
            25,
            "PIN1 is used for identity verification and service logins (4 to 12 digits).",
        );
        p1_note.set_align(Align::Left | Align::Inside);

        let mut cur_p1_in = SecretInput::new(250, 255, 250, 30, "Current PIN1:");
        cur_p1_in.set_align(Align::Left);
        let mut new_p1_in = SecretInput::new(250, 295, 250, 30, "New PIN1 (4-12 digits):");
        new_p1_in.set_align(Align::Left);
        let mut conf_p1_in = SecretInput::new(250, 335, 250, 30, "Confirm New PIN1:");
        conf_p1_in.set_align(Align::Left);

        let mut change_pin1_btn = Button::new(250, 380, 180, 35, "Change PIN1");
        tab_change_pin1.end();

        // Subtab 2: Change PIN2
        let tab_change_pin2 = Group::new(25, 210, 870, 435, "Change PIN2 (Signing)\t");
        let mut p2_note = Frame::new(
            40,
            220,
            840,
            25,
            "PIN2 is used for legally binding digital signatures (6 to 12 digits).",
        );
        p2_note.set_align(Align::Left | Align::Inside);

        let mut cur_p2_in = SecretInput::new(250, 255, 250, 30, "Current PIN2:");
        cur_p2_in.set_align(Align::Left);
        let mut new_p2_in = SecretInput::new(250, 295, 250, 30, "New PIN2 (6-12 digits):");
        new_p2_in.set_align(Align::Left);
        let mut conf_p2_in = SecretInput::new(250, 335, 250, 30, "Confirm New PIN2:");
        conf_p2_in.set_align(Align::Left);

        let mut change_pin2_btn = Button::new(250, 380, 180, 35, "Change PIN2");
        tab_change_pin2.end();

        // Subtab 3: Reactivate PIN (PUK)
        let tab_reactivate = Group::new(25, 210, 870, 435, "Reactivate PIN (PUK)\t");
        let mut react_note = Frame::new(
            40,
            220,
            840,
            25,
            "If PIN1 or PIN2 is blocked, enter your PUK code to set a new PIN.",
        );
        react_note.set_align(Align::Left | Align::Inside);

        let mut react_slot_choice = Choice::new(250, 255, 250, 30, "PIN to Reactivate:");
        react_slot_choice.set_align(Align::Left);
        react_slot_choice.add_choice("PIN1 (Authentication)|PIN2 (Signing)");
        react_slot_choice.set_value(0);

        let mut puk_in = SecretInput::new(250, 295, 250, 30, "PUK Code (8 digits):");
        puk_in.set_align(Align::Left);
        let mut react_new_pin = SecretInput::new(250, 335, 250, 30, "New PIN:");
        react_new_pin.set_align(Align::Left);
        let mut react_conf_pin = SecretInput::new(250, 375, 250, 30, "Confirm New PIN:");
        react_conf_pin.set_align(Align::Left);

        let mut reactivate_btn = Button::new(250, 420, 180, 35, "Reactivate PIN");
        tab_reactivate.end();

        // Subtab 4: First-Time Card Activation
        let tab_activate = Group::new(25, 210, 870, 435, "Activate New Card\t");
        let mut act_note = Frame::new(
            40,
            220,
            840,
            25,
            "Enter the factory activation code received with your card to set initial PINs.",
        );
        act_note.set_align(Align::Left | Align::Inside);

        let mut act_code_in = SecretInput::new(260, 255, 250, 30, "Activation Code:");
        act_code_in.set_align(Align::Left);
        let mut act_p1_in = SecretInput::new(260, 295, 250, 30, "New PIN1 (4-12 digits):");
        act_p1_in.set_align(Align::Left);
        let mut act_p1_conf = SecretInput::new(260, 335, 250, 30, "Confirm PIN1:");
        act_p1_conf.set_align(Align::Left);
        let mut act_p2_in = SecretInput::new(260, 375, 250, 30, "New PIN2 (6-12 digits):");
        act_p2_in.set_align(Align::Left);
        let mut act_p2_conf = SecretInput::new(260, 415, 250, 30, "Confirm PIN2:");
        act_p2_conf.set_align(Align::Left);

        let mut activate_btn = Button::new(260, 460, 180, 35, "Activate Card");
        tab_activate.end();

        pin_subtabs.end();
        pin_tab.end();

        // ---------------------------------------------------------------------
        // TAB 2: Identity & PACE (Portrait & Signature)
        // ---------------------------------------------------------------------
        let pace_tab = Group::new(15, 85, 890, 565, "Identity & PACE\t");

        let mut pace_bar = Group::new(25, 95, 870, 45, "");
        pace_bar.set_frame(FrameType::EngravedBox);
        let mut can_label = Frame::new(35, 102, 180, 30, "Card Access Number (CAN):");
        can_label.set_align(Align::Left | Align::Inside);
        let mut can_input = Input::new(220, 102, 100, 30, "");
        can_input.set_maximum_size(6);
        let mut read_images_btn = Button::new(330, 102, 160, 30, "Read Card Data");
        let mut can_hint = Frame::new(
            505,
            102,
            380,
            30,
            "6 digits printed on the front of your card.",
        );
        can_hint.set_align(Align::Left | Align::Inside);
        pace_bar.end();

        // Portrait frame
        let mut p_title = Frame::new(50, 150, 350, 25, "Official Portrait (ICAO eMRTD DG2)");
        p_title.set_align(Align::Center | Align::Inside);
        let mut portrait_frame = Frame::new(75, 180, 300, 390, "No image loaded");
        portrait_frame.set_frame(FrameType::EngravedBox);
        let copy_portrait_btn = Button::new(100, 580, 120, 30, "Copy Image");
        let save_portrait_btn = Button::new(230, 580, 120, 30, "Save As...");

        // Signature frame
        let mut s_title = Frame::new(500, 150, 350, 25, "Cardholder Signature (DG7)");
        s_title.set_align(Align::Center | Align::Inside);
        let mut signature_frame = Frame::new(500, 180, 350, 180, "No signature loaded");
        signature_frame.set_frame(FrameType::EngravedBox);
        let copy_sig_btn = Button::new(530, 375, 140, 30, "Copy Signature");
        let save_sig_btn = Button::new(685, 375, 140, 30, "Save As...");

        let mut pace_info = Frame::new(
            500,
            425,
            350,
            185,
            "Protected by PACE (Password Authenticated\nConnection Establishment) with EAC1.\n\nBiometric portrait and signature data are read\nsecurely using PACE-ECDH key agreement.",
        );
        pace_info.set_frame(FrameType::EngravedBox);
        pace_info.set_align(Align::Center | Align::Inside);

        pace_tab.end();

        // ---------------------------------------------------------------------
        // TAB 3: Sign Documents
        // ---------------------------------------------------------------------
        let sign_tab = Group::new(15, 85, 890, 565, "Sign Documents\t");

        let mut queue_label = Frame::new(35, 95, 200, 25, "Queued Documents:");
        queue_label.set_align(Align::Left | Align::Inside);

        let doc_browser = HoldBrowser::new(35, 120, 520, 280, "");
        let mut add_doc_btn = Button::new(35, 410, 150, 30, "Add Files...");
        let mut remove_doc_btn = Button::new(195, 410, 150, 30, "Remove Selected");
        let mut clear_docs_btn = Button::new(355, 410, 120, 30, "Clear List");

        let mut sign_settings = Group::new(575, 100, 320, 440, "");
        sign_settings.set_frame(FrameType::EngravedBox);

        let mut fmt_label = Frame::new(590, 110, 200, 25, "Signature Format:");
        fmt_label.set_align(Align::Left | Align::Inside);

        let mut format_pades = RadioRoundButton::new(590, 135, 280, 25, "PAdES (Embedded in PDF)");
        format_pades.set_value(true);
        let format_asice =
            RadioRoundButton::new(590, 165, 280, 25, "ASiC-E (Associated Container)");

        let mut tsa_label = Frame::new(590, 205, 200, 25, "Timestamp Authority:");
        tsa_label.set_align(Align::Left | Align::Inside);
        let mut tsa_check = CheckButton::new(590, 230, 280, 25, "Include Qualified Timestamp");
        tsa_check.set_value(true);
        let mut tsa_url_input = Input::new(590, 260, 290, 28, "");
        tsa_url_input.set_value("https://timestamp.sectigo.com/qualified");

        let mut p2_label = Frame::new(590, 305, 200, 25, "PIN2 (Signing PIN):");
        p2_label.set_align(Align::Left | Align::Inside);
        let sign_pin2_input = SecretInput::new(590, 330, 290, 30, "");

        let mut sign_btn = Button::new(590, 375, 290, 40, "Sign Documents");

        let mut sign_result_frame = Frame::new(35, 460, 520, 80, "");
        sign_result_frame.set_frame(FrameType::EngravedBox);
        sign_result_frame.set_align(Align::Left | Align::Inside);

        sign_settings.end();
        sign_tab.end();

        // ---------------------------------------------------------------------
        // TAB 4: Phone Pairing (RAPP / CPace PAKE)
        // ---------------------------------------------------------------------
        let rapp_tab = Group::new(15, 85, 890, 565, "Phone Pairing (RAPP)\t");

        let mut rapp_desc = Frame::new(
            40,
            95,
            830,
            40,
            "Pair your smartphone running RefineID Authenticator using secure CPace PAKE (RFC 9383).\nAllows authorized mobile apps to perform signatures and logins using this smart card.",
        );
        rapp_desc.set_align(Align::Left | Align::Inside);

        let mut start_pair_btn = Button::new(60, 150, 180, 35, "Start New Pairing");
        let mut cancel_pair_btn = Button::new(260, 150, 140, 35, "Cancel");

        let mut pcode_lbl = Frame::new(60, 205, 340, 25, "Pairing Verification Code:");
        pcode_lbl.set_align(Align::Left | Align::Inside);

        let mut pair_code_frame = Frame::new(60, 235, 340, 65, "---   ---");
        pair_code_frame.set_frame(FrameType::EngravedBox);
        pair_code_frame.set_label_font(Font::CourierBold);
        pair_code_frame.set_label_size(28);

        let mut pair_status_frame = Frame::new(60, 320, 340, 50, "Status: Idle");
        pair_status_frame.set_frame(FrameType::EngravedBox);
        pair_status_frame.set_align(Align::Center | Align::Inside);

        let mut qr_frame = Frame::new(
            450,
            150,
            380,
            380,
            "QR Code will appear when pairing starts",
        );
        qr_frame.set_frame(FrameType::EngravedBox);
        qr_frame.set_align(Align::Center | Align::Inside);

        rapp_tab.end();
        tabs.end();

        // Bottom status bar
        let mut status_frame = Frame::new(15, 665, 890, 25, "Initializing RefineID...");
        status_frame.set_frame(FrameType::EngravedBox);
        status_frame.set_align(Align::Left | Align::Inside);

        window.end();

        // ---------------------------------------------------------------------
        // Set up Callbacks
        // ---------------------------------------------------------------------
        {
            let c = Arc::clone(controller);
            card_choice.set_callback(move |choice| {
                let idx = choice.value() as usize;
                c.handle_intent(UserIntent::SelectCard(idx));
            });
        }
        {
            let c = Arc::clone(controller);
            refresh_btn.set_callback(move |_| {
                c.handle_intent(UserIntent::RefreshCards);
            });
        }
        {
            let c = Arc::clone(controller);
            let mut cur = cur_p1_in.clone();
            let mut new = new_p1_in.clone();
            let mut conf = conf_p1_in.clone();
            change_pin1_btn.set_callback(move |_| {
                let cur_val = cur.value();
                let new_val = new.value();
                let conf_val = conf.value();

                if new_val != conf_val {
                    alert(200, 200, "New PIN1 entries do not match.");
                    return;
                }
                if new_val.len() < 4 || new_val.len() > 12 {
                    alert(200, 200, "PIN1 must be between 4 and 12 digits.");
                    return;
                }
                let (Some(cur_pin), Some(new_pin)) =
                    (to_pin_bytes(&cur_val), to_pin_bytes(&new_val))
                else {
                    alert(200, 200, "PIN contains invalid characters.");
                    return;
                };
                c.handle_intent(UserIntent::ChangePin {
                    slot: PinManageSlot::Pin1,
                    current_pin: cur_pin,
                    new_pin,
                });
                cur.set_value("");
                new.set_value("");
                conf.set_value("");
            });
        }
        {
            let c = Arc::clone(controller);
            let mut cur = cur_p2_in.clone();
            let mut new = new_p2_in.clone();
            let mut conf = conf_p2_in.clone();
            change_pin2_btn.set_callback(move |_| {
                let cur_val = cur.value();
                let new_val = new.value();
                let conf_val = conf.value();

                if new_val != conf_val {
                    alert(200, 200, "New PIN2 entries do not match.");
                    return;
                }
                if new_val.len() < 6 || new_val.len() > 12 {
                    alert(200, 200, "PIN2 must be between 6 and 12 digits.");
                    return;
                }
                let (Some(cur_pin), Some(new_pin)) =
                    (to_pin_bytes(&cur_val), to_pin_bytes(&new_val))
                else {
                    alert(200, 200, "PIN contains invalid characters.");
                    return;
                };
                c.handle_intent(UserIntent::ChangePin {
                    slot: PinManageSlot::Pin2,
                    current_pin: cur_pin,
                    new_pin,
                });
                cur.set_value("");
                new.set_value("");
                conf.set_value("");
            });
        }
        {
            let c = Arc::clone(controller);
            let slot_choice = react_slot_choice.clone();
            let mut puk = puk_in.clone();
            let mut new = react_new_pin.clone();
            let mut conf = react_conf_pin.clone();
            reactivate_btn.set_callback(move |_| {
                let slot = match slot_choice.value() {
                    1 => PinManageSlot::Pin2,
                    _ => PinManageSlot::Pin1,
                };
                let puk_val = puk.value();
                let new_val = new.value();
                let conf_val = conf.value();

                if new_val != conf_val {
                    alert(200, 200, "New PIN entries do not match.");
                    return;
                }
                let min_len = match slot {
                    PinManageSlot::Pin1 => 4,
                    PinManageSlot::Pin2 => 6,
                };
                if new_val.len() < min_len || new_val.len() > 12 {
                    alert(
                        200,
                        200,
                        &format!("PIN must be between {min_len} and 12 digits."),
                    );
                    return;
                }
                let (Some(puk_pin), Some(new_pin)) =
                    (to_pin_bytes(&puk_val), to_pin_bytes(&new_val))
                else {
                    alert(200, 200, "PUK or PIN contains invalid characters.");
                    return;
                };
                c.handle_intent(UserIntent::ReactivatePin {
                    slot,
                    puk: puk_pin,
                    new_pin,
                });
                puk.set_value("");
                new.set_value("");
                conf.set_value("");
            });
        }
        {
            let c = Arc::clone(controller);
            let mut act = act_code_in.clone();
            let mut p1 = act_p1_in.clone();
            let mut p1c = act_p1_conf.clone();
            let mut p2 = act_p2_in.clone();
            let mut p2c = act_p2_conf.clone();
            activate_btn.set_callback(move |_| {
                let act_val = act.value();
                let p1_val = p1.value();
                let p1c_val = p1c.value();
                let p2_val = p2.value();
                let p2c_val = p2c.value();

                if p1_val != p1c_val {
                    alert(200, 200, "PIN1 entries do not match.");
                    return;
                }
                if p2_val != p2c_val {
                    alert(200, 200, "PIN2 entries do not match.");
                    return;
                }
                if p1_val.len() < 4 || p1_val.len() > 12 {
                    alert(200, 200, "PIN1 must be between 4 and 12 digits.");
                    return;
                }
                if p2_val.len() < 6 || p2_val.len() > 12 {
                    alert(200, 200, "PIN2 must be between 6 and 12 digits.");
                    return;
                }
                let (Some(act_code), Some(new_p1), Some(new_p2)) = (
                    to_pin_bytes(&act_val),
                    to_pin_bytes(&p1_val),
                    to_pin_bytes(&p2_val),
                ) else {
                    alert(
                        200,
                        200,
                        "Activation code or PINs contain invalid characters.",
                    );
                    return;
                };
                c.handle_intent(UserIntent::ActivateCard {
                    activation_code: act_code,
                    new_pin1: new_p1,
                    new_pin2: new_p2,
                });
                act.set_value("");
                p1.set_value("");
                p1c.set_value("");
                p2.set_value("");
                p2c.set_value("");
            });
        }
        {
            let c = Arc::clone(controller);
            let can = can_input.clone();
            read_images_btn.set_callback(move |_| {
                let can_val = can.value();
                if can_val.len() != 6 || !can_val.chars().all(|ch| ch.is_ascii_digit()) {
                    alert(200, 200, "CAN must be exactly 6 numeric digits.");
                    return;
                }
                let Some(can_pin) = to_pin_bytes(&can_val) else {
                    alert(200, 200, "CAN contains invalid characters.");
                    return;
                };
                c.handle_intent(UserIntent::LoadImages { can: can_pin });
            });
        }
        {
            let c = Arc::clone(controller);
            add_doc_btn.set_callback(move |_| {
                let mut chooser = NativeFileChooser::new(FileDialogType::BrowseMultiFile);
                chooser.set_filter("PDF Documents\t*.{pdf,PDF}\nAll Files\t*.*");
                chooser.show();
                let paths = chooser.filenames();
                if !paths.is_empty() {
                    c.handle_intent(UserIntent::AddDocuments(paths));
                }
            });
        }
        {
            let c = Arc::clone(controller);
            let browser = doc_browser.clone();
            remove_doc_btn.set_callback(move |_| {
                let val = browser.value();
                if val > 0 {
                    let idx = (val - 1) as usize;
                    let current = c.state().pdf_documents;
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
            clear_docs_btn.set_callback(move |_| {
                c.handle_intent(UserIntent::ClearDocuments);
            });
        }
        {
            let c = Arc::clone(controller);
            let mut pades = format_pades.clone();
            pades.set_callback(move |_| {
                c.handle_intent(UserIntent::SetSignFormat(SignFormat::Pades));
            });
        }
        {
            let c = Arc::clone(controller);
            let mut asice = format_asice.clone();
            asice.set_callback(move |_| {
                c.handle_intent(UserIntent::SetSignFormat(SignFormat::AsicE));
            });
        }
        {
            let c = Arc::clone(controller);
            let tsa_url = tsa_url_input.clone();
            tsa_check.set_callback({
                let c = Arc::clone(&c);
                let tsa_url = tsa_url.clone();
                move |_chk| {
                    c.handle_intent(UserIntent::SetTimestampConfig(TimestampConfig {
                        host_path: tsa_url.value(),
                        username: None,
                        password: None,
                    }));
                }
            });
            tsa_url_input.set_callback(move |input| {
                c.handle_intent(UserIntent::SetTimestampConfig(TimestampConfig {
                    host_path: input.value(),
                    username: None,
                    password: None,
                }));
            });
        }
        {
            let c = Arc::clone(controller);
            let mut p2 = sign_pin2_input.clone();
            sign_btn.set_callback(move |_| {
                let pin2_val = p2.value();
                if pin2_val.len() < 6 {
                    alert(200, 200, "PIN2 must be at least 6 digits.");
                    return;
                }
                let Some(pin2) = to_pin_bytes(&pin2_val) else {
                    alert(200, 200, "PIN2 contains invalid characters.");
                    return;
                };
                c.handle_intent(UserIntent::SignDocuments { pin2 });
                p2.set_value("");
            });
        }
        {
            let c = Arc::clone(controller);
            start_pair_btn.set_callback(move |_| {
                c.handle_intent(UserIntent::StartPairing);
            });
        }
        {
            let c = Arc::clone(controller);
            cancel_pair_btn.set_callback(move |_| {
                c.handle_intent(UserIntent::CancelPairing);
            });
        }

        self.widgets = Some(FltkWidgets {
            window,
            card_choice,
            card_status_badge,
            serial_frame,
            pin1_status_frame,
            pin2_status_frame,
            puk_status_frame,
            change_pin1_btn,
            change_pin2_btn,
            reactivate_btn,
            activate_btn,
            can_input,
            read_images_btn,
            portrait_frame,
            copy_portrait_btn,
            save_portrait_btn,
            signature_frame,
            copy_sig_btn,
            save_sig_btn,
            doc_browser,
            format_pades,
            format_asice,
            sign_btn,
            sign_result_frame,
            start_pair_btn,
            cancel_pair_btn,
            pair_code_frame,
            qr_frame,
            pair_status_frame,
            status_frame,
        });

        self.wire_image_actions();
    }

    /// Wire up image clipboard copying and save file actions.
    fn wire_image_actions(&mut self) {
        if let Some(ref widgets) = self.widgets {
            let mut copy_p = widgets.copy_portrait_btn.clone();
            copy_p.set_callback(|_| {
                copy_image_to_clipboard();
            });

            let mut save_p = widgets.save_portrait_btn.clone();
            save_p.set_callback(|_| {
                save_image_to_file();
            });

            let mut copy_s = widgets.copy_sig_btn.clone();
            copy_s.set_callback(|_| {
                copy_sig_to_clipboard();
            });

            let mut save_s = widgets.save_sig_btn.clone();
            save_s.set_callback(|_| {
                save_sig_to_file();
            });
        }
    }
}

// Global cached image slots for the clipboard/save dialogs
static CURRENT_PORTRAIT: std::sync::RwLock<Option<Arc<RgbaImageBuffer>>> =
    std::sync::RwLock::new(None);
static CURRENT_SIGNATURE: std::sync::RwLock<Option<Arc<RgbaImageBuffer>>> =
    std::sync::RwLock::new(None);

fn copy_image_to_clipboard() {
    let guard = CURRENT_PORTRAIT.read().expect("current portrait lock");
    if let Some(ref portrait) = *guard
        && let Ok(mut cb) = arboard::Clipboard::new()
    {
        let img_data = arboard::ImageData {
            width: portrait.width() as usize,
            height: portrait.height() as usize,
            bytes: Cow::Borrowed(portrait.rgba_bytes()),
        };
        if cb.set_image(img_data).is_ok() {
            message(200, 200, "Portrait image copied to clipboard.");
            return;
        }
    }
    alert(200, 200, "Failed to copy image to clipboard.");
}

fn save_image_to_file() {
    let guard = CURRENT_PORTRAIT.read().expect("current portrait lock");
    if let Some(ref portrait) = *guard {
        let mut chooser = NativeFileChooser::new(FileDialogType::BrowseSaveFile);
        chooser.set_filter("PNG Images\t*.png");
        chooser.show();
        let path = chooser.filename();
        if !path.as_os_str().is_empty() {
            let mut save_path = path;
            if save_path.extension().is_none() {
                save_path.set_extension("png");
            }
            if image::save_buffer(
                &save_path,
                portrait.rgba_bytes(),
                portrait.width(),
                portrait.height(),
                image::ExtendedColorType::Rgba8,
            )
            .is_ok()
            {
                message(
                    200,
                    200,
                    &format!("Saved portrait to {}", save_path.display()),
                );
                return;
            }
        }
    }
    alert(200, 200, "Failed to save portrait image.");
}

fn copy_sig_to_clipboard() {
    let guard = CURRENT_SIGNATURE.read().expect("current signature lock");
    if let Some(ref sig) = *guard
        && let Ok(mut cb) = arboard::Clipboard::new()
    {
        let img_data = arboard::ImageData {
            width: sig.width() as usize,
            height: sig.height() as usize,
            bytes: Cow::Borrowed(sig.rgba_bytes()),
        };
        if cb.set_image(img_data).is_ok() {
            message(200, 200, "Signature image copied to clipboard.");
            return;
        }
    }
    alert(200, 200, "Failed to copy signature to clipboard.");
}

fn save_sig_to_file() {
    let guard = CURRENT_SIGNATURE.read().expect("current signature lock");
    if let Some(ref sig) = *guard {
        let mut chooser = NativeFileChooser::new(FileDialogType::BrowseSaveFile);
        chooser.set_filter("PNG Images\t*.png");
        chooser.show();
        let path = chooser.filename();
        if !path.as_os_str().is_empty() {
            let mut save_path = path;
            if save_path.extension().is_none() {
                save_path.set_extension("png");
            }
            if image::save_buffer(
                &save_path,
                sig.rgba_bytes(),
                sig.width(),
                sig.height(),
                image::ExtendedColorType::Rgba8,
            )
            .is_ok()
            {
                message(
                    200,
                    200,
                    &format!("Saved signature to {}", save_path.display()),
                );
                return;
            }
        }
    }
    alert(200, 200, "Failed to save signature image.");
}

/// Create a fitted FLTK `RgbImage` preserving aspect ratio.
fn create_fitted_image(buf: &RgbaImageBuffer, max_w: i32, max_h: i32) -> Option<RgbImage> {
    if buf.width() == 0 || buf.height() == 0 || buf.rgba_bytes().is_empty() {
        return None;
    }
    let mut fltk_img = RgbImage::new(
        buf.rgba_bytes(),
        buf.width() as i32,
        buf.height() as i32,
        ColorDepth::Rgba8,
    )
    .ok()?;

    let aspect = buf.width() as f64 / buf.height() as f64;
    let (target_w, target_h) = if (max_w as f64 / max_h as f64) > aspect {
        ((max_h as f64 * aspect) as i32, max_h)
    } else {
        (max_w, (max_w as f64 / aspect) as i32)
    };

    fltk_img.scale(target_w, target_h, true, true);
    Some(fltk_img)
}

/// Render a 2D boolean matrix of QR modules into an FLTK `RgbImage`.
fn render_qr_image(matrix: &[Vec<bool>], target_size: i32) -> Option<RgbImage> {
    let size = matrix.len();
    if size == 0 {
        return None;
    }
    let quiet_zone = 4;
    let full_modules = size + 2 * quiet_zone;
    let scale = (target_size / full_modules as i32).max(1);
    let img_dim = full_modules as i32 * scale;
    let mut buf = vec![255u8; (img_dim * img_dim * 3) as usize];

    for (y, row) in matrix.iter().enumerate() {
        for (x, &is_dark) in row.iter().enumerate() {
            if is_dark {
                let px_start_x = (x + quiet_zone) as i32 * scale;
                let px_start_y = (y + quiet_zone) as i32 * scale;
                for py in 0..scale {
                    for px in 0..scale {
                        let idx = (((px_start_y + py) * img_dim + (px_start_x + px)) * 3) as usize;
                        if idx + 2 < buf.len() {
                            buf[idx] = 0;
                            buf[idx + 1] = 0;
                            buf[idx + 2] = 0;
                        }
                    }
                }
            }
        }
    }
    RgbImage::new(&buf, img_dim, img_dim, ColorDepth::Rgb8).ok()
}

impl UiDriver for FltkDriver {
    fn init(&mut self) -> Result<(), GuiCoreError> {
        Ok(())
    }

    fn render(&mut self, state: &UiState) {
        let Some(widgets) = self.widgets.as_mut() else {
            return;
        };

        // Window Title & Status
        widgets.window.set_label(&state.window_title);
        widgets.status_frame.set_label(&state.status_message);

        // Top bar: Card selector
        widgets.card_choice.clear();
        for card in &state.cards {
            widgets.card_choice.add_choice(&card.label());
        }
        if let Some(idx) = state.selected_card {
            widgets.card_choice.set_value(idx as i32);
        }

        // Top bar: Card presence badge
        if state.cards.is_empty() {
            widgets.card_status_badge.set_label("No Card Detected");
            widgets
                .card_status_badge
                .set_label_color(Color::from_rgb(120, 120, 120));
        } else if state.busy {
            widgets.card_status_badge.set_label("Processing...");
            widgets
                .card_status_badge
                .set_label_color(Color::from_rgb(200, 150, 0));
        } else {
            widgets.card_status_badge.set_label("Card Ready");
            widgets
                .card_status_badge
                .set_label_color(Color::from_rgb(0, 150, 0));
        }

        // Tab 1: Card & PIN Status
        widgets.serial_frame.set_label(&format!(
            "Card Serial: {}",
            state.card_serial.as_deref().unwrap_or("N/A")
        ));

        let p1_text = match state.pin1_status {
            Some(PinStatus::Remaining(retries)) => {
                let count = retries.get();
                if retries.is_exhausted() {
                    "PIN1 (Authentication): BLOCKED".to_string()
                } else {
                    format!("PIN1 (Authentication): Valid ({count} retries left)")
                }
            }
            Some(PinStatus::Verified) => "PIN1 (Authentication): Verified".to_string(),
            Some(PinStatus::Locked) => "PIN1 (Authentication): BLOCKED".to_string(),
            Some(PinStatus::NoInfo) => "PIN1 (Authentication): No retry info".to_string(),
            Some(PinStatus::Other(sw)) => format!("PIN1 (Authentication): Status 0x{sw:04X}"),
            None => "PIN1 (Authentication): Not Inspected".to_string(),
        };
        widgets.pin1_status_frame.set_label(&p1_text);

        let p2_text = match state.pin2_status {
            Some(PinStatus::Remaining(retries)) => {
                let count = retries.get();
                if retries.is_exhausted() {
                    "PIN2 (Signing): BLOCKED".to_string()
                } else {
                    format!("PIN2 (Signing): Valid ({count} retries left)")
                }
            }
            Some(PinStatus::Verified) => "PIN2 (Signing): Verified".to_string(),
            Some(PinStatus::Locked) => "PIN2 (Signing): BLOCKED".to_string(),
            Some(PinStatus::NoInfo) => "PIN2 (Signing): No retry info".to_string(),
            Some(PinStatus::Other(sw)) => format!("PIN2 (Signing): Status 0x{sw:04X}"),
            None => "PIN2 (Signing): Not Inspected".to_string(),
        };
        widgets.pin2_status_frame.set_label(&p2_text);

        let puk_text = match state.puk_status {
            Some(PukStatus::Remaining(retries)) => {
                let count = retries.get();
                if retries.is_exhausted() {
                    "PUK: BLOCKED".to_string()
                } else {
                    format!("PUK: Valid ({count} retries left)")
                }
            }
            Some(PukStatus::Locked) => "PUK: BLOCKED".to_string(),
            Some(PukStatus::Invalidated) => "PUK: Invalidated".to_string(),
            Some(PukStatus::NoInfo) => "PUK: No retry info".to_string(),
            Some(PukStatus::Other(sw)) => format!("PUK: Status 0x{sw:04X}"),
            None => "PUK: Unknown".to_string(),
        };
        widgets.puk_status_frame.set_label(&puk_text);

        set_active(
            &mut widgets.change_pin1_btn,
            state.pin1_change_available && !state.busy,
        );
        set_active(
            &mut widgets.change_pin2_btn,
            state.pin2_change_available && !state.busy,
        );
        set_active(
            &mut widgets.reactivate_btn,
            (state.pin1_unblock_available || state.pin2_unblock_available) && !state.busy,
        );
        set_active(
            &mut widgets.activate_btn,
            state.activation_available && !state.busy,
        );

        // Tab 2: Identity & PACE
        set_active(
            &mut widgets.read_images_btn,
            !state.busy && state.selected_card.is_some(),
        );
        if !state.can_text.is_empty() && widgets.can_input.value().is_empty() {
            widgets.can_input.set_value(&state.can_text);
        }

        // Update portrait frame
        if state.portrait.as_ref() != self.cached_portrait.as_ref() {
            self.cached_portrait = state.portrait.clone();
            *CURRENT_PORTRAIT
                .write()
                .expect("current portrait write lock") = state.portrait.clone();

            if let Some(ref buf) = state.portrait {
                if let Some(img) = create_fitted_image(buf, 290, 380) {
                    widgets.portrait_frame.set_label("");
                    widgets.portrait_frame.set_image(Some(img));
                }
                set_active(&mut widgets.copy_portrait_btn, true);
                set_active(&mut widgets.save_portrait_btn, true);
            } else {
                widgets.portrait_frame.set_image(None::<RgbImage>);
                widgets.portrait_frame.set_label("No image loaded");
                set_active(&mut widgets.copy_portrait_btn, false);
                set_active(&mut widgets.save_portrait_btn, false);
            }
            widgets.portrait_frame.redraw();
        }

        // Update signature frame
        if state.signature.as_ref() != self.cached_signature.as_ref() {
            self.cached_signature = state.signature.clone();
            *CURRENT_SIGNATURE
                .write()
                .expect("current signature write lock") = state.signature.clone();

            if let Some(ref buf) = state.signature {
                if let Some(img) = create_fitted_image(buf, 340, 170) {
                    widgets.signature_frame.set_label("");
                    widgets.signature_frame.set_image(Some(img));
                }
                set_active(&mut widgets.copy_sig_btn, true);
                set_active(&mut widgets.save_sig_btn, true);
            } else {
                widgets.signature_frame.set_image(None::<RgbImage>);
                widgets.signature_frame.set_label("No signature loaded");
                set_active(&mut widgets.copy_sig_btn, false);
                set_active(&mut widgets.save_sig_btn, false);
            }
            widgets.signature_frame.redraw();
        }

        // Tab 3: Sign Documents
        widgets.doc_browser.clear();
        for p in &state.pdf_documents {
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                widgets.doc_browser.add(name);
            } else {
                widgets.doc_browser.add(&p.display().to_string());
            }
        }

        match state.sign_format {
            SignFormat::Pades => widgets.format_pades.set_value(true),
            SignFormat::AsicE => widgets.format_asice.set_value(true),
        }

        let can_sign =
            !state.pdf_documents.is_empty() && !state.busy && state.selected_card.is_some();
        set_active(&mut widgets.sign_btn, can_sign);

        if let Some(ref result) = state.sign_result {
            widgets.sign_result_frame.set_label(result);
        } else {
            widgets.sign_result_frame.set_label("");
        }

        // Tab 4: Phone Pairing (RAPP)
        if let Some(ref pairing) = state.pairing {
            widgets.pair_code_frame.set_label(&pairing.code);
            widgets.pair_status_frame.set_label(&pairing.status);

            if let Some(ref modules) = pairing.qr_modules
                && let Some(qr_img) = render_qr_image(modules, 340)
            {
                widgets.qr_frame.set_label("");
                widgets.qr_frame.set_image(Some(qr_img));
            }
            set_active(&mut widgets.start_pair_btn, false);
            set_active(&mut widgets.cancel_pair_btn, true);
        } else {
            widgets.pair_code_frame.set_label("---   ---");
            widgets.pair_status_frame.set_label("Status: Idle");
            widgets.qr_frame.set_image(None::<RgbImage>);
            widgets
                .qr_frame
                .set_label("QR Code will appear when pairing starts");
            set_active(&mut widgets.start_pair_btn, true);
            set_active(&mut widgets.cancel_pair_btn, false);
        }
        widgets.qr_frame.redraw();
    }

    fn run(mut self, controller: Arc<RefineIdController>) -> Result<(), GuiCoreError> {
        self.init_ui(&controller);

        // Apply initial state
        self.render(&controller.state());

        if let Some(ref mut widgets) = self.widgets {
            widgets.window.show();
        }

        while self.app.wait() {
            while let Some(state) = self.state_rx.recv() {
                self.render(&state);
            }
        }

        controller.stop();
        Ok(())
    }
}
