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
use fltk::dialog::{FileDialogType, NativeFileChooser, alert, input_default, message};
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
    holder_name_frame: Frame,
    holder_sub_frame: Frame,
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
        app::set_background_color(245, 246, 248);
        app::set_foreground_color(33, 37, 41);
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
        let window = Window::default().with_size(920, 680).with_label("RefineID");

        // Top bar: Card selector, Refresh, Status Badge
        let mut card_choice = Choice::new(70, 15, 520, 32, "Card:");
        card_choice.set_align(Align::Left);

        let mut refresh_btn = Button::new(605, 15, 80, 32, "Refresh");
        let mut card_status_badge = Frame::new(695, 15, 205, 32, "No Card Detected");
        card_status_badge.set_frame(FrameType::RFlatBox);
        card_status_badge.set_label_font(Font::HelveticaBold);
        card_status_badge.set_label_size(12);

        // Main Tabs
        let tabs = Tabs::new(20, 58, 880, 580, "");

        // ---------------------------------------------------------------------
        // TAB 1: Card & PIN Management
        // ---------------------------------------------------------------------
        let pin_tab = Group::new(20, 88, 880, 550, "Card & PIN   ");

        // Hero Card: Cardholder profile and PIN retries
        let mut hero_card = Group::new(35, 98, 850, 96, "");
        hero_card.set_frame(FrameType::RFlatBox);
        hero_card.set_color(Color::from_rgb(255, 255, 255));

        let mut holder_name_frame = Frame::new(50, 108, 430, 28, "No Card Detected");
        holder_name_frame.set_label_font(Font::HelveticaBold);
        holder_name_frame.set_label_size(18);
        holder_name_frame.set_align(Align::Left | Align::Inside);

        let mut holder_sub_frame =
            Frame::new(50, 138, 430, 20, "Insert your smart card into the reader");
        holder_sub_frame.set_label_size(12);
        holder_sub_frame.set_label_color(Color::from_rgb(108, 117, 125));
        holder_sub_frame.set_align(Align::Left | Align::Inside);

        let mut serial_frame = Frame::new(50, 160, 430, 18, "");
        serial_frame.set_label_size(11);
        serial_frame.set_label_color(Color::from_rgb(140, 145, 150));
        serial_frame.set_align(Align::Left | Align::Inside);

        let mut pin1_status_frame =
            Frame::new(490, 108, 380, 24, "Authentication PIN (PIN 1): Unknown");
        pin1_status_frame.set_label_size(12);
        pin1_status_frame.set_align(Align::Left | Align::Inside);

        let mut pin2_status_frame = Frame::new(490, 134, 380, 24, "Signing PIN (PIN 2): Unknown");
        pin2_status_frame.set_label_size(12);
        pin2_status_frame.set_align(Align::Left | Align::Inside);

        let mut puk_status_frame = Frame::new(490, 160, 380, 24, "PUK Code: Unknown");
        puk_status_frame.set_label_size(12);
        puk_status_frame.set_align(Align::Left | Align::Inside);
        hero_card.end();

        // Subtabs for PIN operations
        let pin_subtabs = Tabs::new(35, 204, 850, 420, "");

        // Subtab 1: Change PIN 1
        let mut tab_change_pin1 = Group::new(35, 234, 850, 390, "Change PIN 1   ");
        tab_change_pin1.set_frame(FrameType::RFlatBox);
        tab_change_pin1.set_color(Color::from_rgb(255, 255, 255));

        let mut l1 = Frame::new(120, 265, 150, 32, "Current PIN 1:");
        l1.set_align(Align::Right | Align::Inside);
        let cur_p1_in = SecretInput::new(285, 265, 260, 32, "");

        let mut l2 = Frame::new(120, 310, 150, 32, "New PIN 1:");
        l2.set_align(Align::Right | Align::Inside);
        let new_p1_in = SecretInput::new(285, 310, 260, 32, "");

        let mut l3 = Frame::new(120, 355, 150, 32, "Confirm PIN 1:");
        l3.set_align(Align::Right | Align::Inside);
        let conf_p1_in = SecretInput::new(285, 355, 260, 32, "");

        let mut change_pin1_btn = Button::new(285, 405, 180, 36, "Change PIN 1");
        change_pin1_btn.set_color(Color::from_rgb(0, 122, 255));
        change_pin1_btn.set_label_color(Color::from_rgb(255, 255, 255));
        change_pin1_btn.set_label_font(Font::HelveticaBold);
        tab_change_pin1.end();

        // Subtab 2: Change PIN 2
        let mut tab_change_pin2 = Group::new(35, 234, 850, 390, "Change PIN 2   ");
        tab_change_pin2.set_frame(FrameType::RFlatBox);
        tab_change_pin2.set_color(Color::from_rgb(255, 255, 255));

        let mut l1_p2 = Frame::new(120, 265, 150, 32, "Current PIN 2:");
        l1_p2.set_align(Align::Right | Align::Inside);
        let cur_p2_in = SecretInput::new(285, 265, 260, 32, "");

        let mut l2_p2 = Frame::new(120, 310, 150, 32, "New PIN 2:");
        l2_p2.set_align(Align::Right | Align::Inside);
        let new_p2_in = SecretInput::new(285, 310, 260, 32, "");

        let mut l3_p2 = Frame::new(120, 355, 150, 32, "Confirm PIN 2:");
        l3_p2.set_align(Align::Right | Align::Inside);
        let conf_p2_in = SecretInput::new(285, 355, 260, 32, "");

        let mut change_pin2_btn = Button::new(285, 405, 180, 36, "Change PIN 2");
        change_pin2_btn.set_color(Color::from_rgb(0, 122, 255));
        change_pin2_btn.set_label_color(Color::from_rgb(255, 255, 255));
        change_pin2_btn.set_label_font(Font::HelveticaBold);
        tab_change_pin2.end();

        // Subtab 3: Unblock PIN
        let mut tab_reactivate = Group::new(35, 234, 850, 390, "Unblock PIN   ");
        tab_reactivate.set_frame(FrameType::RFlatBox);
        tab_reactivate.set_color(Color::from_rgb(255, 255, 255));

        let mut l_slot = Frame::new(120, 260, 150, 32, "PIN to Unblock:");
        l_slot.set_align(Align::Right | Align::Inside);
        let mut react_slot_choice = Choice::new(285, 260, 260, 32, "");
        react_slot_choice.add_choice("PIN 1 (Authentication)|PIN 2 (Signing)");
        react_slot_choice.set_value(0);

        let mut l_puk = Frame::new(120, 300, 150, 32, "PUK Code:");
        l_puk.set_align(Align::Right | Align::Inside);
        let puk_in = SecretInput::new(285, 300, 260, 32, "");

        let mut l_rnew = Frame::new(120, 340, 150, 32, "New PIN:");
        l_rnew.set_align(Align::Right | Align::Inside);
        let react_new_pin = SecretInput::new(285, 340, 260, 32, "");

        let mut l_rconf = Frame::new(120, 380, 150, 32, "Confirm New PIN:");
        l_rconf.set_align(Align::Right | Align::Inside);
        let react_conf_pin = SecretInput::new(285, 380, 260, 32, "");

        let mut reactivate_btn = Button::new(285, 428, 180, 36, "Unblock PIN");
        reactivate_btn.set_color(Color::from_rgb(0, 122, 255));
        reactivate_btn.set_label_color(Color::from_rgb(255, 255, 255));
        reactivate_btn.set_label_font(Font::HelveticaBold);
        tab_reactivate.end();

        // Subtab 4: First-Time Setup
        let mut tab_activate = Group::new(35, 234, 850, 390, "First-Time Setup   ");
        tab_activate.set_frame(FrameType::RFlatBox);
        tab_activate.set_color(Color::from_rgb(255, 255, 255));

        let mut l_acode = Frame::new(120, 250, 150, 30, "Activation Code:");
        l_acode.set_align(Align::Right | Align::Inside);
        let act_code_in = SecretInput::new(285, 250, 260, 30, "");

        let mut l_ap1 = Frame::new(120, 290, 150, 30, "New PIN 1:");
        l_ap1.set_align(Align::Right | Align::Inside);
        let act_p1_in = SecretInput::new(285, 290, 260, 30, "");

        let mut l_ap1c = Frame::new(120, 330, 150, 30, "Confirm PIN 1:");
        l_ap1c.set_align(Align::Right | Align::Inside);
        let act_p1_conf = SecretInput::new(285, 330, 260, 30, "");

        let mut l_ap2 = Frame::new(120, 370, 150, 30, "New PIN 2:");
        l_ap2.set_align(Align::Right | Align::Inside);
        let act_p2_in = SecretInput::new(285, 370, 260, 30, "");

        let mut l_ap2c = Frame::new(120, 410, 150, 30, "Confirm PIN 2:");
        l_ap2c.set_align(Align::Right | Align::Inside);
        let act_p2_conf = SecretInput::new(285, 410, 260, 30, "");

        let mut activate_btn = Button::new(285, 455, 180, 36, "Activate Card");
        activate_btn.set_color(Color::from_rgb(0, 122, 255));
        activate_btn.set_label_color(Color::from_rgb(255, 255, 255));
        activate_btn.set_label_font(Font::HelveticaBold);
        tab_activate.end();

        pin_subtabs.end();
        pin_tab.end();

        // ---------------------------------------------------------------------
        // TAB 2: Identity (Portrait & Signature)
        // ---------------------------------------------------------------------
        let pace_tab = Group::new(20, 88, 880, 550, "Identity   ");

        // CAN Bar
        let mut can_bar = Group::new(35, 98, 850, 44, "");
        can_bar.set_frame(FrameType::RFlatBox);
        can_bar.set_color(Color::from_rgb(255, 255, 255));

        let mut can_label = Frame::new(50, 105, 210, 30, "Card Access Number (CAN):");
        can_label.set_align(Align::Left | Align::Inside);
        let mut can_input = Input::new(265, 105, 90, 30, "");
        can_input.set_maximum_size(6);

        let mut read_images_btn = Button::new(370, 105, 140, 30, "Load Photos");
        read_images_btn.set_color(Color::from_rgb(0, 122, 255));
        read_images_btn.set_label_color(Color::from_rgb(255, 255, 255));
        read_images_btn.set_label_font(Font::HelveticaBold);

        let mut can_hint = Frame::new(525, 105, 340, 30, "6 digits on front of card");
        can_hint.set_label_size(12);
        can_hint.set_label_color(Color::from_rgb(108, 117, 125));
        can_hint.set_align(Align::Left | Align::Inside);
        can_bar.end();

        // Photo Card
        let mut photo_card = Group::new(35, 152, 370, 470, "");
        photo_card.set_frame(FrameType::RFlatBox);
        photo_card.set_color(Color::from_rgb(255, 255, 255));

        let mut p_title = Frame::new(50, 160, 340, 24, "Official Photo");
        p_title.set_label_font(Font::HelveticaBold);
        p_title.set_label_size(14);
        p_title.set_align(Align::Left | Align::Inside);

        let mut portrait_frame = Frame::new(60, 192, 320, 370, "No image loaded");
        portrait_frame.set_frame(FrameType::ThinDownBox);

        let copy_portrait_btn = Button::new(85, 575, 120, 32, "Copy Photo");
        let save_portrait_btn = Button::new(225, 575, 120, 32, "Save As...");
        photo_card.end();

        // Signature Card
        let mut sig_card = Group::new(420, 152, 465, 265, "");
        sig_card.set_frame(FrameType::RFlatBox);
        sig_card.set_color(Color::from_rgb(255, 255, 255));

        let mut s_title = Frame::new(435, 160, 435, 24, "Cardholder Signature");
        s_title.set_label_font(Font::HelveticaBold);
        s_title.set_label_size(14);
        s_title.set_align(Align::Left | Align::Inside);

        let mut signature_frame = Frame::new(435, 192, 435, 165, "No signature loaded");
        signature_frame.set_frame(FrameType::ThinDownBox);

        let copy_sig_btn = Button::new(490, 372, 140, 32, "Copy Signature");
        let save_sig_btn = Button::new(650, 372, 140, 32, "Save As...");
        sig_card.end();

        // Security Privacy Card
        let mut sec_card = Group::new(420, 430, 465, 192, "");
        sec_card.set_frame(FrameType::RFlatBox);
        sec_card.set_color(Color::from_rgb(255, 255, 255));

        let mut sec_title = Frame::new(435, 442, 435, 24, "Security & Privacy");
        sec_title.set_label_font(Font::HelveticaBold);
        sec_title.set_label_size(14);
        sec_title.set_align(Align::Left | Align::Inside);

        let mut sec_text = Frame::new(
            435,
            475,
            435,
            60,
            "Biometric data is read directly from your smart card using\nPACE-ECDH encryption. Photos are never stored remotely.",
        );
        sec_text.set_label_size(12);
        sec_text.set_label_color(Color::from_rgb(108, 117, 125));
        sec_text.set_align(Align::Left | Align::Inside);
        sec_card.end();

        pace_tab.end();

        // ---------------------------------------------------------------------
        // TAB 3: Sign Documents
        // ---------------------------------------------------------------------
        let sign_tab = Group::new(20, 88, 880, 550, "Sign   ");

        // Document Queue Card
        let mut doc_card = Group::new(35, 98, 495, 525, "");
        doc_card.set_frame(FrameType::RFlatBox);
        doc_card.set_color(Color::from_rgb(255, 255, 255));

        let mut queue_label = Frame::new(50, 108, 465, 24, "Documents to Sign");
        queue_label.set_label_font(Font::HelveticaBold);
        queue_label.set_label_size(14);
        queue_label.set_align(Align::Left | Align::Inside);

        let doc_browser = HoldBrowser::new(50, 138, 465, 335, "");

        let mut add_doc_btn = Button::new(50, 485, 130, 32, "Add Files...");
        let mut remove_doc_btn = Button::new(190, 485, 140, 32, "Remove Selected");
        let mut clear_docs_btn = Button::new(340, 485, 100, 32, "Clear List");

        let mut sign_result_frame = Frame::new(50, 530, 465, 80, "");
        sign_result_frame.set_frame(FrameType::ThinDownBox);
        sign_result_frame.set_align(Align::Left | Align::Inside);
        doc_card.end();

        // Signing Options Card
        let mut sign_settings = Group::new(545, 98, 340, 525, "");
        sign_settings.set_frame(FrameType::RFlatBox);
        sign_settings.set_color(Color::from_rgb(255, 255, 255));

        let mut opt_title = Frame::new(560, 108, 310, 24, "Signature Options");
        opt_title.set_label_font(Font::HelveticaBold);
        opt_title.set_label_size(14);
        opt_title.set_align(Align::Left | Align::Inside);

        let mut fmt_label = Frame::new(560, 145, 310, 20, "Format:");
        fmt_label.set_align(Align::Left | Align::Inside);

        let mut format_pades = RadioRoundButton::new(560, 170, 290, 25, "PDF Document (PAdES)");
        format_pades.set_value(true);
        let format_asice = RadioRoundButton::new(560, 200, 290, 25, "BDOC Container (ASiC-E)");

        let mut tsa_label = Frame::new(560, 240, 310, 20, "Timestamp Authority:");
        tsa_label.set_align(Align::Left | Align::Inside);
        let mut tsa_check = CheckButton::new(560, 265, 290, 25, "Include Qualified Timestamp");
        tsa_check.set_value(true);
        let mut tsa_url_input = Input::new(560, 295, 310, 28, "");
        tsa_url_input.set_value("https://timestamp.sectigo.com/qualified");

        let mut p2_label = Frame::new(560, 345, 310, 20, "Signing PIN (PIN 2):");
        p2_label.set_align(Align::Left | Align::Inside);
        let sign_pin2_input = SecretInput::new(560, 370, 310, 32, "");

        let mut sign_btn = Button::new(560, 425, 310, 42, "Sign Documents");
        sign_btn.set_color(Color::from_rgb(0, 122, 255));
        sign_btn.set_label_color(Color::from_rgb(255, 255, 255));
        sign_btn.set_label_font(Font::HelveticaBold);
        sign_btn.set_label_size(14);
        sign_settings.end();

        sign_tab.end();

        // ---------------------------------------------------------------------
        // TAB 4: Mobile Reader (RAPP / CPace PAKE)
        // ---------------------------------------------------------------------
        let rapp_tab = Group::new(20, 88, 880, 550, "Mobile Reader   ");

        // Header Description Card
        let mut desc_card = Group::new(35, 98, 850, 65, "");
        desc_card.set_frame(FrameType::RFlatBox);
        desc_card.set_color(Color::from_rgb(255, 255, 255));

        let mut r_title = Frame::new(50, 106, 820, 24, "Use this card on your mobile phone");
        r_title.set_label_font(Font::HelveticaBold);
        r_title.set_label_size(15);
        r_title.set_align(Align::Left | Align::Inside);

        let mut r_sub = Frame::new(
            50,
            132,
            820,
            20,
            "Open RefineID Authenticator on your phone to sign and log in securely.",
        );
        r_sub.set_label_size(12);
        r_sub.set_label_color(Color::from_rgb(108, 117, 125));
        r_sub.set_align(Align::Left | Align::Inside);
        desc_card.end();

        // Controls Card
        let mut ctrl_card = Group::new(35, 175, 385, 445, "");
        ctrl_card.set_frame(FrameType::RFlatBox);
        ctrl_card.set_color(Color::from_rgb(255, 255, 255));

        let mut start_pair_btn = Button::new(55, 195, 170, 36, "Start Pairing");
        start_pair_btn.set_color(Color::from_rgb(0, 122, 255));
        start_pair_btn.set_label_color(Color::from_rgb(255, 255, 255));
        start_pair_btn.set_label_font(Font::HelveticaBold);

        let mut cancel_pair_btn = Button::new(240, 195, 110, 36, "Cancel");

        let mut pcode_lbl = Frame::new(55, 250, 340, 22, "Verification Code:");
        pcode_lbl.set_label_font(Font::HelveticaBold);
        pcode_lbl.set_align(Align::Left | Align::Inside);

        let mut pair_code_frame = Frame::new(55, 280, 345, 65, "-- -- --");
        pair_code_frame.set_frame(FrameType::ThinDownBox);
        pair_code_frame.set_label_font(Font::CourierBold);
        pair_code_frame.set_label_size(28);

        let mut pair_status_frame = Frame::new(55, 365, 345, 45, "Status: Idle");
        pair_status_frame.set_frame(FrameType::ThinDownBox);
        pair_status_frame.set_align(Align::Center | Align::Inside);
        ctrl_card.end();

        // QR Code Card
        let mut qr_card = Group::new(435, 175, 450, 445, "");
        qr_card.set_frame(FrameType::RFlatBox);
        qr_card.set_color(Color::from_rgb(255, 255, 255));

        let mut qr_frame = Frame::new(
            465,
            200,
            390,
            390,
            "Start pairing on your phone, then type the code it shows.",
        );
        qr_frame.set_frame(FrameType::ThinDownBox);
        qr_frame.set_align(Align::Center | Align::Inside);
        qr_card.end();

        rapp_tab.end();
        tabs.end();

        // Bottom status bar
        let mut status_frame = Frame::new(20, 642, 880, 24, "Initializing RefineID...");
        status_frame.set_align(Align::Left | Align::Inside);
        status_frame.set_label_size(12);
        status_frame.set_label_color(Color::from_rgb(108, 117, 125));

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
                if let Some(code) = input_default("Type the code your phone shows:", "") {
                    c.handle_intent(UserIntent::StartPairing { code });
                }
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
            holder_name_frame,
            holder_sub_frame,
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
            widgets
                .card_choice
                .add_choice(&escape_fltk_menu_text(&card.label()));
        }
        if let Some(idx) = state.selected_card {
            widgets.card_choice.set_value(idx as i32);
        }

        // Top bar: Card presence badge & Hero Card
        if state.cards.is_empty() {
            widgets.card_status_badge.set_label("○ No Card");
            widgets
                .card_status_badge
                .set_color(Color::from_rgb(238, 240, 242));
            widgets
                .card_status_badge
                .set_label_color(Color::from_rgb(120, 120, 120));

            widgets.holder_name_frame.set_label("No Card Detected");
            widgets
                .holder_sub_frame
                .set_label("Insert your smart card into the reader");
            widgets.serial_frame.set_label("");
        } else if state.busy {
            widgets.card_status_badge.set_label("◌ Reading...");
            widgets
                .card_status_badge
                .set_color(Color::from_rgb(254, 247, 224));
            widgets
                .card_status_badge
                .set_label_color(Color::from_rgb(180, 100, 0));

            if let Some(card) = state.selected_card.and_then(|i| state.cards.get(i)) {
                widgets.holder_name_frame.set_label(&card.display_name());
                widgets
                    .holder_sub_frame
                    .set_label("Finnish Identity Card (FINEID)");
            }
        } else {
            widgets.card_status_badge.set_label("● Card Ready");
            widgets
                .card_status_badge
                .set_color(Color::from_rgb(230, 244, 234));
            widgets
                .card_status_badge
                .set_label_color(Color::from_rgb(46, 125, 50));

            if let Some(card) = state.selected_card.and_then(|i| state.cards.get(i)) {
                widgets.holder_name_frame.set_label(&card.display_name());
                widgets
                    .holder_sub_frame
                    .set_label("Finnish Identity Card (FINEID)");
                widgets.serial_frame.set_label(&format!(
                    "Card ID: {}",
                    state.card_serial.as_deref().unwrap_or("—")
                ));
            }
        }
        widgets.card_status_badge.redraw();

        // Tab 1: PIN Status
        let p1_text = match state.pin1_status {
            Some(PinStatus::Remaining(retries)) => {
                let count = retries.get();
                if retries.is_exhausted() {
                    "Authentication PIN (PIN 1):  BLOCKED".to_string()
                } else {
                    format!("Authentication PIN (PIN 1):  Ready ({count} tries left)")
                }
            }
            Some(PinStatus::Verified) => "Authentication PIN (PIN 1):  Verified".to_string(),
            Some(PinStatus::Locked) => "Authentication PIN (PIN 1):  BLOCKED".to_string(),
            Some(PinStatus::NoInfo) => "Authentication PIN (PIN 1):  No retry info".to_string(),
            Some(PinStatus::Other(sw)) => format!("Authentication PIN (PIN 1):  Status 0x{sw:04X}"),
            None => "Authentication PIN (PIN 1):  Not Inspected".to_string(),
        };
        widgets.pin1_status_frame.set_label(&p1_text);

        let p2_text = match state.pin2_status {
            Some(PinStatus::Remaining(retries)) => {
                let count = retries.get();
                if retries.is_exhausted() {
                    "Signing PIN (PIN 2):         BLOCKED".to_string()
                } else {
                    format!("Signing PIN (PIN 2):         Ready ({count} tries left)")
                }
            }
            Some(PinStatus::Verified) => "Signing PIN (PIN 2):         Verified".to_string(),
            Some(PinStatus::Locked) => "Signing PIN (PIN 2):         BLOCKED".to_string(),
            Some(PinStatus::NoInfo) => "Signing PIN (PIN 2):         No retry info".to_string(),
            Some(PinStatus::Other(sw)) => format!("Signing PIN (PIN 2):         Status 0x{sw:04X}"),
            None => "Signing PIN (PIN 2):         Not Inspected".to_string(),
        };
        widgets.pin2_status_frame.set_label(&p2_text);

        let puk_text = match state.puk_status {
            Some(PukStatus::Remaining(retries)) => {
                let count = retries.get();
                if retries.is_exhausted() {
                    "PUK Code:                    BLOCKED".to_string()
                } else {
                    format!("PUK Code:                    Ready ({count} tries left)")
                }
            }
            Some(PukStatus::Locked) => "PUK Code:                    BLOCKED".to_string(),
            Some(PukStatus::Invalidated) => "PUK Code:                    Invalidated".to_string(),
            Some(PukStatus::NoInfo) => "PUK Code:                    No retry info".to_string(),
            Some(PukStatus::Other(sw)) => format!("PUK Code:                    Status 0x{sw:04X}"),
            None => "PUK Code:                    Unknown".to_string(),
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
                if let Some(img) = create_fitted_image(buf, 310, 360) {
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
                if let Some(img) = create_fitted_image(buf, 420, 150) {
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
            widgets.pair_code_frame.set_label("-- -- --");
            widgets.pair_status_frame.set_label("Status: Idle");
            widgets.qr_frame.set_image(None::<RgbImage>);
            widgets
                .qr_frame
                .set_label("Start pairing on your phone, then type the code it shows.");
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

/// Escapes special menu characters in FLTK choice items (`/`, `&`, `_`).
fn escape_fltk_menu_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '/' => out.push_str("\\/"),
            '&' => out.push_str("&&"),
            '_' => out.push_str("\\_"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_fltk_menu_text() {
        assert_eq!(
            escape_fltk_menu_text("KOISTINEN PETRI / Alcor Reader / CardOS"),
            "KOISTINEN PETRI \\/ Alcor Reader \\/ CardOS"
        );
        assert_eq!(
            escape_fltk_menu_text("R&D / Test_Case"),
            "R&&D \\/ Test\\_Case"
        );
        assert_eq!(escape_fltk_menu_text("Clean Name"), "Clean Name");
    }
}
