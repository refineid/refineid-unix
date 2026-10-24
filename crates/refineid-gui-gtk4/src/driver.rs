// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

//! GTK 4 presentation driver for RefineID.
//!
//! Follows Apple macOS Human Interface Guidelines (HIG):
//! - Unified titlebar with segmented pill view switcher (`Identity`, `PINs`, `Sign`, `Phone`).
//! - Rounded inset grouped cards (`.apple-card`).
//! - SF-style typography hierarchy and colored status pills for retry counters and pairing.
//! - Masked `PasswordEntry` with zero PIN data or candidate PIN-length logging.
//! - 6-box pairing code entry for RAPP phone pairing.
//! - Native file choosers and system clipboard integration for visual credentials.

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use refineid_gui_core::PinManageSlot;
use refineid_gui_core::controller::RefineIdController;
use refineid_gui_core::driver::UiDriver;
use refineid_gui_core::error::GuiCoreError;
use refineid_gui_core::image::RgbaImageBuffer;
use refineid_gui_core::model::{SignFormat, UiState, UserIntent};
use refineid_lib_core::auth::{PIN_TRY_LIMIT, PinStatus, PukStatus};
use refineid_lib_core::can::CAN_DIGITS;
use refineid_lib_core::pin::{ActivationPinEight, ActivationPinSeven, PinBytes, Puk};
use refineid_rapp_core::offer::{
    PAIRING_CODE_GROUP_SIZE, PAIRING_CODE_LENGTH, pairing_code_character,
};

use gtk4::gdk;
use gtk4::glib;
use gtk4::prelude::*;

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

/// Convert an [`RgbaImageBuffer`] into a [`gdk::Texture`] for rendering.
fn texture_from_rgba(buf: &RgbaImageBuffer) -> Option<gdk::Texture> {
    if buf.width() == 0 || buf.height() == 0 || buf.rgba_bytes().is_empty() {
        return None;
    }
    let width: i32 = buf.width().try_into().ok()?;
    let height: i32 = buf.height().try_into().ok()?;
    let rowstride: i32 = buf.width().checked_mul(4)?.try_into().ok()?;
    let required_len = (rowstride as usize).checked_mul(height as usize)?;
    if buf.rgba_bytes().len() < required_len {
        return None;
    }
    let bytes = glib::Bytes::from(buf.rgba_bytes());
    let pixbuf = gtk4::gdk_pixbuf::Pixbuf::from_bytes(
        &bytes,
        gtk4::gdk_pixbuf::Colorspace::Rgb,
        true,
        8,
        width,
        height,
        rowstride,
    );
    Some(gdk::Texture::for_pixbuf(&pixbuf))
}

/// Copy a texture to the system clipboard.
fn copy_texture_to_clipboard(texture: &gdk::Texture) {
    if let Some(display) = gdk::Display::default() {
        display.clipboard().set_texture(texture);
    }
}

/// Save an RGBA image buffer to a PNG file.
fn save_buffer_to_png(path: &Path, buf: &RgbaImageBuffer) -> Result<(), String> {
    let mut save_path = path.to_path_buf();
    save_path.set_extension("png");
    image::save_buffer(
        &save_path,
        buf.rgba_bytes(),
        buf.width(),
        buf.height(),
        image::ExtendedColorType::Rgba8,
    )
    .map_err(|e| e.to_string())
}

/// Single character box inside the RAPP pairing code control.
#[derive(Clone)]
struct CodeBox {
    frame: gtk4::Frame,
    label: gtk4::Label,
}

/// 6-character Apple-style code boxes grouped in pairs: `[ 7 ][ K ]   [ X ][ 4 ]   [ M ][ 9 ]`.
#[derive(Clone)]
struct CodeBoxes {
    container_widget: gtk4::Box,
    boxes: Vec<CodeBox>,
    entry: gtk4::Entry,
}

impl CodeBoxes {
    fn new() -> Self {
        let container = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(8)
            .halign(gtk4::Align::Center)
            .valign(gtk4::Align::Center)
            .build();

        let mut boxes = Vec::with_capacity(PAIRING_CODE_LEN);
        for i in 0..PAIRING_CODE_LEN {
            if i > 0 && i % PAIRING_CODE_GROUP_SIZE == 0 {
                let spacer = gtk4::Box::builder().width_request(14).build();
                container.append(&spacer);
            }

            let frame = gtk4::Frame::builder()
                .width_request(48)
                .height_request(56)
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
            .opacity(0.0)
            .width_request(1)
            .height_request(1)
            .can_focus(true)
            .build();
        container.append(&entry);

        let click_gesture = gtk4::GestureClick::new();
        let e_click = entry.clone();
        click_gesture.connect_pressed(move |_, _, _, _| {
            e_click.grab_focus();
        });
        container.add_controller(click_gesture);

        Self {
            container_widget: container,
            boxes,
            entry,
        }
    }

    fn container(&self) -> &gtk4::Box {
        &self.container_widget
    }

    fn render(&self, code: &str) {
        let chars: Vec<char> = code.chars().collect();
        for (i, b) in self.boxes.iter().enumerate() {
            let ch = chars.get(i).map(|c| c.to_string()).unwrap_or_default();
            b.label.set_label(&ch);

            if i == chars.len() && chars.len() < PAIRING_CODE_LEN {
                b.frame.add_css_class("code-box-active");
            } else {
                b.frame.remove_css_class("code-box-active");
            }

            if i < chars.len() {
                b.frame.add_css_class("code-box-filled");
            } else {
                b.frame.remove_css_class("code-box-filled");
            }
        }
    }
}

/// Human-readable retry count formatting for status pills.
fn format_pin_status(status: Option<&PinStatus>, changed: Option<bool>) -> (String, &'static str) {
    let limit = PIN_TRY_LIMIT as usize;
    match status {
        Some(PinStatus::Remaining(retries)) => {
            let count = retries.get() as usize;
            let note = if changed == Some(false) {
                " • Factory"
            } else {
                ""
            };
            if count >= limit {
                (format!("{count} / {limit}{note}"), "status-pill-green")
            } else if count >= 3 {
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
            if count >= 5 {
                (format!("{count} remaining"), "status-pill-green")
            } else if count >= 3 {
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

/// Visual widgets associated with the Identity tab.
struct IdentityWidgets {
    holder_name_label: gtk4::Label,
    status_pill_label: gtk4::Label,
    can_entry: gtk4::Entry,
    load_photo_button: gtk4::Button,
    portrait_picture: gtk4::Picture,
    portrait_placeholder: gtk4::Label,
    copy_portrait_button: gtk4::Button,
    save_portrait_button: gtk4::Button,
    signature_picture: gtk4::Picture,
    signature_placeholder: gtk4::Label,
    copy_signature_button: gtk4::Button,
    save_signature_button: gtk4::Button,
}

/// Visual widgets associated with the PINs tab.
#[allow(
    dead_code,
    reason = "Widget handles retained for GTK UI hierarchy lifetime"
)]
struct PinsWidgets {
    pin1_pill: gtk4::Label,
    pin1_note: gtk4::Label,
    pin2_pill: gtk4::Label,
    pin2_note: gtk4::Label,
    puk_pill: gtk4::Label,
    task_stack: gtk4::Stack,
    btn_task_p1: gtk4::ToggleButton,
    btn_task_p2: gtk4::ToggleButton,
    btn_task_unblock: gtk4::ToggleButton,
    btn_task_activate: gtk4::ToggleButton,

    // Change PIN 1
    p1_current_entry: gtk4::PasswordEntry,
    p1_new_entry: gtk4::PasswordEntry,
    p1_confirm_entry: gtk4::PasswordEntry,
    change_pin1_button: gtk4::Button,

    // Change PIN 2
    p2_current_entry: gtk4::PasswordEntry,
    p2_new_entry: gtk4::PasswordEntry,
    p2_confirm_entry: gtk4::PasswordEntry,
    change_pin2_button: gtk4::Button,

    // Reactivate / Unblock
    unblock_slot_combo: gtk4::DropDown,
    puk_entry: gtk4::PasswordEntry,
    unblock_new_entry: gtk4::PasswordEntry,
    unblock_confirm_entry: gtk4::PasswordEntry,
    unblock_button: gtk4::Button,

    // Activate Card
    act_code_entry: gtk4::PasswordEntry,
    act_p1_entry: gtk4::PasswordEntry,
    act_p1_confirm_entry: gtk4::PasswordEntry,
    act_p2_entry: gtk4::PasswordEntry,
    act_p2_confirm_entry: gtk4::PasswordEntry,
    activate_button: gtk4::Button,
}

/// Visual widgets associated with the Document Signing tab.
#[allow(
    dead_code,
    reason = "Widget handles retained for GTK UI hierarchy lifetime"
)]
struct SignWidgets {
    doc_count_label: gtk4::Label,
    doc_list: gtk4::ListBox,
    add_doc_button: gtk4::Button,
    remove_doc_button: gtk4::Button,
    clear_doc_button: gtk4::Button,
    btn_format_pades: gtk4::ToggleButton,
    btn_format_asice: gtk4::ToggleButton,
    sign_pin2_entry: gtk4::PasswordEntry,
    sign_button: gtk4::Button,
    sign_result_banner: gtk4::Box,
    sign_result_label: gtk4::Label,
    last_pdf_documents: RefCell<Vec<std::path::PathBuf>>,
}

/// Visual widgets associated with the Phone (RAPP) tab.
#[allow(
    dead_code,
    reason = "Widget handles retained for GTK UI hierarchy lifetime"
)]
struct PhoneWidgets {
    reader_card: gtk4::Box,
    code_boxes: CodeBoxes,
    pair_status_label: gtk4::Label,

    phone_card: gtk4::Box,
    phone_name_label: gtk4::Label,
    phone_state_pill: gtk4::Label,
    forget_phone_button: gtk4::Button,
}

/// Bottom status bar widgets.
struct StatusBarWidgets {
    attempts_label: gtk4::Label,
    status_label: gtk4::Label,
    spinner: gtk4::Spinner,
}

/// Internal handle set for all controls rendered by [`Gtk4Driver`].
#[allow(
    dead_code,
    reason = "Widget handles retained for GTK UI hierarchy lifetime"
)]
struct Gtk4Widgets {
    window: gtk4::Window,
    stack: gtk4::Stack,
    btn_tab_identity: gtk4::ToggleButton,
    btn_tab_pins: gtk4::ToggleButton,
    btn_tab_sign: gtk4::ToggleButton,
    btn_tab_phone: gtk4::ToggleButton,
    identity: IdentityWidgets,
    pins: PinsWidgets,
    sign: SignWidgets,
    phone: PhoneWidgets,
    status_bar: StatusBarWidgets,
    cached_portrait: Option<Arc<RgbaImageBuffer>>,
    cached_signature: Option<Arc<RgbaImageBuffer>>,
}

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

    /// Load Apple macOS Human Interface Guidelines CSS styling into GTK display.
    fn load_css() {
        let css_provider = gtk4::CssProvider::new();
        css_provider.load_from_data(
            "
            /* macOS HIG Foundation */
            window {
                background-color: #f5f5f7;
                color: #1d1d1f;
                font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Helvetica Neue', Cantarell, sans-serif;
            }

            /* Inset Grouped Apple Card */
            .apple-card {
                background-color: #ffffff;
                border-radius: 12px;
                border: 1px solid rgba(0, 0, 0, 0.08);
                box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
                padding: 18px 20px;
            }

            .apple-card-title {
                font-size: 15px;
                font-weight: 700;
                color: #1d1d1f;
            }

            .apple-card-subtitle {
                font-size: 12px;
                color: #86868b;
            }

            /* Apple Segmented Control (Pill Switcher) */
            .apple-segmented-bar {
                background-color: rgba(120, 120, 128, 0.14);
                border-radius: 9px;
                padding: 3px;
            }

            .apple-segmented-button {
                background-color: transparent;
                color: #1d1d1f;
                border: none;
                border-radius: 7px;
                padding: 6px 18px;
                font-weight: 500;
                font-size: 13px;
                box-shadow: none;
                transition: all 150ms ease-in-out;
            }

            .apple-segmented-button:checked {
                background-color: #ffffff;
                color: #000000;
                font-weight: 600;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 1px rgba(0, 0, 0, 0.08);
            }

            .apple-segmented-button:hover:not(:checked) {
                background-color: rgba(255, 255, 255, 0.4);
            }

            /* Primary Action Button (macOS Blue) */
            .apple-primary-button {
                background-color: #007aff;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 8px 18px;
                font-weight: 600;
                font-size: 13px;
                box-shadow: 0 1px 2px rgba(0, 122, 255, 0.2);
            }

            .apple-primary-button:hover {
                background-color: #0069d9;
            }

            .apple-primary-button:active {
                background-color: #0056b3;
            }

            .apple-primary-button:disabled {
                background-color: #e5e5ea;
                color: #8e8e93;
                box-shadow: none;
            }

            /* Secondary Action Button (macOS White Button) */
            .apple-secondary-button {
                background-color: #ffffff;
                color: #1d1d1f;
                border: 1px solid #d1d1d6;
                border-radius: 8px;
                padding: 7px 16px;
                font-weight: 500;
                font-size: 13px;
            }

            .apple-secondary-button:hover {
                background-color: #f5f5f7;
                border-color: #c7c7cc;
            }

            .apple-secondary-button:active {
                background-color: #e5e5ea;
            }

            .apple-secondary-button:disabled {
                color: #8e8e93;
                border-color: #e5e5ea;
            }

            /* Destructive Action Button (macOS Red) */
            .apple-destructive-button {
                background-color: #ff3b30;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-weight: 600;
                font-size: 13px;
            }

            .apple-destructive-button:hover {
                background-color: #d70015;
            }

            /* Status Pill Badges */
            .status-pill {
                border-radius: 12px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 600;
            }

            .status-pill-green {
                background-color: rgba(52, 199, 89, 0.15);
                color: #248a3d;
            }

            .status-pill-orange {
                background-color: rgba(255, 149, 0, 0.15);
                color: #c97000;
            }

            .status-pill-red {
                background-color: rgba(255, 59, 48, 0.15);
                color: #d70015;
            }

            .status-pill-blue {
                background-color: rgba(0, 122, 255, 0.15);
                color: #007aff;
            }

            .status-pill-gray {
                background-color: rgba(142, 142, 147, 0.15);
                color: #8e8e93;
            }

            /* Code Boxes (Phone Pairing) */
            .code-box {
                background-color: #ffffff;
                border: 2px solid #d1d1d6;
                border-radius: 10px;
                transition: all 120ms ease-in-out;
            }

            .code-box.code-box-active {
                border-color: #007aff;
                box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.25);
            }

            .code-box.code-box-filled {
                border-color: #8e8e93;
                background-color: #fbfbfd;
            }

            .code-char {
                font-family: 'SF Mono', 'Menlo', monospace;
                font-size: 22px;
                font-weight: 700;
                color: #1d1d1f;
            }

            /* Input Fields */
            entry {
                background-color: #ffffff;
                border: 1px solid #d1d1d6;
                border-radius: 8px;
                padding: 6px 10px;
                color: #1d1d1f;
            }

            entry:focus {
                border-color: #007aff;
                box-shadow: 0 0 0 2px rgba(0, 122, 255, 0.2);
            }

            passwordentry {
                background-color: #ffffff;
                border: 1px solid #d1d1d6;
                border-radius: 8px;
                padding: 6px 10px;
                color: #1d1d1f;
            }

            passwordentry:focus-within {
                border-color: #007aff;
                box-shadow: 0 0 0 2px rgba(0, 122, 255, 0.2);
            }

            /* Inset Media Preview Containers */
            .media-preview-frame {
                background-color: #fbfbfd;
                border: 1px solid #e5e5ea;
                border-radius: 10px;
            }

            /* Result Banners */
            .result-banner-success {
                background-color: rgba(52, 199, 89, 0.12);
                border: 1px solid rgba(52, 199, 89, 0.3);
                border-radius: 8px;
                padding: 10px 14px;
                color: #1f7a33;
                font-weight: 500;
            }

            .result-banner-error {
                background-color: rgba(255, 59, 48, 0.12);
                border: 1px solid rgba(255, 59, 48, 0.3);
                border-radius: 8px;
                padding: 10px 14px;
                color: #d70015;
                font-weight: 500;
            }

            /* Bottom Bar */
            .bottom-bar {
                background-color: rgba(245, 245, 247, 0.85);
                border-top: 1px solid rgba(0, 0, 0, 0.08);
                padding: 8px 16px;
            }
            ",
        );

        if let Some(display) = gdk::Display::default() {
            gtk4::style_context_add_provider_for_display(
                &display,
                &css_provider,
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
        let widgets = Gtk4Widgets::build(&controller, self.initial_tab.as_deref());
        let widgets_cell = Rc::new(RefCell::new(widgets));

        // Initial render
        widgets_cell.borrow_mut().apply_state(&controller.state());

        // Connect reactive state receiver from background tasks via main context
        if let Some(receiver) = self.receiver.take() {
            let w = Rc::clone(&widgets_cell);
            glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
                while let Ok(state) = receiver.try_recv() {
                    w.borrow_mut().apply_state(&state);
                }
                glib::ControlFlow::Continue
            });
        }

        let main_loop = glib::MainLoop::new(Some(&context), false);
        let loop_for_close = main_loop.clone();

        widgets_cell
            .borrow()
            .window
            .connect_close_request(move |_| {
                loop_for_close.quit();
                glib::Propagation::Proceed
            });

        widgets_cell.borrow().window.present();

        main_loop.run();

        controller.stop();
        Ok(())
    }
}

impl Gtk4Widgets {
    /// Build entire GTK4 UI with Apple HIG presentation.
    fn build(controller: &Arc<RefineIdController>, initial_tab: Option<&str>) -> Self {
        let window = gtk4::Window::builder()
            .title("RefineID")
            .default_width(940)
            .default_height(680)
            .build();

        // Top Navigation Header
        let header_box = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(12)
            .margin_top(12)
            .margin_bottom(8)
            .margin_start(16)
            .margin_end(16)
            .build();

        // Apple Segmented Control in Top Bar
        let segmented_bar = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(2)
            .halign(gtk4::Align::Center)
            .build();
        segmented_bar.add_css_class("apple-segmented-bar");

        let btn_tab_identity = gtk4::ToggleButton::builder().label("Identity").build();
        btn_tab_identity.add_css_class("apple-segmented-button");

        let btn_tab_pins = gtk4::ToggleButton::builder().label("PINs").build();
        btn_tab_pins.add_css_class("apple-segmented-button");

        let btn_tab_sign = gtk4::ToggleButton::builder().label("Sign").build();
        btn_tab_sign.add_css_class("apple-segmented-button");

        let btn_tab_phone = gtk4::ToggleButton::builder().label("Phone").build();
        btn_tab_phone.add_css_class("apple-segmented-button");

        segmented_bar.append(&btn_tab_identity);
        segmented_bar.append(&btn_tab_pins);
        segmented_bar.append(&btn_tab_sign);
        segmented_bar.append(&btn_tab_phone);
        header_box.append(&segmented_bar);

        // Main Stack for the 4 primary views
        let stack = gtk4::Stack::builder()
            .transition_type(gtk4::StackTransitionType::Crossfade)
            .vexpand(true)
            .hexpand(true)
            .build();

        // 1. Identity Tab
        let (identity_page, identity) = build_identity_page(controller, &window);
        stack.add_named(&identity_page, Some("identity"));

        // 2. PINs Tab
        let (pins_page, pins) = build_pins_page(controller);
        stack.add_named(&pins_page, Some("pins"));

        // 3. Sign Tab
        let (sign_page, sign) = build_sign_page(controller, &window);
        stack.add_named(&sign_page, Some("sign"));

        // 4. Phone Tab
        let (phone_page, phone) = build_phone_page(controller);
        stack.add_named(&phone_page, Some("phone"));

        // Wire segmented bar buttons to stack using ToggleButton grouping
        btn_tab_pins.set_group(Some(&btn_tab_identity));
        btn_tab_sign.set_group(Some(&btn_tab_identity));
        btn_tab_phone.set_group(Some(&btn_tab_identity));

        {
            let s = stack.clone();
            btn_tab_identity.connect_toggled(move |btn| {
                if btn.is_active() {
                    s.set_visible_child_name("identity");
                }
            });

            let s = stack.clone();
            btn_tab_pins.connect_toggled(move |btn| {
                if btn.is_active() {
                    s.set_visible_child_name("pins");
                }
            });

            let s = stack.clone();
            btn_tab_sign.connect_toggled(move |btn| {
                if btn.is_active() {
                    s.set_visible_child_name("sign");
                }
            });

            let s = stack.clone();
            btn_tab_phone.connect_toggled(move |btn| {
                if btn.is_active() {
                    s.set_visible_child_name("phone");
                }
            });
        }

        // Initial tab selection
        match initial_tab {
            Some("phone") => {
                btn_tab_phone.set_active(true);
                stack.set_visible_child_name("phone");
                phone.code_boxes.entry.grab_focus();
            }
            Some("pins") => {
                btn_tab_pins.set_active(true);
                stack.set_visible_child_name("pins");
            }
            Some("sign") => {
                btn_tab_sign.set_active(true);
                stack.set_visible_child_name("sign");
            }
            _ => {
                btn_tab_identity.set_active(true);
                stack.set_visible_child_name("identity");
            }
        }

        // Bottom Status Bar
        let (status_bar_box, status_bar) = build_status_bar();

        let root = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .build();
        root.append(&header_box);
        root.append(&stack);
        root.append(&status_bar_box);

        window.set_child(Some(&root));

        Self {
            window,
            stack,
            btn_tab_identity,
            btn_tab_pins,
            btn_tab_sign,
            btn_tab_phone,
            identity,
            pins,
            sign,
            phone,
            status_bar,
            cached_portrait: None,
            cached_signature: None,
        }
    }

    /// Apply an updated [`UiState`] snapshot across all Apple HIG widgets.
    fn apply_state(&mut self, state: &UiState) {
        self.window.set_title(Some(&state.window_title));

        // 1. Identity Tab
        let holder = state
            .selected_card
            .and_then(|idx| state.cards.get(idx))
            .map(|c| c.display_name())
            .unwrap_or_else(|| "No card inserted".to_string());
        self.identity.holder_name_label.set_label(&holder);

        if state.selected_card_is_local {
            self.identity
                .status_pill_label
                .set_label("● Local Smart Card");
            self.identity
                .status_pill_label
                .remove_css_class("status-pill-blue");
            self.identity
                .status_pill_label
                .remove_css_class("status-pill-gray");
            self.identity
                .status_pill_label
                .add_css_class("status-pill-green");
            self.identity.can_entry.set_sensitive(true);
            self.identity
                .load_photo_button
                .set_sensitive(!state.busy && state.selected_card.is_some());
        } else if state.selected_card.is_some() {
            self.identity.status_pill_label.set_label("● Paired Phone");
            self.identity
                .status_pill_label
                .remove_css_class("status-pill-green");
            self.identity
                .status_pill_label
                .remove_css_class("status-pill-gray");
            self.identity
                .status_pill_label
                .add_css_class("status-pill-blue");
            self.identity.can_entry.set_sensitive(false);
            self.identity.load_photo_button.set_sensitive(false);
        } else {
            self.identity.status_pill_label.set_label("No Card");
            self.identity
                .status_pill_label
                .remove_css_class("status-pill-green");
            self.identity
                .status_pill_label
                .remove_css_class("status-pill-blue");
            self.identity
                .status_pill_label
                .add_css_class("status-pill-gray");
            self.identity.can_entry.set_sensitive(false);
            self.identity.load_photo_button.set_sensitive(false);
        }

        if state.can_text.is_empty() && !state.busy && !self.identity.can_entry.text().is_empty() {
            self.identity.can_entry.set_text("");
        } else if !state.can_text.is_empty() && self.identity.can_entry.text().is_empty() {
            self.identity.can_entry.set_text(&state.can_text);
        }

        // Render portrait
        if state.portrait != self.cached_portrait {
            self.cached_portrait = state.portrait.clone();
            if let Some(ref buf) = state.portrait {
                if let Some(texture) = texture_from_rgba(buf) {
                    self.identity.portrait_picture.set_paintable(Some(&texture));
                    self.identity.portrait_placeholder.set_visible(false);
                    self.identity.portrait_picture.set_visible(true);
                    self.identity.copy_portrait_button.set_sensitive(true);
                    self.identity.save_portrait_button.set_sensitive(true);
                }
            } else {
                self.identity
                    .portrait_picture
                    .set_paintable(None::<&gdk::Texture>);
                self.identity.portrait_picture.set_visible(false);
                self.identity.portrait_placeholder.set_visible(true);
                self.identity.copy_portrait_button.set_sensitive(false);
                self.identity.save_portrait_button.set_sensitive(false);
            }
        }

        // Render signature
        if state.signature != self.cached_signature {
            self.cached_signature = state.signature.clone();
            if let Some(ref buf) = state.signature {
                if let Some(texture) = texture_from_rgba(buf) {
                    self.identity
                        .signature_picture
                        .set_paintable(Some(&texture));
                    self.identity.signature_placeholder.set_visible(false);
                    self.identity.signature_picture.set_visible(true);
                    self.identity.copy_signature_button.set_sensitive(true);
                    self.identity.save_signature_button.set_sensitive(true);
                }
            } else {
                self.identity
                    .signature_picture
                    .set_paintable(None::<&gdk::Texture>);
                self.identity.signature_picture.set_visible(false);
                self.identity.signature_placeholder.set_visible(true);
                self.identity.copy_signature_button.set_sensitive(false);
                self.identity.save_signature_button.set_sensitive(false);
            }
        }

        // 2. PINs Tab
        let (p1_text, p1_cls) = format_pin_status(state.pin1_status.as_ref(), state.pin1_changed);
        self.pins.pin1_pill.set_label(&p1_text);
        self.pins
            .pin1_pill
            .set_css_classes(&["status-pill", p1_cls]);
        self.pins.pin1_note.set_label(match state.pin1_changed {
            Some(false) => "Factory value",
            _ => "Authentication",
        });

        let (p2_text, p2_cls) = format_pin_status(state.pin2_status.as_ref(), state.pin2_changed);
        self.pins.pin2_pill.set_label(&p2_text);
        self.pins
            .pin2_pill
            .set_css_classes(&["status-pill", p2_cls]);
        self.pins.pin2_note.set_label(match state.pin2_changed {
            Some(false) => "Factory value",
            _ => "Qualified Signature",
        });

        let (puk_text, puk_cls) = format_puk_status(state.puk_status.as_ref());
        self.pins.puk_pill.set_label(&puk_text);
        self.pins
            .puk_pill
            .set_css_classes(&["status-pill", puk_cls]);

        // Toggle activation tab availability
        self.pins
            .btn_task_activate
            .set_visible(state.activation_available);

        self.pins
            .change_pin1_button
            .set_sensitive(state.pin1_change_available && !state.busy);
        self.pins
            .change_pin2_button
            .set_sensitive(state.pin2_change_available && !state.busy);
        self.pins.unblock_button.set_sensitive(
            (state.pin1_unblock_available || state.pin2_unblock_available) && !state.busy,
        );
        self.pins
            .activate_button
            .set_sensitive(state.activation_available && !state.busy);

        // 3. Sign Tab
        let count = state.pdf_documents.len();
        self.sign.doc_count_label.set_label(&format!(
            "{} document{}",
            count,
            if count == 1 { "" } else { "s" }
        ));

        let mut cached_docs = self.sign.last_pdf_documents.borrow_mut();
        if *cached_docs != state.pdf_documents {
            *cached_docs = state.pdf_documents.clone();
            let prev_selected = self.sign.doc_list.selected_row().map(|r| r.index());
            while let Some(row) = self.sign.doc_list.first_child() {
                self.sign.doc_list.remove(&row);
            }
            for (i, path) in state.pdf_documents.iter().enumerate() {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("document.pdf");
                let row = gtk4::ListBoxRow::builder().build();
                let h = gtk4::Box::builder()
                    .orientation(gtk4::Orientation::Horizontal)
                    .spacing(12)
                    .margin_top(8)
                    .margin_bottom(8)
                    .margin_start(12)
                    .margin_end(12)
                    .build();
                let icon = gtk4::Image::from_icon_name("x-office-document");
                let title = gtk4::Label::builder()
                    .label(name)
                    .halign(gtk4::Align::Start)
                    .hexpand(true)
                    .build();
                let path_lbl = gtk4::Label::builder()
                    .label(path.display().to_string())
                    .halign(gtk4::Align::End)
                    .build();
                path_lbl.add_css_class("apple-card-subtitle");

                h.append(&icon);
                h.append(&title);
                h.append(&path_lbl);
                row.set_child(Some(&h));
                self.sign.doc_list.append(&row);
                if Some(i as i32) == prev_selected {
                    self.sign.doc_list.select_row(Some(&row));
                }
            }
        }

        match state.sign_format {
            SignFormat::Pades => {
                self.sign.btn_format_pades.set_active(true);
                self.sign.btn_format_asice.set_active(false);
            }
            SignFormat::AsicE => {
                self.sign.btn_format_asice.set_active(true);
                self.sign.btn_format_pades.set_active(false);
            }
        }

        let can_sign = !state.pdf_documents.is_empty()
            && !state.busy
            && state.selected_card.is_some()
            && state.signature_supported;
        self.sign.sign_button.set_sensitive(can_sign);

        if let Some(ref res) = state.sign_result {
            self.sign.sign_result_banner.set_visible(true);
            self.sign.sign_result_label.set_label(res);
            if res.to_lowercase().contains("error") || res.to_lowercase().contains("fail") {
                self.sign
                    .sign_result_banner
                    .remove_css_class("result-banner-success");
                self.sign
                    .sign_result_banner
                    .add_css_class("result-banner-error");
            } else {
                self.sign
                    .sign_result_banner
                    .remove_css_class("result-banner-error");
                self.sign
                    .sign_result_banner
                    .add_css_class("result-banner-success");
            }
        } else {
            self.sign.sign_result_banner.set_visible(false);
        }

        // 4. Phone Tab (RAPP Continuity)
        if state.has_local_card {
            self.btn_tab_phone.set_visible(false);
            if self.stack.visible_child_name().as_deref() == Some("phone") {
                self.btn_tab_identity.set_active(true);
                self.stack.set_visible_child_name("identity");
            }
        } else {
            self.btn_tab_phone.set_visible(true);
            if let Some(ref phone) = state.phone {
                self.phone.phone_name_label.set_label(&phone.name);
                self.phone
                    .phone_state_pill
                    .set_label(if phone.certificate_cached {
                        &phone.platform
                    } else {
                        "Reading card"
                    });
                self.phone.reader_card.set_visible(false);
                self.phone.phone_card.set_visible(true);
            } else {
                self.phone.phone_card.set_visible(false);
                self.phone.reader_card.set_visible(true);

                if let Some(ref pairing) = state.pairing {
                    self.phone.pair_status_label.set_label(&pairing.status);
                    self.phone.code_boxes.render(&pairing.code);
                    self.phone.code_boxes.entry.set_sensitive(false);
                } else {
                    self.phone.pair_status_label.set_label("");
                    self.phone.code_boxes.entry.set_sensitive(true);
                }
            }
        }

        // 5. Bottom Status Bar
        self.status_bar.attempts_label.set_label(&format!(
            "PIN 1: {p1_text}  •  PIN 2: {p2_text}  •  PUK: {puk_text}"
        ));
        self.status_bar
            .status_label
            .set_label(&state.status_message);
        self.status_bar.spinner.set_spinning(state.busy);
        self.status_bar.spinner.set_visible(state.busy);
    }
}

/// Helper alert modal dialog.
fn show_alert(parent: &gtk4::Window, message: &str) {
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
fn show_confirm(parent: &gtk4::Window, message: &str, on_confirm: impl FnOnce() + 'static) {
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
// Page Builders
// ---------------------------------------------------------------------------

fn build_identity_page(
    controller: &Arc<RefineIdController>,
    window: &gtk4::Window,
) -> (gtk4::ScrolledWindow, IdentityWidgets) {
    let scrolled = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .build();

    let page = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(16)
        .margin_top(16)
        .margin_bottom(20)
        .margin_start(24)
        .margin_end(24)
        .build();

    // Card 1: Cardholder and CAN Bar
    let card1 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(14)
        .build();
    card1.add_css_class("apple-card");

    let holder_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .build();
    let id_icon = gtk4::Image::from_icon_name("avatar-default-symbolic");
    id_icon.set_pixel_size(24);

    let holder_name_label = gtk4::Label::builder()
        .label("No card detected")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    holder_name_label.add_css_class("apple-card-title");

    let status_pill_label = gtk4::Label::builder().label("No Card").build();
    status_pill_label.add_css_class("status-pill");
    status_pill_label.add_css_class("status-pill-gray");

    holder_row.append(&id_icon);
    holder_row.append(&holder_name_label);
    holder_row.append(&status_pill_label);
    card1.append(&holder_row);

    let sep = gtk4::Separator::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .build();
    card1.append(&sep);

    let can_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .build();
    let can_label = gtk4::Label::builder()
        .label("Card Access Number (CAN):")
        .halign(gtk4::Align::Start)
        .build();

    let can_entry = gtk4::Entry::builder()
        .placeholder_text("6 digits on card")
        .max_length(CAN_DIGITS as i32)
        .width_chars(16)
        .build();

    can_entry.connect_changed(|entry| {
        let cur = entry.text();
        let filtered = filter_digits(&cur, CAN_DIGITS);
        if filtered != cur.as_str() {
            entry.set_text(&filtered);
            entry.set_position(filtered.chars().count() as i32);
        }
    });

    let load_photo_button = gtk4::Button::builder().label("Load Photo").build();
    load_photo_button.add_css_class("apple-primary-button");

    can_row.append(&can_label);
    can_row.append(&can_entry);
    can_row.append(&gtk4::Box::builder().hexpand(true).build());
    can_row.append(&load_photo_button);
    card1.append(&can_row);

    {
        let c = Arc::clone(controller);
        let e = can_entry.clone();
        load_photo_button.connect_clicked(move |btn| {
            let val = e.text();
            if val.len() != CAN_DIGITS {
                e.set_text("");
                if let Some(root) = btn.root()
                    && let Ok(win) = root.downcast::<gtk4::Window>()
                {
                    show_alert(&win, "CAN must be exactly 6 numeric digits.");
                }
                return;
            }
            if let Some(pin) = to_pin_bytes(&val) {
                c.handle_intent(UserIntent::LoadImages { can: pin });
                e.set_text("");
            } else {
                e.set_text("");
                if let Some(root) = btn.root()
                    && let Ok(win) = root.downcast::<gtk4::Window>()
                {
                    show_alert(&win, "CAN contains invalid characters.");
                }
            }
        });
    }

    // Card 2: Visual Credentials
    let card2 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(20)
        .build();
    card2.add_css_class("apple-card");

    // Official Photo Column
    let photo_col = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(10)
        .hexpand(true)
        .build();
    let photo_title = gtk4::Label::builder()
        .label("Official Photo")
        .halign(gtk4::Align::Start)
        .build();
    photo_title.add_css_class("apple-card-title");

    let photo_frame = gtk4::Frame::builder()
        .width_request(260)
        .height_request(320)
        .build();
    photo_frame.add_css_class("media-preview-frame");

    let portrait_overlay = gtk4::Overlay::builder().build();
    let portrait_placeholder = gtk4::Label::builder()
        .label("Enter CAN above to load photo")
        .halign(gtk4::Align::Center)
        .valign(gtk4::Align::Center)
        .build();
    portrait_placeholder.add_css_class("apple-card-subtitle");

    let portrait_picture = gtk4::Picture::builder()
        .can_shrink(true)
        .halign(gtk4::Align::Center)
        .valign(gtk4::Align::Center)
        .build();
    portrait_picture.set_visible(false);

    portrait_overlay.set_child(Some(&portrait_placeholder));
    portrait_overlay.add_overlay(&portrait_picture);
    photo_frame.set_child(Some(&portrait_overlay));

    let photo_actions = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .build();
    let copy_portrait_button = gtk4::Button::builder().label("Copy Photo").build();
    copy_portrait_button.add_css_class("apple-secondary-button");
    let save_portrait_button = gtk4::Button::builder().label("Save As…").build();
    save_portrait_button.add_css_class("apple-secondary-button");
    photo_actions.append(&copy_portrait_button);
    photo_actions.append(&save_portrait_button);

    photo_col.append(&photo_title);
    photo_col.append(&photo_frame);
    photo_col.append(&photo_actions);

    // Cardholder Signature Column
    let sig_col = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(10)
        .hexpand(true)
        .build();
    let sig_title = gtk4::Label::builder()
        .label("Cardholder Signature")
        .halign(gtk4::Align::Start)
        .build();
    sig_title.add_css_class("apple-card-title");

    let sig_frame = gtk4::Frame::builder()
        .width_request(360)
        .height_request(160)
        .build();
    sig_frame.add_css_class("media-preview-frame");

    let sig_overlay = gtk4::Overlay::builder().build();
    let signature_placeholder = gtk4::Label::builder()
        .label("(Signature not loaded)")
        .halign(gtk4::Align::Center)
        .valign(gtk4::Align::Center)
        .build();
    signature_placeholder.add_css_class("apple-card-subtitle");

    let signature_picture = gtk4::Picture::builder()
        .can_shrink(true)
        .halign(gtk4::Align::Center)
        .valign(gtk4::Align::Center)
        .build();
    signature_picture.set_visible(false);

    sig_overlay.set_child(Some(&signature_placeholder));
    sig_overlay.add_overlay(&signature_picture);
    sig_frame.set_child(Some(&sig_overlay));

    let sig_actions = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .build();
    let copy_signature_button = gtk4::Button::builder().label("Copy Signature").build();
    copy_signature_button.add_css_class("apple-secondary-button");
    let save_signature_button = gtk4::Button::builder().label("Save As…").build();
    save_signature_button.add_css_class("apple-secondary-button");
    sig_actions.append(&copy_signature_button);
    sig_actions.append(&save_signature_button);

    sig_col.append(&sig_title);
    sig_col.append(&sig_frame);
    sig_col.append(&sig_actions);

    card2.append(&photo_col);
    card2.append(&sig_col);

    page.append(&card1);
    page.append(&card2);
    scrolled.set_child(Some(&page));

    // Clipboard and File Saving Callbacks
    {
        let c = Arc::clone(controller);
        copy_portrait_button.connect_clicked(move |_| {
            if let Some(ref buf) = c.state().portrait
                && let Some(texture) = texture_from_rgba(buf)
            {
                copy_texture_to_clipboard(&texture);
            }
        });
    }
    {
        let c = Arc::clone(controller);
        let win_clone = window.clone();
        save_portrait_button.connect_clicked(move |_| {
            if let Some(ref buf) = c.state().portrait {
                let chooser = gtk4::FileChooserNative::new(
                    Some("Save Photo As"),
                    Some(&win_clone),
                    gtk4::FileChooserAction::Save,
                    Some("Save"),
                    Some("Cancel"),
                );
                chooser.set_current_name("official_photo.png");
                let buf_clone = buf.clone();
                let win_alert = win_clone.clone();
                chooser.connect_response(move |dialog, resp| {
                    if resp == gtk4::ResponseType::Accept
                        && let Some(file) = dialog.file()
                        && let Some(path) = file.path()
                        && let Err(e) = save_buffer_to_png(&path, &buf_clone)
                    {
                        show_alert(&win_alert, &format!("Failed to save image: {e}"));
                    }
                });
                chooser.show();
            }
        });
    }
    {
        let c = Arc::clone(controller);
        copy_signature_button.connect_clicked(move |_| {
            if let Some(ref buf) = c.state().signature
                && let Some(texture) = texture_from_rgba(buf)
            {
                copy_texture_to_clipboard(&texture);
            }
        });
    }
    {
        let c = Arc::clone(controller);
        let win_clone = window.clone();
        save_signature_button.connect_clicked(move |_| {
            if let Some(ref buf) = c.state().signature {
                let chooser = gtk4::FileChooserNative::new(
                    Some("Save Signature As"),
                    Some(&win_clone),
                    gtk4::FileChooserAction::Save,
                    Some("Save"),
                    Some("Cancel"),
                );
                chooser.set_current_name("cardholder_signature.png");
                let buf_clone = buf.clone();
                let win_alert = win_clone.clone();
                chooser.connect_response(move |dialog, resp| {
                    if resp == gtk4::ResponseType::Accept
                        && let Some(file) = dialog.file()
                        && let Some(path) = file.path()
                        && let Err(e) = save_buffer_to_png(&path, &buf_clone)
                    {
                        show_alert(&win_alert, &format!("Failed to save image: {e}"));
                    }
                });
                chooser.show();
            }
        });
    }

    (
        scrolled,
        IdentityWidgets {
            holder_name_label,
            status_pill_label,
            can_entry,
            load_photo_button,
            portrait_picture,
            portrait_placeholder,
            copy_portrait_button,
            save_portrait_button,
            signature_picture,
            signature_placeholder,
            copy_signature_button,
            save_signature_button,
        },
    )
}

fn build_pins_page(controller: &Arc<RefineIdController>) -> (gtk4::ScrolledWindow, PinsWidgets) {
    let scrolled = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .build();

    let page = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(16)
        .margin_top(16)
        .margin_bottom(20)
        .margin_start(24)
        .margin_end(24)
        .build();

    // Card 1: Attempts Overview
    let card1 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .build();
    card1.add_css_class("apple-card");

    let card1_title = gtk4::Label::builder()
        .label("Credential Status")
        .halign(gtk4::Align::Start)
        .build();
    card1_title.add_css_class("apple-card-title");
    card1.append(&card1_title);

    let tiles_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(16)
        .homogeneous(true)
        .build();

    // Tile 1: PIN 1
    let t1 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(6)
        .build();
    let t1_head = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .build();
    let l1 = gtk4::Label::builder()
        .label("PIN 1")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    l1.add_css_class("apple-card-title");
    let pin1_pill = gtk4::Label::builder().label("5 / 5").build();
    pin1_pill.add_css_class("status-pill");
    pin1_pill.add_css_class("status-pill-green");
    t1_head.append(&l1);
    t1_head.append(&pin1_pill);
    let pin1_note = gtk4::Label::builder()
        .label("Authentication")
        .halign(gtk4::Align::Start)
        .build();
    pin1_note.add_css_class("apple-card-subtitle");
    t1.append(&t1_head);
    t1.append(&pin1_note);

    // Tile 2: PIN 2
    let t2 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(6)
        .build();
    let t2_head = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .build();
    let l2 = gtk4::Label::builder()
        .label("PIN 2")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    l2.add_css_class("apple-card-title");
    let pin2_pill = gtk4::Label::builder().label("5 / 5").build();
    pin2_pill.add_css_class("status-pill");
    pin2_pill.add_css_class("status-pill-green");
    t2_head.append(&l2);
    t2_head.append(&pin2_pill);
    let pin2_note = gtk4::Label::builder()
        .label("Qualified Signature")
        .halign(gtk4::Align::Start)
        .build();
    pin2_note.add_css_class("apple-card-subtitle");
    t2.append(&t2_head);
    t2.append(&pin2_note);

    // Tile 3: PUK
    let t3 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(6)
        .build();
    let t3_head = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .build();
    let l3 = gtk4::Label::builder()
        .label("PUK")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    l3.add_css_class("apple-card-title");
    let puk_pill = gtk4::Label::builder().label("5 remaining").build();
    puk_pill.add_css_class("status-pill");
    puk_pill.add_css_class("status-pill-green");
    t3_head.append(&l3);
    t3_head.append(&puk_pill);
    let puk_note = gtk4::Label::builder()
        .label("Unblocking Code")
        .halign(gtk4::Align::Start)
        .build();
    puk_note.add_css_class("apple-card-subtitle");
    t3.append(&t3_head);
    t3.append(&puk_note);

    tiles_row.append(&t1);
    tiles_row.append(&t2);
    tiles_row.append(&t3);
    card1.append(&tiles_row);

    // Card 2: Management Tasks
    let card2 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(16)
        .build();
    card2.add_css_class("apple-card");

    // Task Selector Bar
    let task_bar = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(2)
        .halign(gtk4::Align::Start)
        .build();
    task_bar.add_css_class("apple-segmented-bar");

    let btn_task_p1 = gtk4::ToggleButton::builder().label("Change PIN 1").build();
    btn_task_p1.add_css_class("apple-segmented-button");

    let btn_task_p2 = gtk4::ToggleButton::builder().label("Change PIN 2").build();
    btn_task_p2.add_css_class("apple-segmented-button");

    let btn_task_unblock = gtk4::ToggleButton::builder().label("Unblock PIN").build();
    btn_task_unblock.add_css_class("apple-segmented-button");

    let btn_task_activate = gtk4::ToggleButton::builder().label("Activate Card").build();
    btn_task_activate.add_css_class("apple-segmented-button");
    btn_task_activate.set_visible(false);

    task_bar.append(&btn_task_p1);
    task_bar.append(&btn_task_p2);
    task_bar.append(&btn_task_unblock);
    task_bar.append(&btn_task_activate);
    card2.append(&task_bar);

    let task_stack = gtk4::Stack::builder()
        .transition_type(gtk4::StackTransitionType::Crossfade)
        .build();

    // Subform 1: Change PIN 1
    let p1_form = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .margin_top(8)
        .build();
    let p1_current_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Current PIN 1 (4-12 digits)")
        .show_peek_icon(true)
        .build();
    let p1_new_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("New PIN 1")
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
    task_stack.add_named(&p1_form, Some("p1"));

    // Subform 2: Change PIN 2
    let p2_form = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .margin_top(8)
        .build();
    let p2_current_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Current PIN 2 (6-12 digits)")
        .show_peek_icon(true)
        .build();
    let p2_new_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("New PIN 2")
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
    task_stack.add_named(&p2_form, Some("p2"));

    // Subform 3: Unblock PIN
    let unblock_form = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .margin_top(8)
        .build();
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

    // Subform 4: Activate Card
    let activate_form = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .margin_top(8)
        .build();
    let act_code_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("8-digit Activation Code from Letter")
        .show_peek_icon(true)
        .build();
    let act_p1_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Initial PIN 1 (4-12 digits)")
        .show_peek_icon(true)
        .build();
    let act_p1_confirm_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Confirm Initial PIN 1")
        .show_peek_icon(true)
        .build();
    let act_p2_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Initial PIN 2 (6-12 digits)")
        .show_peek_icon(true)
        .build();
    let act_p2_confirm_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("Confirm Initial PIN 2")
        .show_peek_icon(true)
        .build();
    let activate_button = gtk4::Button::builder().label("Activate Card").build();
    activate_button.add_css_class("apple-primary-button");

    activate_form.append(&act_code_entry);
    activate_form.append(&act_p1_entry);
    activate_form.append(&act_p1_confirm_entry);
    activate_form.append(&act_p2_entry);
    activate_form.append(&act_p2_confirm_entry);
    activate_form.append(&activate_button);
    task_stack.add_named(&activate_form, Some("activate"));

    card2.append(&task_stack);

    // Wire task segmented switcher using ToggleButton grouping
    btn_task_p2.set_group(Some(&btn_task_p1));
    btn_task_unblock.set_group(Some(&btn_task_p1));
    btn_task_activate.set_group(Some(&btn_task_p1));

    {
        let ts = task_stack.clone();
        btn_task_p1.connect_toggled(move |btn| {
            if btn.is_active() {
                ts.set_visible_child_name("p1");
            }
        });

        let ts = task_stack.clone();
        btn_task_p2.connect_toggled(move |btn| {
            if btn.is_active() {
                ts.set_visible_child_name("p2");
            }
        });

        let ts = task_stack.clone();
        btn_task_unblock.connect_toggled(move |btn| {
            if btn.is_active() {
                ts.set_visible_child_name("unblock");
            }
        });

        let ts = task_stack.clone();
        btn_task_activate.connect_toggled(move |btn| {
            if btn.is_active() {
                ts.set_visible_child_name("activate");
            }
        });
    }

    btn_task_p1.set_active(true);
    task_stack.set_visible_child_name("p1");

    page.append(&card1);
    page.append(&card2);
    scrolled.set_child(Some(&page));

    // PIN Management Action Callbacks
    {
        let c = Arc::clone(controller);
        let cur = p1_current_entry.clone();
        let new = p1_new_entry.clone();
        let conf = p1_confirm_entry.clone();
        change_pin1_button.connect_clicked(move |btn| {
            let win = btn.root().and_then(|r| r.downcast::<gtk4::Window>().ok());
            let cur_v = cur.text();
            let new_v = new.text();
            let conf_v = conf.text();
            if new_v != conf_v {
                new.set_text("");
                conf.set_text("");
                if let Some(ref w) = win {
                    show_alert(w, "New PIN 1 entries do not match.");
                }
                return;
            }
            if new_v.len() < MIN_PIN1_DIGITS || new_v.len() > MAX_PIN1_DIGITS {
                new.set_text("");
                conf.set_text("");
                if let Some(ref w) = win {
                    show_alert(
                        w,
                        &format!(
                            "PIN 1 must be between {MIN_PIN1_DIGITS} and {MAX_PIN1_DIGITS} digits."
                        ),
                    );
                }
                return;
            }
            if let (Some(cur_pin), Some(new_pin)) = (to_pin_bytes(&cur_v), to_pin_bytes(&new_v)) {
                c.handle_intent(UserIntent::ChangePin {
                    slot: PinManageSlot::Pin1,
                    current_pin: cur_pin,
                    new_pin,
                });
                cur.set_text("");
                new.set_text("");
                conf.set_text("");
            } else {
                cur.set_text("");
                new.set_text("");
                conf.set_text("");
                if let Some(ref w) = win {
                    show_alert(w, "PIN contains invalid characters.");
                }
            }
        });
    }
    {
        let c = Arc::clone(controller);
        let cur = p2_current_entry.clone();
        let new = p2_new_entry.clone();
        let conf = p2_confirm_entry.clone();
        change_pin2_button.connect_clicked(move |btn| {
            let win = btn.root().and_then(|r| r.downcast::<gtk4::Window>().ok());
            let cur_v = cur.text();
            let new_v = new.text();
            let conf_v = conf.text();
            if new_v != conf_v {
                new.set_text("");
                conf.set_text("");
                if let Some(ref w) = win {
                    show_alert(w, "New PIN 2 entries do not match.");
                }
                return;
            }
            if new_v.len() < MIN_PIN2_DIGITS || new_v.len() > MAX_PIN2_DIGITS {
                new.set_text("");
                conf.set_text("");
                if let Some(ref w) = win {
                    show_alert(
                        w,
                        &format!(
                            "PIN 2 must be between {MIN_PIN2_DIGITS} and {MAX_PIN2_DIGITS} digits."
                        ),
                    );
                }
                return;
            }
            if let (Some(cur_pin), Some(new_pin)) = (to_pin_bytes(&cur_v), to_pin_bytes(&new_v)) {
                c.handle_intent(UserIntent::ChangePin {
                    slot: PinManageSlot::Pin2,
                    current_pin: cur_pin,
                    new_pin,
                });
                cur.set_text("");
                new.set_text("");
                conf.set_text("");
            } else {
                cur.set_text("");
                new.set_text("");
                conf.set_text("");
                if let Some(ref w) = win {
                    show_alert(w, "PIN contains invalid characters.");
                }
            }
        });
    }
    {
        let c = Arc::clone(controller);
        let slot_dd = unblock_slot_combo.clone();
        let puk_in = puk_entry.clone();
        let new_in = unblock_new_entry.clone();
        let conf_in = unblock_confirm_entry.clone();
        unblock_button.connect_clicked(move |btn| {
            let win = btn.root().and_then(|r| r.downcast::<gtk4::Window>().ok());
            let puk_v = puk_in.text();
            let new_v = new_in.text();
            let conf_v = conf_in.text();
            if new_v != conf_v {
                new_in.set_text("");
                conf_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(w, "New PIN entries do not match.");
                }
                return;
            }
            if puk_v.len() < MIN_PUK_DIGITS || puk_v.len() > MAX_PUK_DIGITS {
                puk_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(
                        w,
                        &format!(
                            "PUK must be between {MIN_PUK_DIGITS} and {MAX_PUK_DIGITS} digits."
                        ),
                    );
                }
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
            if new_v.len() < min_len || new_v.len() > max_len {
                new_in.set_text("");
                conf_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(
                        w,
                        &format!("PIN must be between {min_len} and {max_len} digits."),
                    );
                }
                return;
            }
            if let (Some(puk_pin), Some(new_pin)) = (to_pin_bytes(&puk_v), to_pin_bytes(&new_v)) {
                c.handle_intent(UserIntent::ReactivatePin {
                    slot,
                    puk: puk_pin,
                    new_pin,
                });
                puk_in.set_text("");
                new_in.set_text("");
                conf_in.set_text("");
            } else {
                puk_in.set_text("");
                new_in.set_text("");
                conf_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(w, "PUK or PIN contains invalid characters.");
                }
            }
        });
    }
    {
        let c = Arc::clone(controller);
        let act_in = act_code_entry.clone();
        let p1_in = act_p1_entry.clone();
        let p1c_in = act_p1_confirm_entry.clone();
        let p2_in = act_p2_entry.clone();
        let p2c_in = act_p2_confirm_entry.clone();
        activate_button.connect_clicked(move |btn| {
            let win = btn.root().and_then(|r| r.downcast::<gtk4::Window>().ok());
            let act_v = act_in.text();
            let p1_v = p1_in.text();
            let p1c_v = p1c_in.text();
            let p2_v = p2_in.text();
            let p2c_v = p2c_in.text();
            if p1_v != p1c_v {
                p1_in.set_text("");
                p1c_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(w, "PIN 1 entries do not match.");
                }
                return;
            }
            if p2_v != p2c_v {
                p2_in.set_text("");
                p2c_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(w, "PIN 2 entries do not match.");
                }
                return;
            }
            if act_v.len() < MIN_ACTIVATION_CODE_DIGITS || act_v.len() > MAX_ACTIVATION_CODE_DIGITS {
                act_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(
                        w,
                        &format!(
                            "Activation code must be between {MIN_ACTIVATION_CODE_DIGITS} and {MAX_ACTIVATION_CODE_DIGITS} digits."
                        ),
                    );
                }
                return;
            }
            if p1_v.len() < MIN_PIN1_DIGITS || p1_v.len() > MAX_PIN1_DIGITS {
                p1_in.set_text("");
                p1c_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(
                        w,
                        &format!(
                            "PIN 1 must be between {MIN_PIN1_DIGITS} and {MAX_PIN1_DIGITS} digits."
                        ),
                    );
                }
                return;
            }
            if p2_v.len() < MIN_PIN2_DIGITS || p2_v.len() > MAX_PIN2_DIGITS {
                p2_in.set_text("");
                p2c_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(
                        w,
                        &format!(
                            "PIN 2 must be between {MIN_PIN2_DIGITS} and {MAX_PIN2_DIGITS} digits."
                        ),
                    );
                }
                return;
            }
            if let (Some(act_code), Some(new_pin1), Some(new_pin2)) = (
                to_pin_bytes(&act_v),
                to_pin_bytes(&p1_v),
                to_pin_bytes(&p2_v),
            ) {
                c.handle_intent(UserIntent::ActivateCard {
                    activation_code: act_code,
                    new_pin1,
                    new_pin2,
                });
                act_in.set_text("");
                p1_in.set_text("");
                p1c_in.set_text("");
                p2_in.set_text("");
                p2c_in.set_text("");
            } else {
                act_in.set_text("");
                p1_in.set_text("");
                p1c_in.set_text("");
                p2_in.set_text("");
                p2c_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(w, "Activation code or PINs contain invalid characters.");
                }
            }
        });
    }

    (
        scrolled,
        PinsWidgets {
            pin1_pill,
            pin1_note,
            pin2_pill,
            pin2_note,
            puk_pill,
            task_stack,
            btn_task_p1,
            btn_task_p2,
            btn_task_unblock,
            btn_task_activate,
            p1_current_entry,
            p1_new_entry,
            p1_confirm_entry,
            change_pin1_button,
            p2_current_entry,
            p2_new_entry,
            p2_confirm_entry,
            change_pin2_button,
            unblock_slot_combo,
            puk_entry,
            unblock_new_entry,
            unblock_confirm_entry,
            unblock_button,
            act_code_entry,
            act_p1_entry,
            act_p1_confirm_entry,
            act_p2_entry,
            act_p2_confirm_entry,
            activate_button,
        },
    )
}

fn build_sign_page(
    controller: &Arc<RefineIdController>,
    window: &gtk4::Window,
) -> (gtk4::ScrolledWindow, SignWidgets) {
    let scrolled = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .build();

    let page = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(16)
        .margin_top(16)
        .margin_bottom(20)
        .margin_start(24)
        .margin_end(24)
        .build();

    // Card 1: Documents Queue
    let card1 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .build();
    card1.add_css_class("apple-card");

    let card1_head = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .build();
    let card1_title = gtk4::Label::builder()
        .label("Documents to Sign")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    card1_title.add_css_class("apple-card-title");
    let doc_count_label = gtk4::Label::builder().label("0 documents").build();
    doc_count_label.add_css_class("status-pill");
    doc_count_label.add_css_class("status-pill-gray");

    card1_head.append(&card1_title);
    card1_head.append(&doc_count_label);
    card1.append(&card1_head);

    let doc_scroller = gtk4::ScrolledWindow::builder()
        .min_content_height(140)
        .max_content_height(180)
        .build();
    doc_scroller.add_css_class("media-preview-frame");

    let doc_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .build();
    doc_scroller.set_child(Some(&doc_list));
    card1.append(&doc_scroller);

    let doc_actions = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .build();
    let add_doc_button = gtk4::Button::builder().label("Add Documents…").build();
    add_doc_button.add_css_class("apple-primary-button");
    let remove_doc_button = gtk4::Button::builder().label("Remove").build();
    remove_doc_button.add_css_class("apple-secondary-button");
    let clear_doc_button = gtk4::Button::builder().label("Clear All").build();
    clear_doc_button.add_css_class("apple-secondary-button");

    doc_actions.append(&add_doc_button);
    doc_actions.append(&remove_doc_button);
    doc_actions.append(&clear_doc_button);
    card1.append(&doc_actions);

    // Card 2: Signature Format
    let card2 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(10)
        .build();
    card2.add_css_class("apple-card");

    let card2_title = gtk4::Label::builder()
        .label("Signature Format")
        .halign(gtk4::Align::Start)
        .build();
    card2_title.add_css_class("apple-card-title");
    card2.append(&card2_title);

    let format_bar = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(2)
        .halign(gtk4::Align::Start)
        .build();
    format_bar.add_css_class("apple-segmented-bar");

    let btn_format_pades = gtk4::ToggleButton::builder()
        .label("PAdES (PDF Embedded)")
        .build();
    btn_format_pades.add_css_class("apple-segmented-button");

    let btn_format_asice = gtk4::ToggleButton::builder()
        .label("ASiC-E Container")
        .build();
    btn_format_asice.add_css_class("apple-segmented-button");
    btn_format_asice.set_group(Some(&btn_format_pades));

    format_bar.append(&btn_format_pades);
    format_bar.append(&btn_format_asice);
    card2.append(&format_bar);

    let format_hint = gtk4::Label::builder()
        .label(
            "PAdES (ETSI EN 319 142) embeds qualified digital signatures directly within standard PDF files.",
        )
        .halign(gtk4::Align::Start)
        .build();
    format_hint.add_css_class("apple-card-subtitle");
    card2.append(&format_hint);

    // Card 3: Qualified Authorization & Sign Action
    let card3 = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(12)
        .build();
    card3.add_css_class("apple-card");

    let card3_title = gtk4::Label::builder()
        .label("Qualified Signature Authorization")
        .halign(gtk4::Align::Start)
        .build();
    card3_title.add_css_class("apple-card-title");
    let card3_subtitle = gtk4::Label::builder()
        .label(
            "Enter PIN 2 to execute a Qualified Electronic Signature (QES) pursuant to EU eIDAS Regulation (EU) No 910/2014.",
        )
        .halign(gtk4::Align::Start)
        .build();
    card3_subtitle.add_css_class("apple-card-subtitle");

    card3.append(&card3_title);
    card3.append(&card3_subtitle);

    let sign_row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .build();
    let sign_pin2_entry = gtk4::PasswordEntry::builder()
        .placeholder_text("PIN 2 (Signature)")
        .show_peek_icon(true)
        .hexpand(true)
        .build();
    let sign_button = gtk4::Button::builder().label("Sign Documents").build();
    sign_button.add_css_class("apple-primary-button");

    sign_row.append(&sign_pin2_entry);
    sign_row.append(&sign_button);
    card3.append(&sign_row);

    let sign_result_banner = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .build();
    sign_result_banner.add_css_class("result-banner-success");
    let sign_result_label = gtk4::Label::builder()
        .label("")
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    sign_result_banner.append(&sign_result_label);
    sign_result_banner.set_visible(false);
    card3.append(&sign_result_banner);

    page.append(&card1);
    page.append(&card2);
    page.append(&card3);
    scrolled.set_child(Some(&page));

    // Sign Document Callbacks
    {
        let c = Arc::clone(controller);
        let win_clone = window.clone();
        add_doc_button.connect_clicked(move |_| {
            let chooser = gtk4::FileChooserNative::new(
                Some("Select PDF Documents to Sign"),
                Some(&win_clone),
                gtk4::FileChooserAction::Open,
                Some("Add"),
                Some("Cancel"),
            );
            chooser.set_select_multiple(true);
            let filter = gtk4::FileFilter::new();
            filter.set_name(Some("PDF Documents"));
            filter.add_pattern("*.pdf");
            filter.add_pattern("*.PDF");
            chooser.add_filter(&filter);

            let c_resp = Arc::clone(&c);
            chooser.connect_response(move |dialog, resp| {
                if resp == gtk4::ResponseType::Accept {
                    let files = dialog.files();
                    let mut paths = Vec::new();
                    for i in 0..files.n_items() {
                        if let Some(item) = files.item(i)
                            && let Ok(file) = item.downcast::<gtk4::gio::File>()
                            && let Some(path) = file.path()
                        {
                            paths.push(path);
                        }
                    }
                    if !paths.is_empty() {
                        c_resp.handle_intent(UserIntent::AddDocuments(paths));
                    }
                }
            });
            chooser.show();
        });
    }
    {
        let c = Arc::clone(controller);
        let dl = doc_list.clone();
        remove_doc_button.connect_clicked(move |_| {
            if let Some(row) = dl.selected_row() {
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
        clear_doc_button.connect_clicked(move |_| {
            c.handle_intent(UserIntent::ClearDocuments);
        });
    }
    {
        let c = Arc::clone(controller);
        let hint = format_hint.clone();
        btn_format_pades.connect_toggled(move |btn| {
            if btn.is_active() {
                hint.set_label(
                    "PAdES (ETSI EN 319 142) embeds qualified digital signatures directly within standard PDF files.",
                );
                c.handle_intent(UserIntent::SetSignFormat(SignFormat::Pades));
            }
        });

        let c = Arc::clone(controller);
        let hint = format_hint.clone();
        btn_format_asice.connect_toggled(move |btn| {
            if btn.is_active() {
                hint.set_label(
                    "ASiC-E (ETSI EN 319 162) packages arbitrary documents and signatures into a standardized container.",
                );
                c.handle_intent(UserIntent::SetSignFormat(SignFormat::AsicE));
            }
        });
    }
    {
        let c = Arc::clone(controller);
        let pin2_in = sign_pin2_entry.clone();
        sign_button.connect_clicked(move |btn| {
            let win = btn.root().and_then(|r| r.downcast::<gtk4::Window>().ok());
            let pin2_v = pin2_in.text();
            if pin2_v.len() < MIN_PIN2_DIGITS || pin2_v.len() > MAX_PIN2_DIGITS {
                pin2_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(
                        w,
                        &format!(
                            "PIN 2 must be between {MIN_PIN2_DIGITS} and {MAX_PIN2_DIGITS} digits."
                        ),
                    );
                }
                return;
            }
            if let Some(pin2) = to_pin_bytes(&pin2_v) {
                c.handle_intent(UserIntent::SignDocuments { pin2 });
                pin2_in.set_text("");
            } else {
                pin2_in.set_text("");
                if let Some(ref w) = win {
                    show_alert(w, "PIN 2 contains invalid characters.");
                }
            }
        });
    }

    (
        scrolled,
        SignWidgets {
            doc_count_label,
            doc_list,
            add_doc_button,
            remove_doc_button,
            clear_doc_button,
            btn_format_pades,
            btn_format_asice,
            sign_pin2_entry,
            sign_button,
            sign_result_banner,
            sign_result_label,
            last_pdf_documents: RefCell::new(Vec::new()),
        },
    )
}

fn build_phone_page(controller: &Arc<RefineIdController>) -> (gtk4::ScrolledWindow, PhoneWidgets) {
    let scrolled = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .build();

    let page = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(16)
        .margin_top(24)
        .margin_bottom(20)
        .margin_start(24)
        .margin_end(24)
        .build();

    // 1. Unbonded Pairing Card (6-Box Entry)
    let reader_card = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(16)
        .halign(gtk4::Align::Center)
        .build();
    reader_card.add_css_class("apple-card");
    reader_card.set_width_request(540);

    let phone_icon = gtk4::Image::from_icon_name("network-wireless-symbolic");
    phone_icon.set_pixel_size(48);
    phone_icon.set_halign(gtk4::Align::Center);
    reader_card.append(&phone_icon);

    let pair_title = gtk4::Label::builder()
        .label("Use Phone as Smart Card Reader")
        .halign(gtk4::Align::Center)
        .build();
    pair_title.add_css_class("apple-card-title");
    reader_card.append(&pair_title);

    let pair_subtitle = gtk4::Label::builder()
        .label("Type the 6-character code displayed in the RefineID app on your phone:")
        .halign(gtk4::Align::Center)
        .build();
    pair_subtitle.add_css_class("apple-card-subtitle");
    reader_card.append(&pair_subtitle);

    let code_boxes = CodeBoxes::new();
    reader_card.append(code_boxes.container());

    let pair_status_label = gtk4::Label::builder()
        .label("")
        .halign(gtk4::Align::Center)
        .build();
    pair_status_label.add_css_class("apple-card-subtitle");
    reader_card.append(&pair_status_label);

    page.append(&reader_card);

    // 2. Bonded Phone Card
    let phone_card = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(16)
        .build();
    phone_card.add_css_class("apple-card");

    let paired_icon = gtk4::Image::from_icon_name("phone-symbolic");
    paired_icon.set_pixel_size(36);

    let phone_info = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(4)
        .hexpand(true)
        .build();
    let phone_name_label = gtk4::Label::builder()
        .label("")
        .halign(gtk4::Align::Start)
        .build();
    phone_name_label.add_css_class("apple-card-title");
    let phone_state_pill = gtk4::Label::builder().label("Ready").build();
    phone_state_pill.add_css_class("status-pill");
    phone_state_pill.add_css_class("status-pill-blue");
    phone_state_pill.set_halign(gtk4::Align::Start);
    phone_info.append(&phone_name_label);
    phone_info.append(&phone_state_pill);

    let forget_phone_button = gtk4::Button::builder().label("Forget Phone").build();
    forget_phone_button.add_css_class("apple-destructive-button");

    phone_card.append(&paired_icon);
    phone_card.append(&phone_info);
    phone_card.append(&forget_phone_button);
    phone_card.set_visible(false);

    page.append(&phone_card);
    scrolled.set_child(Some(&page));

    // Wiring pairing input
    {
        let c = Arc::clone(controller);
        let cb = code_boxes.clone();
        let last_submitted = Rc::new(RefCell::new(None::<String>));
        code_boxes.entry.connect_changed(move |entry| {
            let filtered = filter_pairing_code(&entry.text());
            if filtered != entry.text().as_str() {
                entry.set_text(&filtered);
                entry.set_position(filtered.chars().count() as i32);
                return;
            }
            cb.render(&filtered);
            if filtered.len() == PAIRING_CODE_LEN {
                let mut last = last_submitted.borrow_mut();
                if last.as_deref() != Some(&filtered) {
                    *last = Some(filtered.clone());
                    c.handle_intent(UserIntent::StartPairing { code: filtered });
                }
            } else {
                *last_submitted.borrow_mut() = None;
            }
        });
    }

    // Wiring forget phone
    {
        let c = Arc::clone(controller);
        forget_phone_button.connect_clicked(move |btn| {
            if let Some(root) = btn.root()
                && let Ok(win) = root.downcast::<gtk4::Window>()
            {
                let c_action = Arc::clone(&c);
                show_confirm(
                    &win,
                    "Forget this paired phone? It will no longer serve smart card sessions.",
                    move || {
                        c_action.handle_intent(UserIntent::ForgetPhone);
                    },
                );
            }
        });
    }

    (
        scrolled,
        PhoneWidgets {
            reader_card,
            code_boxes,
            pair_status_label,
            phone_card,
            phone_name_label,
            phone_state_pill,
            forget_phone_button,
        },
    )
}

fn build_status_bar() -> (gtk4::Box, StatusBarWidgets) {
    let bar = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .build();
    bar.add_css_class("bottom-bar");

    let attempts_label = gtk4::Label::builder()
        .label("PIN 1: No card  •  PIN 2: No card  •  PUK: No card")
        .halign(gtk4::Align::Start)
        .build();
    attempts_label.add_css_class("apple-card-subtitle");

    let spacer = gtk4::Box::builder().hexpand(true).build();

    let status_label = gtk4::Label::builder()
        .label("")
        .halign(gtk4::Align::End)
        .build();
    status_label.add_css_class("apple-card-subtitle");

    let spinner = gtk4::Spinner::builder().build();
    spinner.set_visible(false);

    bar.append(&attempts_label);
    bar.append(&spacer);
    bar.append(&status_label);
    bar.append(&spinner);

    (
        bar,
        StatusBarWidgets {
            attempts_label,
            status_label,
            spinner,
        },
    )
}

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
    fn test_texture_from_rgba() {
        let empty = RgbaImageBuffer::new(0, 0, Vec::new()).expect("valid 0x0 buffer");
        assert!(texture_from_rgba(&empty).is_none());

        // GTK Texture creation requires an active GDK backend/display or returns a Texture
        let valid = RgbaImageBuffer::new(2, 2, vec![255u8; 16]).expect("valid 2x2 buffer");
        if gdk::Display::default().is_some() {
            assert!(texture_from_rgba(&valid).is_some());
        }
    }
}
