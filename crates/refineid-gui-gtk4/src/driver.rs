// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

//! GTK 4 presentation driver for RefineID: one window, laid out as the
//! Mac app's (`doc/gui-architecture.md`).
//!
//! From the top: the identity line, then the document drop area with the
//! signing controls and the outcome of the last action. A contactless
//! card asking for its access number, a card waiting to be taken into
//! use, and the pairing prompt replace that content. The header bar holds
//! one control: the remote-use switch, or the button that opens the PIN
//! codes window while a card is in a reader here.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use refineid_gui_core::controller::RefineIdController;
use refineid_gui_core::driver::UiDriver;
use refineid_gui_core::error::GuiCoreError;
use refineid_gui_core::model::{CanRequest, SignFormat, UiState, UserIntent};
use refineid_gui_core::window::{
    self, IdentityLine, PinTask, Recovery, WindowContent, activation_complete, digits_only,
};
use refineid_lib_core::can::{CAN_DIGITS, Can};
use refineid_lib_core::pin::PinBytes;
use refineid_rapp_core::offer::{
    PAIRING_CODE_GROUP_SIZE, PAIRING_CODE_LENGTH, pairing_code_character,
};

use gtk4::gdk;
use gtk4::gio;
use gtk4::glib;
use gtk4::prelude::*;

/// The window's natural width, as the Mac window's.
const WINDOW_WIDTH: i32 = 560;
/// The space around and between the window's sections.
const SPACING: i32 = 14;
/// The margin around the window's content.
const PADDING: i32 = 24;
/// The drop area's least height.
const DROP_HEIGHT: i32 = 96;
/// The pile's height before it scrolls.
const PILE_HEIGHT: i32 = 132;
/// One code box's width and height.
const CODE_BOX_WIDTH: i32 = 40;
const CODE_BOX_HEIGHT: i32 = 48;
/// The gap between two-character clusters of the pairing code.
const CODE_GROUP_GAP: i32 = 12;
/// How often the driver takes the controller's state snapshots.
const STATE_POLL: std::time::Duration = std::time::Duration::from_millis(50);
/// The icons of the header bar and the drop area.
const PHONE_ICON: &str = "phone-symbolic";
const PIN_CODES_ICON: &str = "dialog-password-symbolic";
const DROP_ICON: &str = "document-open-symbolic";
const REMOVE_ICON: &str = "window-close-symbolic";
const BELOW_FLOOR_ICON: &str = "dialog-error-symbolic";

/// The styles GTK's own theme lacks: the code boxes and the drop area's
/// highlight while a drag is over it.
const CSS: &str = "
.code-box { border: 1px solid alpha(currentColor, 0.3); border-radius: 8px; }
.code-box.active { border: 2px solid @accent_color; }
.code-box.refused { border: 2px solid @error_color; }
.code-char { font-family: monospace; font-size: 20px; font-weight: bold; }
.drop-area { border: 1px solid alpha(currentColor, 0.15); border-radius: 10px; padding: 12px; }
.drop-area.targeted { border: 2px solid @accent_color; }
";

/// Keeps the code characters of `typed`, up to the code's length.
fn pairing_code(typed: &str) -> String {
    typed
        .chars()
        .filter_map(pairing_code_character)
        .take(PAIRING_CODE_LENGTH)
        .collect()
}

/// Keeps the digits of `typed`, up to the access number's length.
fn access_number(typed: &str) -> String {
    digits_only(typed, CAN_DIGITS)
}

/// Keeps the digits of a typed PIN, up to the longest PIN.
fn pin_entry(typed: &str) -> String {
    digits_only(typed, PinBytes::MAX_LENGTH)
}

fn to_pin_bytes(s: &str) -> Option<PinBytes> {
    PinBytes::new(s.as_bytes().to_vec()).ok()
}

/// Gives `widget` the name a screen reader reads.
fn name(widget: &impl IsA<gtk4::Accessible>, label: &str) {
    widget.update_property(&[gtk4::accessible::Property::Label(label)]);
}

/// A label aligned to the start, wrapping.
fn text_label(text: &str) -> gtk4::Label {
    gtk4::Label::builder()
        .label(text)
        .halign(gtk4::Align::Start)
        .xalign(0.0)
        .wrap(true)
        .build()
}

/// A vertical box with the window's spacing.
fn column() -> gtk4::Box {
    gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(SPACING)
        .build()
}

/// A masked PIN entry that keeps digits only, named for screen readers.
fn pin_field(label: &str) -> gtk4::PasswordEntry {
    let entry = gtk4::PasswordEntry::builder()
        .show_peek_icon(true)
        .hexpand(true)
        .build();
    name(&entry, label);
    entry.connect_changed(|entry| {
        let kept = pin_entry(&entry.text());
        if kept != entry.text().as_str() {
            entry.set_text(&kept);
            entry.set_position(-1);
        }
    });
    entry
}

/// A form row: the field's name before the field.
fn form_row(label: &gtk4::Label, field: &impl IsA<gtk4::Widget>) -> gtk4::Box {
    let row = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(SPACING)
        .build();
    label.set_width_chars(20);
    label.set_wrap(false);
    row.append(label);
    row.append(field);
    row
}

/// The six-box code entry: one box per character, typed into a hidden
/// entry that carries the field's accessible name.
#[derive(Clone)]
struct CodeBoxes {
    container: gtk4::Box,
    frames: Vec<gtk4::Frame>,
    labels: Vec<gtk4::Label>,
    entry: gtk4::Entry,
}

impl CodeBoxes {
    fn new(
        length: usize,
        group: Option<usize>,
        label: &str,
        caption: Option<&str>,
        filter: fn(&str) -> String,
        on_complete: impl Fn(String) + 'static,
    ) -> Self {
        let container = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(6)
            .halign(gtk4::Align::Start)
            .build();
        if let Some(caption) = caption {
            let caption = gtk4::Label::new(Some(caption));
            caption.add_css_class("dim-label");
            container.append(&caption);
        }
        let mut frames = Vec::with_capacity(length);
        let mut labels = Vec::with_capacity(length);
        for index in 0..length {
            if group.is_some_and(|size| index > 0 && index % size == 0) {
                container.append(&gtk4::Box::builder().width_request(CODE_GROUP_GAP).build());
            }
            let frame = gtk4::Frame::builder()
                .width_request(CODE_BOX_WIDTH)
                .height_request(CODE_BOX_HEIGHT)
                .build();
            frame.add_css_class("code-box");
            let character = gtk4::Label::new(None);
            character.add_css_class("code-char");
            frame.set_child(Some(&character));
            container.append(&frame);
            frames.push(frame);
            labels.push(character);
        }
        let entry = gtk4::Entry::builder()
            .opacity(0.0)
            .width_request(1)
            .max_length(i32::try_from(length).unwrap_or(i32::MAX))
            .build();
        name(&entry, label);
        container.append(&entry);
        let click = gtk4::GestureClick::new();
        let focus = entry.clone();
        click.connect_pressed(move |_, _, _, _| {
            focus.grab_focus();
        });
        container.add_controller(click);

        let boxes = Self {
            container,
            frames,
            labels,
            entry,
        };
        let shown = boxes.clone();
        boxes.entry.connect_changed(move |entry| {
            let kept = filter(&entry.text());
            if kept != entry.text().as_str() {
                entry.set_text(&kept);
                entry.set_position(-1);
                return;
            }
            shown.set_refused(false);
            shown.render();
            if kept.chars().count() == length {
                on_complete(kept);
            }
        });
        let focused = boxes.clone();
        let focus_events = gtk4::EventControllerFocus::new();
        focus_events.connect_enter(move |_| focused.render());
        let unfocused = boxes.clone();
        focus_events.connect_leave(move |_| unfocused.render());
        boxes.entry.add_controller(focus_events);
        boxes
    }

    /// Draws the typed characters into the boxes; the box the next one
    /// lands in carries the accent while the entry has focus.
    fn render(&self) {
        let typed: Vec<char> = self.entry.text().chars().collect();
        let focused = self.entry.has_focus();
        for (index, (frame, label)) in self.frames.iter().zip(&self.labels).enumerate() {
            label.set_label(&typed.get(index).map(char::to_string).unwrap_or_default());
            if focused && index == typed.len() {
                frame.add_css_class("active");
            } else {
                frame.remove_css_class("active");
            }
        }
    }

    fn clear(&self) {
        self.entry.set_text("");
        self.render();
    }

    /// Marks every box as refused until the next character is typed.
    fn set_refused(&self, refused: bool) {
        for frame in &self.frames {
            if refused {
                frame.add_css_class("refused");
            } else {
                frame.remove_css_class("refused");
            }
        }
    }
}

/// The activation form.
struct ActivationWidgets {
    container: gtk4::Box,
    heading: gtk4::Label,
    code: gtk4::PasswordEntry,
}

/// The PIN codes window.
struct PinCodesWidgets {
    window: gtk4::Window,
    recovery: [gtk4::Label; 2],
    tasks: gtk4::Box,
    task_buttons: Vec<(PinTask, gtk4::ToggleButton)>,
    form: gtk4::Box,
    field_labels: [gtk4::Label; 3],
    entries: [gtk4::PasswordEntry; 3],
    action: gtk4::Button,
    attempts: gtk4::Box,
    attempts_entries: gtk4::Box,
    error: gtk4::Label,
    task: Cell<PinTask>,
}

/// Every widget the driver updates, and what it remembers between
/// snapshots.
struct Ui {
    controller: Arc<RefineIdController>,
    window: gtk4::Window,
    remote_switch: gtk4::ToggleButton,
    pin_codes_button: gtk4::Button,
    identity: gtk4::Label,
    prompt: gtk4::Box,
    pairing_boxes: CodeBoxes,
    pairing_spinner: gtk4::Spinner,
    can: gtk4::Box,
    can_boxes: CodeBoxes,
    activation: ActivationWidgets,
    documents: gtk4::Box,
    drop_area: gtk4::Box,
    invitation: gtk4::Box,
    pile: gtk4::ScrolledWindow,
    pile_list: gtk4::ListBox,
    pile_footer: gtk4::Box,
    signing: gtk4::Box,
    separately: gtk4::ToggleButton,
    package: gtk4::ToggleButton,
    pin2_row: gtk4::Box,
    pin2: gtk4::PasswordEntry,
    sign_spinner: gtk4::Spinner,
    sign: gtk4::Button,
    result: gtk4::Label,
    error: gtk4::Label,
    pin_codes: PinCodesWidgets,
    last: RefCell<UiState>,
    shown_pile: RefCell<Vec<PathBuf>>,
    /// Set while a snapshot is applied, so that the toggles it sets are
    /// not taken for the user's clicks.
    applying: Cell<bool>,
    content: Cell<Option<WindowContent>>,
    pairing_running: Cell<bool>,
    /// Whether the PIN codes window opened by itself for the card now in
    /// the reader.
    opened_for_card: Cell<bool>,
}

/// Presentation driver using GTK 4.
pub struct Gtk4Driver {
    receiver: Option<std::sync::mpsc::Receiver<UiState>>,
}

impl std::fmt::Debug for Gtk4Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gtk4Driver").finish_non_exhaustive()
    }
}

/// Notification callback invoked on state changes.
pub type StateChangeCallback = Box<dyn Fn(&UiState) + Send + Sync + 'static>;

impl Gtk4Driver {
    /// Construct a new driver and its state notification callback.
    pub fn create() -> (Self, StateChangeCallback) {
        let (sender, receiver) = std::sync::mpsc::channel::<UiState>();
        let on_state_change: StateChangeCallback = Box::new(move |state: &UiState| {
            let _ = sender.send(state.clone());
        });
        (
            Self {
                receiver: Some(receiver),
            },
            on_state_change,
        )
    }

    fn load_css() {
        let provider = gtk4::CssProvider::new();
        provider.load_from_data(CSS);
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
        glib::set_prgname(Some("refineid-gui"));
        glib::set_application_name("RefineID");
        Self::load_css();

        let ui = Ui::build(&controller);
        ui.apply(&controller.state());

        if let Some(receiver) = self.receiver.take() {
            let polled = Rc::clone(&ui);
            glib::timeout_add_local(STATE_POLL, move || {
                while let Ok(state) = receiver.try_recv() {
                    polled.apply(&state);
                }
                glib::ControlFlow::Continue
            });
        }

        let main_loop = glib::MainLoop::new(None, false);
        let quit = main_loop.clone();
        ui.window.connect_close_request(move |_| {
            quit.quit();
            glib::Propagation::Proceed
        });
        ui.window.present();
        main_loop.run();

        controller.stop();
        Ok(())
    }
}

impl Ui {
    fn build(controller: &Arc<RefineIdController>) -> Rc<Self> {
        let window = gtk4::Window::builder()
            .title("RefineID")
            .default_width(WINDOW_WIDTH)
            .build();

        let header = gtk4::HeaderBar::new();
        let remote_switch = gtk4::ToggleButton::builder()
            .icon_name(PHONE_ICON)
            .tooltip_text(window::REMOTE_ACCESS)
            .build();
        name(&remote_switch, window::REMOTE_ACCESS);
        let pin_codes_button = gtk4::Button::builder()
            .icon_name(PIN_CODES_ICON)
            .tooltip_text(window::PIN_CODES)
            .visible(false)
            .build();
        name(&pin_codes_button, window::PIN_CODES);
        header.pack_end(&remote_switch);
        header.pack_end(&pin_codes_button);
        window.set_titlebar(Some(&header));

        let root = column();
        root.set_margin_top(PADDING);
        root.set_margin_bottom(PADDING);
        root.set_margin_start(PADDING);
        root.set_margin_end(PADDING);

        let identity = text_label("");
        identity.set_selectable(true);
        root.append(&identity);

        // The pairing prompt.
        let prompt = column();
        prompt.append(&text_label(window::PAIRING_PROMPT));
        let prompt_row = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(SPACING)
            .build();
        let pairing_controller = Arc::clone(controller);
        let pairing_boxes = CodeBoxes::new(
            PAIRING_CODE_LENGTH,
            Some(PAIRING_CODE_GROUP_SIZE),
            window::PAIRING_CODE,
            None,
            pairing_code,
            move |code| pairing_controller.handle_intent(UserIntent::StartPairing { code }),
        );
        let pairing_spinner = gtk4::Spinner::new();
        name(&pairing_spinner, window::CONNECTING_TO_PHONE_PROGRESS);
        prompt_row.append(&pairing_boxes.container);
        prompt_row.append(&pairing_spinner);
        prompt.append(&prompt_row);
        root.append(&prompt);

        // The card access number entry.
        let can = column();
        let can_controller = Arc::clone(controller);
        let can_boxes = CodeBoxes::new(
            CAN_DIGITS,
            None,
            window::CARD_ACCESS_NUMBER,
            Some(window::CAN_CAPTION),
            access_number,
            move |digits| {
                if let Ok(number) = Can::new(&digits) {
                    can_controller.handle_intent(UserIntent::EnterCan(number));
                }
            },
        );
        can.append(&can_boxes.container);
        root.append(&can);

        let activation = build_activation(controller);
        root.append(&activation.container);

        // The drop area, the signing controls and the outcome.
        let documents = column();
        let drop_area = column();
        drop_area.add_css_class("drop-area");
        drop_area.set_size_request(-1, DROP_HEIGHT);
        name(&drop_area, window::DOCUMENTS_TO_SIGN);
        let invitation = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Vertical)
            .spacing(6)
            .valign(gtk4::Align::Center)
            .vexpand(true)
            .build();
        let drop_icon = gtk4::Image::from_icon_name(DROP_ICON);
        drop_icon.set_pixel_size(32);
        drop_icon.add_css_class("dim-label");
        invitation.append(&drop_icon);
        let invitation_text = gtk4::Label::new(Some(window::DROP_INVITATION));
        invitation_text.add_css_class("dim-label");
        invitation.append(&invitation_text);
        let choose = gtk4::Button::with_label(window::CHOOSE);
        choose.add_css_class("flat");
        choose.set_halign(gtk4::Align::Center);
        invitation.append(&choose);
        drop_area.append(&invitation);

        let pile_list = gtk4::ListBox::builder()
            .selection_mode(gtk4::SelectionMode::None)
            .build();
        name(&pile_list, window::DOCUMENTS_TO_SIGN);
        let pile = gtk4::ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .propagate_natural_height(true)
            .max_content_height(PILE_HEIGHT)
            .child(&pile_list)
            .build();
        drop_area.append(&pile);
        let pile_footer = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .halign(gtk4::Align::End)
            .build();
        let add = gtk4::Button::with_label(window::ADD);
        add.add_css_class("flat");
        let clear = gtk4::Button::with_label(window::CLEAR);
        clear.add_css_class("flat");
        pile_footer.append(&add);
        pile_footer.append(&clear);
        drop_area.append(&pile_footer);
        documents.append(&drop_area);

        let signing = column();
        let method = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .build();
        method.add_css_class("linked");
        let separately = gtk4::ToggleButton::with_label(window::SEPARATELY);
        let package = gtk4::ToggleButton::with_label(window::AS_A_PACKAGE);
        package.set_group(Some(&separately));
        method.append(&separately);
        method.append(&package);
        name(&method, window::SIGNING_METHOD);
        signing.append(&form_row(&text_label(window::SIGNING_METHOD), &method));
        let pin2 = pin_field(window::PIN_2);
        let pin2_row = form_row(&text_label(window::PIN_2), &pin2);
        signing.append(&pin2_row);
        let action = gtk4::Box::builder()
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(SPACING)
            .halign(gtk4::Align::End)
            .build();
        let sign_spinner = gtk4::Spinner::new();
        name(&sign_spinner, window::SIGNING_DOCUMENT);
        let sign = gtk4::Button::with_label(window::SIGN);
        sign.add_css_class("suggested-action");
        action.append(&sign_spinner);
        action.append(&sign);
        signing.append(&action);
        documents.append(&signing);
        root.append(&documents);

        let result = text_label("");
        result.set_selectable(true);
        root.append(&result);
        let error = text_label("");
        error.add_css_class("error");
        error.set_selectable(true);
        root.append(&error);

        window.set_child(Some(&root));
        let pin_codes = build_pin_codes(&window);

        let ui = Rc::new(Self {
            controller: Arc::clone(controller),
            window,
            remote_switch,
            pin_codes_button,
            identity,
            prompt,
            pairing_boxes,
            pairing_spinner,
            can,
            can_boxes,
            activation,
            documents,
            drop_area,
            invitation,
            pile,
            pile_list,
            pile_footer,
            signing,
            separately,
            package,
            pin2_row,
            pin2,
            sign_spinner,
            sign,
            result,
            error,
            pin_codes,
            last: RefCell::new(UiState::default()),
            shown_pile: RefCell::new(Vec::new()),
            applying: Cell::new(false),
            content: Cell::new(None),
            pairing_running: Cell::new(false),
            opened_for_card: Cell::new(false),
        });
        ui.wire(&choose, &add, &clear);
        ui
    }

    /// Connects the controls that need the whole window.
    fn wire(self: &Rc<Self>, choose: &gtk4::Button, add: &gtk4::Button, clear: &gtk4::Button) {
        let ui = Rc::clone(self);
        self.remote_switch.connect_toggled(move |switch| {
            if !ui.applying.get() {
                ui.controller
                    .handle_intent(UserIntent::SetRemoteUse(switch.is_active()));
            }
        });
        let ui = Rc::clone(self);
        self.pin_codes_button
            .connect_clicked(move |_| ui.pin_codes.window.present());

        for button in [choose, add] {
            let ui = Rc::clone(self);
            button.connect_clicked(move |_| ui.choose_documents());
        }
        let controller = Arc::clone(&self.controller);
        clear.connect_clicked(move |_| controller.handle_intent(UserIntent::ClearDocuments));

        let drop = gtk4::DropTarget::new(gdk::FileList::static_type(), gdk::DragAction::COPY);
        let controller = Arc::clone(&self.controller);
        let area = self.drop_area.clone();
        drop.connect_drop(move |_, value, _, _| {
            area.remove_css_class("targeted");
            let Ok(files) = value.get::<gdk::FileList>() else {
                return false;
            };
            let paths: Vec<PathBuf> = files
                .files()
                .iter()
                .filter_map(|file| file.path())
                .collect();
            if paths.is_empty() {
                return false;
            }
            controller.handle_intent(UserIntent::AddDocuments(paths));
            true
        });
        let area = self.drop_area.clone();
        drop.connect_enter(move |_, _, _| {
            area.add_css_class("targeted");
            gdk::DragAction::COPY
        });
        let area = self.drop_area.clone();
        drop.connect_leave(move |_| area.remove_css_class("targeted"));
        self.drop_area.add_controller(drop);

        for (button, format) in [
            (&self.separately, SignFormat::Pades),
            (&self.package, SignFormat::AsicE),
        ] {
            let ui = Rc::clone(self);
            button.connect_toggled(move |button| {
                if button.is_active() && !ui.applying.get() {
                    ui.controller
                        .handle_intent(UserIntent::SetSignFormat(format));
                }
            });
        }

        let ui = Rc::clone(self);
        self.pin2.connect_changed(move |_| ui.update_sign_button());
        let ui = Rc::clone(self);
        self.pin2.connect_activate(move |_| ui.sign());
        let ui = Rc::clone(self);
        self.sign.connect_clicked(move |_| ui.sign());

        let ui = Rc::clone(self);
        self.pin_codes.window.connect_close_request(move |window| {
            window.set_visible(false);
            for entry in &ui.pin_codes.entries {
                entry.set_text("");
            }
            glib::Propagation::Stop
        });
        for entry in &self.pin_codes.entries {
            let ui = Rc::clone(self);
            entry.connect_changed(move |_| ui.update_pin_action());
        }
        let ui = Rc::clone(self);
        self.pin_codes
            .action
            .connect_clicked(move |_| ui.run_pin_task());
        for (task, button) in &self.pin_codes.task_buttons {
            let ui = Rc::clone(self);
            let task = *task;
            button.connect_toggled(move |button| {
                if button.is_active() && !ui.applying.get() {
                    ui.show_pin_task(task);
                }
            });
        }
    }

    /// Opens the file dialog; the chosen files join the pile.
    fn choose_documents(&self) {
        let chooser = gtk4::FileChooserNative::new(
            None,
            Some(&self.window),
            gtk4::FileChooserAction::Open,
            None,
            None,
        );
        chooser.set_select_multiple(true);
        let controller = Arc::clone(&self.controller);
        chooser.connect_response(move |dialog, response| {
            if response != gtk4::ResponseType::Accept {
                return;
            }
            let files = dialog.files();
            let paths: Vec<PathBuf> = (0..files.n_items())
                .filter_map(|index| files.item(index))
                .filter_map(|item| item.downcast::<gio::File>().ok())
                .filter_map(|file| file.path())
                .collect();
            if !paths.is_empty() {
                controller.handle_intent(UserIntent::AddDocuments(paths));
            }
        });
        keep_until_response(&chooser);
        chooser.show();
    }

    fn sign(&self) {
        let state = self.last.borrow().clone();
        let typed = self.pin2.text();
        if !window::can_sign(&state, &typed) {
            return;
        }
        self.pin2.set_text("");
        if state.phone_signs() {
            // PIN 2 for the phone's card is typed on the phone.
            self.controller
                .handle_intent(UserIntent::SignDocuments { pin2: None });
        } else if let Some(pin2) = to_pin_bytes(&typed) {
            self.controller
                .handle_intent(UserIntent::SignDocuments { pin2: Some(pin2) });
        }
    }

    fn update_sign_button(&self) {
        let ready = window::can_sign(&self.last.borrow(), &self.pin2.text());
        self.sign.set_sensitive(ready);
    }

    fn pin_entries(&self) -> [String; 3] {
        self.pin_codes
            .entries
            .each_ref()
            .map(|entry| entry.text().to_string())
    }

    fn update_pin_action(&self) {
        let task = self.pin_codes.task.get();
        let entries = self.pin_entries();
        let ready = task.complete(entries.each_ref().map(String::as_str))
            && task.available(&self.last.borrow());
        self.pin_codes.action.set_sensitive(ready);
    }

    fn show_pin_task(&self, task: PinTask) {
        self.pin_codes.task.set(task);
        for (label, text) in self.pin_codes.field_labels.iter().zip(task.fields()) {
            label.set_label(text);
        }
        for (entry, text) in self.pin_codes.entries.iter().zip(task.fields()) {
            entry.set_text("");
            name(entry, text);
        }
        self.pin_codes.action.set_label(task.action());
        self.update_pin_action();
    }

    fn run_pin_task(&self) {
        let task = self.pin_codes.task.get();
        let entries = self.pin_entries();
        for entry in &self.pin_codes.entries {
            entry.set_text("");
        }
        if !task.complete(entries.each_ref().map(String::as_str)) {
            return;
        }
        let (Some(presented), Some(new_pin)) =
            (to_pin_bytes(&entries[0]), to_pin_bytes(&entries[1]))
        else {
            return;
        };
        let slot = task.manage_slot();
        self.controller.handle_intent(if task.uses_puk() {
            UserIntent::ReactivatePin {
                slot,
                puk: presented,
                new_pin,
            }
        } else {
            UserIntent::ChangePin {
                slot,
                current_pin: presented,
                new_pin,
            }
        });
    }

    /// Applies one snapshot of the controller's state.
    fn apply(&self, state: &UiState) {
        self.applying.set(true);
        *self.last.borrow_mut() = state.clone();
        self.window.set_title(Some(&state.window_title));

        let line = IdentityLine::derive(state);
        let content = WindowContent::derive(state);
        let entered = self.content.replace(Some(content)) != Some(content);

        // The header bar's one control.
        let opens_pin_codes = window::toolbar_opens_pin_codes(state);
        self.pin_codes_button.set_visible(opens_pin_codes);
        self.remote_switch.set_visible(!opens_pin_codes);
        self.remote_switch.set_active(state.remote_use);
        self.remote_switch
            .update_property(&[gtk4::accessible::Property::Description(
                if state.remote_use {
                    window::REMOTE_ON
                } else {
                    window::REMOTE_OFF
                },
            )]);

        // The identity line, absent while a form replaces it.
        let replaced = matches!(
            content,
            WindowContent::CardAccessNumber(_) | WindowContent::Activation
        );
        let text = line.text();
        self.identity.set_label(&text);
        self.identity.set_visible(!replaced && !text.is_empty());
        if line.is_holder() || line.is_warning() {
            self.identity.remove_css_class("dim-label");
        } else {
            self.identity.add_css_class("dim-label");
        }
        if line.is_warning() {
            self.identity.add_css_class("warning");
        } else {
            self.identity.remove_css_class("warning");
        }

        // The pairing prompt.
        self.prompt
            .set_visible(content == WindowContent::PairingPrompt);
        let running = state.pairing.is_some();
        self.pairing_boxes.entry.set_sensitive(!running);
        self.pairing_spinner.set_visible(running);
        self.pairing_spinner.set_spinning(running);
        if self.pairing_running.replace(running) && !running {
            self.pairing_boxes.clear();
            self.pairing_boxes
                .set_refused(!state.status_message.is_empty());
        }
        if entered && content == WindowContent::PairingPrompt {
            self.pairing_boxes.clear();
            self.pairing_boxes.entry.grab_focus();
        }

        // The card access number.
        let can_request = match content {
            WindowContent::CardAccessNumber(request) => Some(request),
            _ => None,
        };
        self.can.set_visible(can_request.is_some());
        if entered && can_request.is_some() {
            self.can_boxes.clear();
            self.can_boxes
                .set_refused(can_request == Some(CanRequest::Refused));
            self.can_boxes.entry.grab_focus();
        }

        // The activation form.
        self.activation
            .container
            .set_visible(content == WindowContent::Activation);
        if content == WindowContent::Activation {
            self.activation
                .heading
                .set_label(window::activation_heading(state));
        }
        if entered && content == WindowContent::Activation {
            self.activation.code.grab_focus();
        }

        // The documents.
        self.documents
            .set_visible(content == WindowContent::Documents);
        self.apply_pile(state);
        let pile = !state.pdf_documents.is_empty();
        self.signing.set_visible(pile);
        let every_one_a_pdf = SignFormat::shared(&state.pdf_documents) == SignFormat::Pades;
        self.separately.set_sensitive(every_one_a_pdf);
        self.package.set_sensitive(every_one_a_pdf);
        match state.sign_format {
            SignFormat::Pades => self.separately.set_active(true),
            SignFormat::AsicE => self.package.set_active(true),
        }
        self.pin2_row.set_visible(window::asks_pin2_here(state));
        let signing = state.busy && pile;
        self.sign_spinner.set_visible(signing);
        self.sign_spinner.set_spinning(signing);
        self.update_sign_button();

        // The outcome of the last action.
        let result = state.sign_result.clone().unwrap_or_default();
        self.result.set_label(&result);
        self.result
            .set_visible(!result.is_empty() && matches!(content, WindowContent::Documents));
        self.error.set_label(&state.status_message);
        self.error.set_visible(!state.status_message.is_empty());

        self.apply_pin_codes(state, opens_pin_codes);
        self.applying.set(false);
    }

    /// Lists the pile, or shows the invitation while it is empty.
    fn apply_pile(&self, state: &UiState) {
        let pile = !state.pdf_documents.is_empty();
        self.invitation.set_visible(!pile);
        self.pile.set_visible(pile);
        self.pile_footer.set_visible(pile);
        if *self.shown_pile.borrow() == state.pdf_documents {
            return;
        }
        self.shown_pile.replace(state.pdf_documents.clone());
        while let Some(row) = self.pile_list.first_child() {
            self.pile_list.remove(&row);
        }
        for document in &state.pdf_documents {
            let file_name = document.file_name().map_or_else(
                || document.display().to_string(),
                |name| name.to_string_lossy().into_owned(),
            );
            let row = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Horizontal)
                .spacing(8)
                .margin_top(4)
                .margin_bottom(4)
                .build();
            let label = gtk4::Label::builder()
                .label(&file_name)
                .halign(gtk4::Align::Start)
                .hexpand(true)
                .ellipsize(gtk4::pango::EllipsizeMode::Middle)
                .tooltip_text(document.display().to_string())
                .build();
            let remove = gtk4::Button::from_icon_name(REMOVE_ICON);
            remove.add_css_class("flat");
            remove.add_css_class("circular");
            let remove_name = window::remove_document(&file_name);
            remove.set_tooltip_text(Some(&remove_name));
            name(&remove, &remove_name);
            let controller = Arc::clone(&self.controller);
            let path = document.clone();
            remove.connect_clicked(move |_| {
                controller.handle_intent(UserIntent::RemoveDocument(path.clone()));
            });
            row.append(&label);
            row.append(&remove);
            self.pile_list.append(&row);
        }
    }

    /// Updates the PIN codes window, opens it by itself once per card
    /// when a code is below the retry floor, and closes it when the card
    /// leaves.
    fn apply_pin_codes(&self, state: &UiState, card_here: bool) {
        let pin = &self.pin_codes;
        if !card_here {
            self.opened_for_card.set(false);
            pin.window.set_visible(false);
            return;
        }
        let recovery = Recovery::derive(state);
        if recovery.is_some() {
            self.pin_codes_button.add_css_class("error");
            self.pin_codes_button
                .update_property(&[gtk4::accessible::Property::Description(
                    window::PIN_NEEDS_RESET,
                )]);
        } else {
            self.pin_codes_button.remove_css_class("error");
            self.pin_codes_button
                .update_property(&[gtk4::accessible::Property::Description("")]);
        }
        let sentences = recovery.map(Recovery::sentences);
        for (index, label) in pin.recovery.iter().enumerate() {
            let text = sentences.map(|pair| pair[index]).unwrap_or_default();
            label.set_label(text);
            label.set_visible(!text.is_empty());
            if matches!(
                recovery,
                Some(Recovery::UseOtherSoftware | Recovery::Unrecoverable)
            ) {
                label.add_css_class("error");
            } else {
                label.remove_css_class("error");
            }
        }

        let tasks = Recovery::tasks(recovery);
        for (task, button) in &pin.task_buttons {
            button.set_visible(tasks.contains(task));
        }
        pin.tasks.set_visible(!tasks.is_empty());
        pin.form.set_visible(!tasks.is_empty());
        if !tasks.contains(&pin.task.get()) {
            let initial = Recovery::initial_task(recovery);
            if let Some((_, button)) = pin.task_buttons.iter().find(|(task, _)| *task == initial) {
                button.set_active(true);
            }
            self.show_pin_task(initial);
        }
        self.update_pin_action();

        let entries = window::attempts_below_full(state);
        while let Some(child) = pin.attempts_entries.first_child() {
            pin.attempts_entries.remove(&child);
        }
        for entry in &entries {
            let item = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Horizontal)
                .spacing(4)
                .build();
            let text = gtk4::Label::new(Some(&entry.text));
            item.append(&text);
            if entry.below_floor {
                item.add_css_class("error");
                item.append(&gtk4::Image::from_icon_name(BELOW_FLOOR_ICON));
            }
            pin.attempts_entries.append(&item);
        }
        pin.attempts.set_visible(!entries.is_empty());
        pin.error.set_label(&state.status_message);
        pin.error.set_visible(!state.status_message.is_empty());

        if recovery.is_some() && !self.opened_for_card.replace(true) {
            pin.window.present();
        }
    }
}

fn build_activation(controller: &Arc<RefineIdController>) -> ActivationWidgets {
    let container = column();
    let heading = text_label(window::IDENTITY_CARD_ACTIVATION);
    heading.add_css_class("heading");
    container.append(&heading);
    let code = pin_field(window::ACTIVATION_PIN);
    container.append(&form_row(&text_label(window::ACTIVATION_PIN), &code));
    let pin1 = [
        pin_field(window::NEW_PIN_1),
        pin_field(window::NEW_PIN_1_AGAIN),
    ];
    let pin2 = [
        pin_field(window::NEW_PIN_2),
        pin_field(window::NEW_PIN_2_AGAIN),
    ];
    for (entry, text) in pin1.iter().chain(&pin2).zip([
        window::NEW_PIN_1,
        window::NEW_PIN_1_AGAIN,
        window::NEW_PIN_2,
        window::NEW_PIN_2_AGAIN,
    ]) {
        container.append(&form_row(&text_label(text), entry));
    }
    let button = gtk4::Button::with_label(window::ACTIVATE_CARD);
    button.add_css_class("suggested-action");
    button.set_halign(gtk4::Align::End);
    container.append(&button);

    let entries: Vec<gtk4::PasswordEntry> = std::iter::once(code.clone())
        .chain(pin1.clone())
        .chain(pin2.clone())
        .collect();
    let filled = {
        let entries = entries.clone();
        move || {
            let text: Vec<String> = entries.iter().map(|e| e.text().to_string()).collect();
            activation_complete(&text[0], [&text[1], &text[2]], [&text[3], &text[4]])
        }
    };
    let filled = Rc::new(filled);
    for entry in &entries {
        let filled = Rc::clone(&filled);
        let button = button.clone();
        entry.connect_changed(move |_| button.set_sensitive(filled()));
    }
    button.set_sensitive(false);
    let controller = Arc::clone(controller);
    button.connect_clicked(move |_| {
        if controller.state().busy {
            return;
        }
        let text: Vec<String> = entries.iter().map(|e| e.text().to_string()).collect();
        for entry in &entries {
            entry.set_text("");
        }
        if !activation_complete(&text[0], [&text[1], &text[2]], [&text[3], &text[4]]) {
            return;
        }
        if let (Some(activation_code), Some(new_pin1), Some(new_pin2)) = (
            to_pin_bytes(&text[0]),
            to_pin_bytes(&text[1]),
            to_pin_bytes(&text[3]),
        ) {
            controller.handle_intent(UserIntent::ActivateCard {
                activation_code,
                new_pin1,
                new_pin2,
            });
        }
    });
    ActivationWidgets {
        container,
        heading,
        code,
    }
}

fn build_pin_codes(parent: &gtk4::Window) -> PinCodesWidgets {
    let window = gtk4::Window::builder()
        .title(window::PIN_CODES)
        .transient_for(parent)
        .default_width(WINDOW_WIDTH)
        .build();
    let root = column();
    root.set_margin_top(PADDING);
    root.set_margin_start(PADDING);
    root.set_margin_end(PADDING);
    root.set_margin_bottom(SPACING);

    let recovery = [text_label(""), text_label("")];
    for label in &recovery {
        label.set_visible(false);
        root.append(label);
    }

    let tasks = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .halign(gtk4::Align::Center)
        .build();
    tasks.add_css_class("linked");
    let mut task_buttons: Vec<(PinTask, gtk4::ToggleButton)> = Vec::new();
    for task in PinTask::ALL {
        let button = gtk4::ToggleButton::with_label(task.name());
        if let Some((_, first)) = task_buttons.first() {
            button.set_group(Some(first));
        }
        tasks.append(&button);
        task_buttons.push((task, button));
    }
    if let Some((_, first)) = task_buttons.first() {
        first.set_active(true);
    }
    root.append(&tasks);

    let form = column();
    let fields = PinTask::ChangePin1.fields();
    let field_labels = fields.map(text_label);
    let entries = fields.map(pin_field);
    for (label, entry) in field_labels.iter().zip(&entries) {
        form.append(&form_row(label, entry));
    }
    let action = gtk4::Button::with_label(PinTask::ChangePin1.action());
    action.add_css_class("suggested-action");
    action.set_halign(gtk4::Align::End);
    action.set_sensitive(false);
    form.append(&action);
    root.append(&form);

    let error = text_label("");
    error.add_css_class("error");
    error.set_visible(false);
    root.append(&error);

    let attempts = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(SPACING)
        .build();
    let attempts_label = gtk4::Label::new(Some(window::ATTEMPTS_LEFT));
    attempts_label.add_css_class("dim-label");
    attempts.append(&attempts_label);
    let attempts_entries = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(SPACING)
        .build();
    attempts.append(&attempts_entries);
    attempts.set_visible(false);
    root.append(&attempts);

    window.set_child(Some(&root));
    PinCodesWidgets {
        window,
        recovery,
        tasks,
        task_buttons,
        form,
        field_labels,
        entries,
        action,
        attempts,
        attempts_entries,
        error,
        task: Cell::new(PinTask::ChangePin1),
    }
}

/// Holds `chooser` until it answers. GTK keeps no reference to a native
/// dialog of its own; the last reference dropping destroys it, and
/// without a desktop portal it is gone before it is shown.
fn keep_until_response(chooser: &gtk4::FileChooserNative) {
    let held = Rc::new(RefCell::new(Some(chooser.clone())));
    chooser.connect_response(move |_, _| {
        let _released = held.borrow_mut().take();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_typed_code_keeps_its_code_characters() {
        assert_eq!(pairing_code("7KX4M9"), "7KX4M9");
        assert_eq!(pairing_code("7kx4m9"), "7KX4M9");
        assert_eq!(pairing_code("7-K-X-4-M-9"), "7KX4M9");
        assert_eq!(pairing_code("7KX4M9ZZZZ"), "7KX4M9");
        assert_eq!(pairing_code("!@#$%^&* "), "");
        assert_eq!(access_number("12a34b567"), "123456");
    }

    /// The window in process, where a display is available: the states
    /// the controller reports lay out as the Mac app's window.
    #[test]
    fn the_window_lays_out_each_state() {
        if gtk4::init().is_err() {
            return;
        }
        let controller = RefineIdController::new(|_| {});
        let ui = Ui::build(&controller);

        let mut state = UiState::default();
        ui.apply(&state);
        assert_eq!(ui.identity.label(), window::CONNECT_READER);
        assert!(!ui.documents.get_visible());
        assert!(!ui.prompt.get_visible());
        assert!(ui.remote_switch.get_visible());
        assert!(!ui.remote_switch.is_active());

        state.remote_use = true;
        ui.apply(&state);
        assert!(ui.prompt.get_visible());
        assert!(ui.remote_switch.is_active());

        state.pdf_documents = vec![PathBuf::from("/documents/report.pdf")];
        ui.apply(&state);
        assert!(ui.documents.get_visible());
        assert!(ui.signing.get_visible());
        assert!(!ui.prompt.get_visible());
        assert!(!ui.sign.is_sensitive());

        state.can_request = Some(CanRequest::Needed);
        ui.apply(&state);
        assert!(ui.can.get_visible());
        assert!(!ui.documents.get_visible());
        assert!(!ui.identity.get_visible());

        ui.pairing_boxes.entry.set_text("7kx4");
        assert_eq!(ui.pairing_boxes.labels[1].label(), "K");
    }
}
