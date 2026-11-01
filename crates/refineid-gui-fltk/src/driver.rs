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

//! FLTK presentation driver for RefineID: the one window of
//! `doc/gui-architecture.md` in FLTK's own widgets.
//!
//! The window is a column of sections that show and hide by state; the
//! remote-use switch, or the button that opens the PIN codes window, sits
//! at the right of the top row.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use fltk::app::{self, Receiver, Scheme};
use fltk::button::{Button, RadioButton, RadioRoundButton, ToggleButton};
use fltk::dialog::{FileDialogType, NativeFileChooser};
use fltk::draw;
use fltk::enums::{Align, CallbackTrigger, Color, Event, Font, FrameType, Key};
use fltk::frame::Frame;
use fltk::group::{Flex, Group, Pack, PackType, Scroll, ScrollType};
use fltk::input::{Input, SecretInput};
use fltk::prelude::*;
use fltk::window::Window;

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

/// The window's width and height, in pixels.
const WINDOW_WIDTH: i32 = 560;
const WINDOW_HEIGHT: i32 = 520;
/// The margin around the content and the gap between its sections.
const MARGIN: i32 = 20;
const GAP: i32 = 10;
/// The width of the content between the margins.
const CONTENT_WIDTH: i32 = WINDOW_WIDTH - 2 * MARGIN;
/// The height of one line of text, of a field and of a button.
const LINE: i32 = 26;
const FIELD: i32 = 30;
/// The width of a form row's name.
const LABEL_WIDTH: i32 = 170;
/// The width of the field beside it.
const FIELD_WIDTH: i32 = CONTENT_WIDTH - LABEL_WIDTH - GAP;
/// The width of a button.
const BUTTON_WIDTH: i32 = 130;
/// The side of the top row's one control.
const TOOL_SIZE: i32 = 30;
/// The drop area's height while empty, and the pile's height.
const DROP_HEIGHT: i32 = 96;
const PILE_HEIGHT: i32 = 132;
/// The height of one row of the pile.
const PILE_ROW: i32 = 24;
/// The side of one code box, the gap between boxes and between clusters.
const CODE_BOX_SIZE: i32 = 36;
const CODE_BOX_SPACING: i32 = 6;
const CODE_GROUP_GAP: i32 = 14;
/// The colours: the secondary text, errors, the accent, the boxes.
const SECONDARY: Color = Color::from_rgb(108, 117, 125);
const ERROR: Color = Color::from_rgb(200, 30, 30);
/// The colour of a warning line: orange.
const WARNING: Color = Color::from_rgb(230, 120, 0);
const ACCENT: Color = Color::from_rgb(0, 122, 255);
const BOX_BORDER: Color = Color::from_rgb(190, 190, 190);
const BACKGROUND: Color = Color::from_rgb(245, 246, 248);
/// The keys that would move a code input's cursor off the end.
const CURSOR_KEYS: [Key; 8] = [
    Key::Left,
    Key::Right,
    Key::Up,
    Key::Down,
    Key::Home,
    Key::End,
    Key::PageUp,
    Key::PageDown,
];
/// How a dropped file is named on the clipboard: a `file:` URI.
const FILE_URI_PREFIX: &str = "file://";
/// The radix of a percent-encoded byte.
const HEX_RADIX: u32 = 16;
/// The FLTK symbol drawn beside a counter below the retry floor.
const BELOW_FLOOR_SYMBOL: &str = "@circle";

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

fn set_shown<W: WidgetExt>(w: &mut W, shown: bool) {
    if shown {
        w.show();
    } else {
        w.hide();
    }
}

/// Keeps the code characters of `typed`, up to the pairing code's length.
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

/// The files a drop names: one `file:` URI or path per line.
fn dropped_paths(text: &str) -> Vec<PathBuf> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.strip_prefix(FILE_URI_PREFIX)
                .map_or_else(|| line.to_owned(), percent_decoded)
        })
        .map(PathBuf::from)
        .collect()
}

/// `text` with each `%XX` replaced by the byte it encodes.
fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let encoded = (byte == b'%')
            .then(|| bytes.get(index + 1..index + 3))
            .flatten()
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, HEX_RADIX).ok());
        if let Some(decoded) = encoded {
            out.push(decoded);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A text line aligned to the left of its section.
fn line_frame(x: i32, y: i32, w: i32, h: i32, text: &str) -> Frame {
    let mut frame = Frame::new(x, y, w, h, None);
    frame.set_label(text);
    frame.set_align(Align::Left | Align::Inside | Align::Wrap);
    frame
}

/// A section of the column, `height` tall, its children placed from its
/// top left.
fn section(height: i32) -> Group {
    let mut group = Group::new(0, 0, CONTENT_WIDTH, height, None);
    group.set_frame(FrameType::NoBox);
    group
}

/// A form row: the name, then a masked PIN entry that keeps digits only.
fn pin_row(y: i32, label: &str) -> (Frame, SecretInput) {
    let frame = line_frame(0, y, LABEL_WIDTH, FIELD, label);
    let mut input = SecretInput::new(LABEL_WIDTH + GAP, y, FIELD_WIDTH, FIELD, None);
    input.set_maximum_size(i32::try_from(PinBytes::MAX_LENGTH).unwrap_or(i32::MAX));
    input.set_trigger(CallbackTrigger::Changed);
    (frame, input)
}

/// Keeps the digits a PIN input was given.
fn keep_pin_digits(input: &mut SecretInput) {
    let kept = digits_only(&input.value(), PinBytes::MAX_LENGTH);
    if kept != input.value() {
        input.set_value(&kept);
    }
}

/// A primary button.
fn primary_button(x: i32, y: i32, label: &str) -> Button {
    let mut button = Button::new(x, y, BUTTON_WIDTH, FIELD, None);
    button.set_label(label);
    button.set_color(ACCENT);
    button.set_label_color(Color::White);
    button.set_label_font(Font::HelveticaBold);
    button
}

/// The width of a row of `length` boxes in clusters of `group`.
fn code_boxes_width(length: usize, group: usize) -> i32 {
    code_box_offset(length - 1, group) + CODE_BOX_SIZE
}

/// The left edge of box `index` relative to the row.
fn code_box_offset(index: usize, group: usize) -> i32 {
    let position = i32::try_from(index).unwrap_or(i32::MAX);
    let cluster = i32::try_from(index / group).unwrap_or(i32::MAX);
    position * (CODE_BOX_SIZE + CODE_BOX_SPACING) + cluster * (CODE_GROUP_GAP - CODE_BOX_SPACING)
}

/// An input drawn as one box per character, its cursor kept at the end;
/// `refused` marks every box until the next character.
fn code_input(x: i32, y: i32, length: usize, group: usize, refused: &Rc<RefCell<bool>>) -> Input {
    let mut input = Input::new(x, y, code_boxes_width(length, group), CODE_BOX_SIZE, None);
    input.set_frame(FrameType::NoBox);
    input.set_trigger(CallbackTrigger::Changed);
    input.set_maximum_size(i32::try_from(length).unwrap_or(i32::MAX));
    let marked = Rc::clone(refused);
    input.draw(move |input| {
        let end = input.value().len().try_into().unwrap_or(i32::MAX);
        if input.position() != end {
            let _ = input.set_position(end);
        }
        draw_code_boxes(input, length, group, *marked.borrow());
    });
    input.handle(|input, event| match event {
        Event::Focus | Event::Unfocus => {
            input.redraw();
            false
        }
        Event::Push => {
            let _ = input.take_focus();
            true
        }
        Event::Drag | Event::Released => true,
        Event::KeyDown => CURSOR_KEYS.contains(&app::event_key()),
        _ => false,
    });
    input
}

/// Draws `input` as `length` boxes; the box the next character lands in
/// carries the accent while the input has focus.
fn draw_code_boxes(input: &Input, length: usize, group: usize, refused: bool) {
    let code: Vec<char> = input.value().chars().collect();
    let active = input.active();
    let focused = input.has_focus();
    draw::draw_rect_fill(input.x(), input.y(), input.w(), input.h(), BACKGROUND);
    draw::set_font(Font::CourierBold, 20);
    for index in 0..length {
        let x = input.x() + code_box_offset(index, group);
        let y = input.y();
        let next = focused && active && index == code.len();
        let border = if refused {
            ERROR
        } else if next {
            ACCENT
        } else {
            BOX_BORDER
        };
        draw::draw_rect_with_color(x, y, CODE_BOX_SIZE, CODE_BOX_SIZE, border);
        if next || refused {
            draw::draw_rect_with_color(x + 1, y + 1, CODE_BOX_SIZE - 2, CODE_BOX_SIZE - 2, border);
        }
        if let Some(character) = code.get(index) {
            draw::set_draw_color(if active { Color::Black } else { SECONDARY });
            draw::draw_text2(
                &character.to_string(),
                x,
                y,
                CODE_BOX_SIZE,
                CODE_BOX_SIZE,
                Align::Center,
            );
        }
    }
}

/// Draws the remote-use switch: a phone, struck through while off.
fn draw_phone(button: &mut ToggleButton) {
    let (x, y, w, h) = (button.x(), button.y(), button.w(), button.h());
    let color = if button.value() {
        Color::Black
    } else {
        SECONDARY
    };
    draw::set_draw_color(color);
    draw::set_line_style(draw::LineStyle::Solid, 2);
    let (px, py) = (x + w / 2 - 6, y + h / 2 - 10);
    draw::draw_rect(px, py, 12, 20);
    draw::draw_line(px + 4, py + 16, px + 8, py + 16);
    if !button.value() {
        draw::draw_line(x + 6, y + h - 6, x + w - 6, y + 6);
    }
    draw::set_line_style(draw::LineStyle::Solid, 0);
}

/// Draws the PIN codes button: two keys, red while a code needs a reset.
fn draw_keys(button: &mut Button) {
    let (x, y) = (button.x(), button.y());
    draw::set_draw_color(button.label_color());
    draw::set_line_style(draw::LineStyle::Solid, 2);
    for (dx, dy) in [(5, 7), (13, 13)] {
        draw::draw_circle(f64::from(x + dx + 4), f64::from(y + dy + 4), 4.0);
        draw::draw_line(x + dx + 8, y + dy + 4, x + dx + 15, y + dy + 4);
        draw::draw_line(x + dx + 13, y + dy + 4, x + dx + 13, y + dy + 7);
    }
    draw::set_line_style(draw::LineStyle::Solid, 0);
}

/// The activation form's fields.
#[derive(Clone)]
struct ActivationFields {
    section: Group,
    inputs: [SecretInput; 5],
    button: Button,
}

/// The PIN codes window.
#[derive(Clone)]
struct PinCodes {
    window: Window,
    column: Flex,
    recovery: [Frame; 2],
    tasks: Group,
    task_buttons: Vec<(PinTask, RadioButton)>,
    form: Group,
    labels: [Frame; 3],
    inputs: [SecretInput; 3],
    action: Button,
    error: Frame,
    attempts: Group,
    attempts_text: Pack,
    task: Rc<RefCell<PinTask>>,
}

/// Every widget the driver updates.
#[derive(Clone)]
struct Widgets {
    window: Window,
    column: Flex,
    remote_switch: ToggleButton,
    pin_codes_button: Button,
    identity: Frame,
    prompt: Group,
    pairing_input: Input,
    pairing_refused: Rc<RefCell<bool>>,
    can: Group,
    can_input: Input,
    can_refused: Rc<RefCell<bool>>,
    activation: ActivationFields,
    drop_area: Group,
    invitation: Group,
    pile: Group,
    pile_rows: Pack,
    method: Group,
    separately: RadioRoundButton,
    package: RadioRoundButton,
    pin2: Group,
    pin2_input: SecretInput,
    action: Group,
    sign: Button,
    result: Frame,
    error: Frame,
    pin_codes: PinCodes,
}

/// What the driver remembers between snapshots.
#[derive(Default)]
struct Memory {
    last: UiState,
    shown_pile: Vec<PathBuf>,
    content: Option<WindowContent>,
    pairing_running: bool,
    opened_for_card: bool,
}

/// Presentation driver using the Fast Light Toolkit (FLTK).
pub struct FltkDriver {
    app: app::App,
    state_rx: Receiver<UiState>,
    widgets: Option<Widgets>,
    controller: Option<Arc<RefineIdController>>,
    memory: Rc<RefCell<Memory>>,
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
            controller: None,
            memory: Rc::new(RefCell::new(Memory::default())),
        };
        (driver, on_state_change)
    }

    /// Builds the window and attaches callbacks dispatching to `controller`.
    fn init_ui(&mut self, controller: &Arc<RefineIdController>) {
        let mut window = Window::default()
            .with_size(WINDOW_WIDTH, WINDOW_HEIGHT)
            .with_label("RefineID");
        let mut column = Flex::default_fill().column();
        column.set_margin(MARGIN);
        column.set_pad(GAP);

        // The top row: the one control at its right.
        let top = section(TOOL_SIZE);
        let mut remote_switch =
            ToggleButton::new(CONTENT_WIDTH - TOOL_SIZE, 0, TOOL_SIZE, TOOL_SIZE, None);
        remote_switch.set_frame(FrameType::FlatBox);
        remote_switch.set_tooltip(window::REMOTE_ACCESS);
        remote_switch.clear_visible_focus();
        remote_switch.draw(draw_phone);
        let mut pin_codes_button =
            Button::new(CONTENT_WIDTH - TOOL_SIZE, 0, TOOL_SIZE, TOOL_SIZE, None);
        pin_codes_button.set_frame(FrameType::FlatBox);
        pin_codes_button.set_tooltip(window::PIN_CODES);
        pin_codes_button.clear_visible_focus();
        pin_codes_button.draw(draw_keys);
        pin_codes_button.hide();
        top.end();
        column.fixed(&top, TOOL_SIZE);

        let mut identity = Frame::new(0, 0, CONTENT_WIDTH, LINE, None);
        identity.set_align(Align::Left | Align::Inside | Align::Wrap);
        identity.set_label_size(16);
        column.fixed(&identity, LINE);

        // The pairing prompt.
        let prompt = section(LINE * 2 + GAP + CODE_BOX_SIZE);
        line_frame(0, 0, CONTENT_WIDTH, LINE * 2, window::PAIRING_PROMPT);
        let pairing_refused = Rc::new(RefCell::new(false));
        let pairing_input = code_input(
            0,
            LINE * 2 + GAP,
            PAIRING_CODE_LENGTH,
            PAIRING_CODE_GROUP_SIZE,
            &pairing_refused,
        );
        prompt.end();
        column.fixed(&prompt, prompt.h());

        // The card access number.
        let can = section(CODE_BOX_SIZE);
        let mut caption = line_frame(0, 0, 40, CODE_BOX_SIZE, window::CAN_CAPTION);
        caption.set_label_color(SECONDARY);
        let can_refused = Rc::new(RefCell::new(false));
        let can_input = code_input(50, 0, CAN_DIGITS, CAN_DIGITS, &can_refused);
        can.end();
        column.fixed(&can, can.h());

        // The activation form.
        let activation_height = LINE + 5 * (FIELD + GAP) + FIELD;
        let activation_section = section(activation_height);
        let mut heading = line_frame(0, 0, CONTENT_WIDTH, LINE, window::CARD_ACTIVATION);
        heading.set_label_font(Font::HelveticaBold);
        let names = [
            window::ACTIVATION_PIN,
            window::NEW_PIN_1,
            window::NEW_PIN_1_AGAIN,
            window::NEW_PIN_2,
            window::NEW_PIN_2_AGAIN,
        ];
        let rows = names.map(|name| name.to_owned());
        let mut y = LINE + GAP;
        let inputs = rows.map(|name| {
            let (_, input) = pin_row(y, &name);
            y += FIELD + GAP;
            input
        });
        let activate = primary_button(CONTENT_WIDTH - BUTTON_WIDTH, y, window::ACTIVATE_CARD);
        activation_section.end();
        column.fixed(&activation_section, activation_height);
        let activation = ActivationFields {
            section: activation_section,
            inputs,
            button: activate,
        };

        // The drop area: the invitation, or the pile and its footer.
        let mut drop_area = section(PILE_HEIGHT + FIELD);
        drop_area.set_frame(FrameType::BorderBox);
        let invitation = Group::new(0, 0, CONTENT_WIDTH, DROP_HEIGHT, None);
        let mut invitation_text = Frame::new(0, 16, CONTENT_WIDTH, LINE, None);
        invitation_text.set_label(window::DROP_INVITATION);
        invitation_text.set_label_color(SECONDARY);
        let mut choose = Button::new(
            (CONTENT_WIDTH - BUTTON_WIDTH) / 2,
            16 + LINE + 4,
            BUTTON_WIDTH,
            LINE,
            None,
        );
        choose.set_label(window::CHOOSE);
        choose.set_frame(FrameType::FlatBox);
        choose.set_label_color(ACCENT);
        invitation.end();
        let pile = Group::new(0, 0, CONTENT_WIDTH, PILE_HEIGHT + FIELD, None);
        let mut scroll = Scroll::new(2, 2, CONTENT_WIDTH - 4, PILE_HEIGHT - 4, None);
        scroll.set_type(ScrollType::Vertical);
        let mut pile_rows = Pack::new(2, 2, CONTENT_WIDTH - 24, PILE_HEIGHT - 4, None);
        pile_rows.set_type(PackType::Vertical);
        pile_rows.end();
        scroll.end();
        let mut add = Button::new(CONTENT_WIDTH - 180, PILE_HEIGHT, 80, LINE, None);
        add.set_label(window::ADD);
        add.set_frame(FrameType::FlatBox);
        add.set_label_color(ACCENT);
        let mut clear = Button::new(CONTENT_WIDTH - 90, PILE_HEIGHT, 80, LINE, None);
        clear.set_label(window::CLEAR);
        clear.set_frame(FrameType::FlatBox);
        clear.set_label_color(ACCENT);
        pile.end();
        drop_area.end();
        column.fixed(&drop_area, DROP_HEIGHT);

        // The signing controls.
        let method = section(FIELD);
        line_frame(0, 0, LABEL_WIDTH, FIELD, window::SIGNING_METHOD);
        let mut separately = RadioRoundButton::new(LABEL_WIDTH + GAP, 0, 160, FIELD, None);
        separately.set_label(window::SEPARATELY);
        let mut package = RadioRoundButton::new(LABEL_WIDTH + GAP + 170, 0, 160, FIELD, None);
        package.set_label(window::AS_A_PACKAGE);
        method.end();
        column.fixed(&method, FIELD);
        let pin2 = section(FIELD);
        let (_, mut pin2_input) = pin_row(0, window::PIN_2);
        pin2.end();
        column.fixed(&pin2, FIELD);
        let action = section(FIELD);
        let mut sign = primary_button(CONTENT_WIDTH - BUTTON_WIDTH, 0, window::SIGN);
        action.end();
        column.fixed(&action, FIELD);

        let mut result = Frame::new(0, 0, CONTENT_WIDTH, LINE * 2, None);
        result.set_align(Align::Left | Align::Inside | Align::Wrap | Align::Top);
        column.fixed(&result, LINE * 2);
        let mut error = Frame::new(0, 0, CONTENT_WIDTH, LINE * 2, None);
        error.set_align(Align::Left | Align::Inside | Align::Wrap | Align::Top);
        error.set_label_color(ERROR);
        column.fixed(&error, LINE * 2);
        // The rest of the window stays empty below the content.
        Frame::default();
        column.end();
        window.end();
        window.make_resizable(true);

        let pin_codes = build_pin_codes();

        // Callbacks.
        {
            let c = Arc::clone(controller);
            remote_switch.set_callback(move |switch| {
                c.handle_intent(UserIntent::SetRemoteUse(switch.value()));
            });
        }
        {
            let mut pin_window = pin_codes.window.clone();
            pin_codes_button.set_callback(move |_| pin_window.show());
        }
        {
            let c = Arc::clone(controller);
            let refused = Rc::clone(&pairing_refused);
            let mut input = pairing_input.clone();
            input.set_callback(move |input| {
                let kept = pairing_code(&input.value());
                if kept != input.value() {
                    input.set_value(&kept);
                }
                *refused.borrow_mut() = false;
                input.redraw();
                if kept.len() == PAIRING_CODE_LENGTH {
                    c.handle_intent(UserIntent::StartPairing { code: kept });
                }
            });
        }
        {
            let c = Arc::clone(controller);
            let refused = Rc::clone(&can_refused);
            let mut input = can_input.clone();
            input.set_callback(move |input| {
                let kept = access_number(&input.value());
                if kept != input.value() {
                    input.set_value(&kept);
                }
                *refused.borrow_mut() = false;
                input.redraw();
                if kept.len() == CAN_DIGITS
                    && let Ok(number) = Can::new(&kept)
                {
                    input.set_value("");
                    c.handle_intent(UserIntent::EnterCan(number));
                }
            });
        }
        {
            let fields = activation.inputs.clone();
            let mut button = activation.button.clone();
            set_active(&mut button, false);
            for mut input in activation.inputs.clone() {
                let fields = fields.clone();
                let mut button = button.clone();
                input.set_callback(move |input| {
                    keep_pin_digits(input);
                    let text = fields.each_ref().map(SecretInput::value);
                    set_active(
                        &mut button,
                        activation_complete(&text[0], [&text[1], &text[2]], [&text[3], &text[4]]),
                    );
                });
            }
            let c = Arc::clone(controller);
            button.set_callback(move |_| {
                if c.state().busy {
                    return;
                }
                let mut fields = fields.clone();
                let text = fields.each_ref().map(SecretInput::value);
                for field in &mut fields {
                    field.set_value("");
                }
                if !activation_complete(&text[0], [&text[1], &text[2]], [&text[3], &text[4]]) {
                    return;
                }
                if let (Some(activation_code), Some(new_pin1), Some(new_pin2)) = (
                    to_pin_bytes(&text[0]),
                    to_pin_bytes(&text[1]),
                    to_pin_bytes(&text[3]),
                ) {
                    c.handle_intent(UserIntent::ActivateCard {
                        activation_code,
                        new_pin1,
                        new_pin2,
                    });
                }
            });
        }
        for button in [&mut choose, &mut add] {
            let c = Arc::clone(controller);
            button.set_callback(move |_| {
                let mut chooser = NativeFileChooser::new(FileDialogType::BrowseMultiFile);
                chooser.show();
                let paths = chooser.filenames();
                if !paths.is_empty() {
                    c.handle_intent(UserIntent::AddDocuments(paths));
                }
            });
        }
        {
            let c = Arc::clone(controller);
            clear.set_callback(move |_| c.handle_intent(UserIntent::ClearDocuments));
        }
        {
            let c = Arc::clone(controller);
            drop_area.handle(move |_, event| match event {
                Event::DndEnter | Event::DndDrag | Event::DndLeave | Event::DndRelease => true,
                Event::Paste => {
                    let paths = dropped_paths(&app::event_text());
                    if !paths.is_empty() {
                        c.handle_intent(UserIntent::AddDocuments(paths));
                    }
                    true
                }
                _ => false,
            });
        }
        for (button, format) in [
            (&mut separately, SignFormat::Pades),
            (&mut package, SignFormat::AsicE),
        ] {
            let c = Arc::clone(controller);
            button.set_callback(move |_| c.handle_intent(UserIntent::SetSignFormat(format)));
        }
        {
            let memory = Rc::clone(&self.memory);
            let mut button = sign.clone();
            pin2_input.set_callback(move |input| {
                keep_pin_digits(input);
                set_active(
                    &mut button,
                    window::can_sign(&memory.borrow().last, &input.value()),
                );
            });
        }
        {
            let memory = Rc::clone(&self.memory);
            let mut pin = pin2_input.clone();
            let c = Arc::clone(controller);
            sign.set_callback(move |_| {
                let typed = pin.value();
                pin.set_value("");
                let state = memory.borrow().last.clone();
                if !window::can_sign(&state, &typed) {
                    return;
                }
                if state.phone_signs() {
                    // PIN 2 for the phone's card is typed on the phone.
                    c.handle_intent(UserIntent::SignDocuments { pin2: None });
                } else if let Some(pin2) = to_pin_bytes(&typed) {
                    c.handle_intent(UserIntent::SignDocuments { pin2: Some(pin2) });
                }
            });
        }
        wire_pin_codes(&pin_codes, controller, &self.memory);

        self.widgets = Some(Widgets {
            window,
            column,
            remote_switch,
            pin_codes_button,
            identity,
            prompt,
            pairing_input,
            pairing_refused,
            can,
            can_input,
            can_refused,
            activation,
            drop_area,
            invitation,
            pile,
            pile_rows,
            method,
            separately,
            package,
            pin2,
            pin2_input,
            action,
            sign,
            result,
            error,
            pin_codes,
        });
    }

    /// Lists the pile, each document with its removal.
    fn rebuild_pile(widgets: &mut Widgets, controller: &Arc<RefineIdController>, pile: &[PathBuf]) {
        widgets.pile_rows.clear();
        widgets.pile_rows.begin();
        for document in pile {
            let file_name = document.file_name().map_or_else(
                || document.display().to_string(),
                |name| name.to_string_lossy().into_owned(),
            );
            let row = Group::new(0, 0, CONTENT_WIDTH - 24, PILE_ROW, None);
            let mut name = Frame::new(4, 0, CONTENT_WIDTH - 24 - PILE_ROW - 8, PILE_ROW, None);
            name.set_label(&file_name);
            name.set_align(Align::Left | Align::Inside | Align::Clip);
            name.set_tooltip(&document.display().to_string());
            let mut remove =
                Button::new(CONTENT_WIDTH - 24 - PILE_ROW, 0, PILE_ROW, PILE_ROW, None);
            remove.set_label("@1+");
            remove.set_frame(FrameType::FlatBox);
            remove.set_label_color(SECONDARY);
            remove.set_tooltip(&window::remove_document(&file_name));
            let c = Arc::clone(controller);
            let path = document.clone();
            remove.set_callback(move |_| c.handle_intent(UserIntent::RemoveDocument(path.clone())));
            row.end();
        }
        widgets.pile_rows.end();
        Group::set_current(None::<&Group>);
        widgets.pile_rows.redraw();
    }
}

fn build_pin_codes() -> PinCodes {
    let window = Window::default()
        .with_size(WINDOW_WIDTH, 360)
        .with_label(window::PIN_CODES);
    let mut column = Flex::default_fill().column();
    column.set_margin(MARGIN);
    column.set_pad(GAP);
    let recovery = [0, 1].map(|_| {
        let frame = Frame::new(0, 0, CONTENT_WIDTH, LINE, None);
        column.fixed(&frame, LINE);
        frame
    });
    for mut frame in recovery.clone() {
        frame.set_align(Align::Left | Align::Inside | Align::Wrap);
    }
    let tasks = section(FIELD);
    let task_width = CONTENT_WIDTH / 4;
    let mut x = 0;
    let task_buttons: Vec<(PinTask, RadioButton)> = PinTask::ALL
        .iter()
        .map(|task| {
            let mut button = RadioButton::new(x, 0, task_width, FIELD, None);
            button.set_label(task.name());
            x += task_width;
            (*task, button)
        })
        .collect();
    tasks.end();
    column.fixed(&tasks, FIELD);
    let form_height = 3 * (FIELD + GAP) + FIELD;
    let form = section(form_height);
    let fields = PinTask::ChangePin1.fields();
    let mut y = 0;
    let rows = fields.map(|name| {
        let row = pin_row(y, name);
        y += FIELD + GAP;
        row
    });
    let labels = rows.clone().map(|(label, _)| label);
    let inputs = rows.map(|(_, input)| input);
    let action = primary_button(
        CONTENT_WIDTH - 2 * BUTTON_WIDTH,
        y,
        PinTask::ChangePin1.action(),
    );
    form.end();
    column.fixed(&form, form_height);
    let mut error = Frame::new(0, 0, CONTENT_WIDTH, LINE * 2, None);
    error.set_align(Align::Left | Align::Inside | Align::Wrap);
    error.set_label_color(ERROR);
    column.fixed(&error, LINE * 2);
    Frame::default();
    let attempts = section(LINE);
    let mut attempts_label = line_frame(0, 0, 110, LINE, window::ATTEMPTS_LEFT);
    attempts_label.set_label_color(SECONDARY);
    let mut attempts_text = Pack::new(120, 0, CONTENT_WIDTH - 120, LINE, None);
    attempts_text.set_type(PackType::Horizontal);
    attempts_text.set_spacing(GAP);
    attempts_text.end();
    attempts.end();
    column.fixed(&attempts, LINE);
    column.end();
    window.end();
    PinCodes {
        window,
        column,
        recovery,
        tasks,
        task_buttons,
        form,
        labels,
        inputs,
        action,
        error,
        attempts,
        attempts_text,
        task: Rc::new(RefCell::new(PinTask::ChangePin1)),
    }
}

/// Shows `task`'s fields and action in the PIN codes window.
fn show_pin_task(pin: &mut PinCodes, task: PinTask, state: &UiState) {
    *pin.task.borrow_mut() = task;
    for (button_task, button) in &mut pin.task_buttons {
        button.set_value(*button_task == task);
    }
    for ((label, input), name) in pin
        .labels
        .iter_mut()
        .zip(&mut pin.inputs)
        .zip(task.fields())
    {
        label.set_label(name);
        input.set_value("");
    }
    pin.action.set_label(task.action());
    update_pin_action(pin, state);
}

/// Activates the PIN codes action while its entries are filled in and the
/// card lets it run.
fn update_pin_action(pin: &mut PinCodes, state: &UiState) {
    let task = *pin.task.borrow();
    let text = pin.inputs.each_ref().map(SecretInput::value);
    let ready = task.complete(text.each_ref().map(String::as_str)) && task.available(state);
    set_active(&mut pin.action, ready);
}

fn wire_pin_codes(
    pin: &PinCodes,
    controller: &Arc<RefineIdController>,
    memory: &Rc<RefCell<Memory>>,
) {
    for (task, button) in &pin.task_buttons {
        let mut shown = pin.clone();
        let memory = Rc::clone(memory);
        let task = *task;
        let mut button = button.clone();
        button.set_callback(move |_| show_pin_task(&mut shown, task, &memory.borrow().last));
    }
    for input in &pin.inputs {
        let mut shown = pin.clone();
        let memory = Rc::clone(memory);
        let mut input = input.clone();
        input.set_callback(move |input| {
            keep_pin_digits(input);
            update_pin_action(&mut shown, &memory.borrow().last);
        });
    }
    let mut shown = pin.clone();
    let c = Arc::clone(controller);
    let mut action = pin.action.clone();
    action.set_callback(move |_| {
        let task = *shown.task.borrow();
        let text = shown.inputs.each_ref().map(SecretInput::value);
        for input in &mut shown.inputs {
            input.set_value("");
        }
        if !task.complete(text.each_ref().map(String::as_str)) {
            return;
        }
        let (Some(presented), Some(new_pin)) = (to_pin_bytes(&text[0]), to_pin_bytes(&text[1]))
        else {
            return;
        };
        let slot = task.manage_slot();
        c.handle_intent(if task.uses_puk() {
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
    });
}

impl UiDriver for FltkDriver {
    fn init(&mut self) -> Result<(), GuiCoreError> {
        Ok(())
    }

    fn render(&mut self, state: &UiState) {
        let (Some(widgets), Some(controller)) = (self.widgets.as_mut(), self.controller.as_ref())
        else {
            return;
        };
        let mut memory = self.memory.borrow_mut();
        memory.last = state.clone();
        widgets.window.set_label(&state.window_title);

        let line = IdentityLine::derive(state);
        let content = WindowContent::derive(state);
        let entered = memory.content.replace(content) != Some(content);

        // The top row's one control.
        let opens_pin_codes = window::toolbar_opens_pin_codes(state);
        set_shown(&mut widgets.pin_codes_button, opens_pin_codes);
        set_shown(&mut widgets.remote_switch, !opens_pin_codes);
        widgets.remote_switch.set_value(state.remote_use);
        widgets.remote_switch.set_tooltip(&format!(
            "{}: {}",
            window::REMOTE_ACCESS,
            if state.remote_use {
                window::REMOTE_ON
            } else {
                window::REMOTE_OFF
            }
        ));
        let recovery = Recovery::derive(state);
        widgets
            .pin_codes_button
            .set_label_color(if recovery.is_some() { ERROR } else { SECONDARY });
        widgets.pin_codes_button.set_tooltip(if recovery.is_some() {
            window::PIN_NEEDS_RESET
        } else {
            window::PIN_CODES
        });

        // The identity line.
        let replaced = matches!(
            content,
            WindowContent::CardAccessNumber(_) | WindowContent::Activation
        );
        let text = line.text();
        widgets.identity.set_label(&text);
        widgets.identity.set_label_color(if line.is_warning() {
            WARNING
        } else if line.is_holder() {
            Color::Black
        } else {
            SECONDARY
        });
        set_shown(&mut widgets.identity, !replaced && !text.is_empty());

        // The pairing prompt.
        set_shown(&mut widgets.prompt, content == WindowContent::PairingPrompt);
        let running = state.pairing.is_some();
        set_active(&mut widgets.pairing_input, !running);
        if memory.pairing_running && !running {
            widgets.pairing_input.set_value("");
            *widgets.pairing_refused.borrow_mut() = !state.status_message.is_empty();
        }
        memory.pairing_running = running;
        if entered && content == WindowContent::PairingPrompt {
            widgets.pairing_input.set_value("");
            let _ = widgets.pairing_input.take_focus();
        }

        // The card access number.
        let can_request = match content {
            WindowContent::CardAccessNumber(request) => Some(request),
            _ => None,
        };
        set_shown(&mut widgets.can, can_request.is_some());
        if entered && can_request.is_some() {
            widgets.can_input.set_value("");
            *widgets.can_refused.borrow_mut() = can_request == Some(CanRequest::Refused);
            let _ = widgets.can_input.take_focus();
        }

        // The activation form.
        set_shown(
            &mut widgets.activation.section,
            content == WindowContent::Activation,
        );
        if entered && content == WindowContent::Activation {
            let _ = widgets.activation.inputs[0].take_focus();
        }

        // The documents.
        let documents = content == WindowContent::Documents;
        let pile = !state.pdf_documents.is_empty();
        set_shown(&mut widgets.drop_area, documents);
        set_shown(&mut widgets.invitation, !pile);
        set_shown(&mut widgets.pile, pile);
        widgets.column.fixed(
            &widgets.drop_area,
            if pile {
                PILE_HEIGHT + FIELD
            } else {
                DROP_HEIGHT
            },
        );
        if memory.shown_pile != state.pdf_documents {
            memory.shown_pile.clone_from(&state.pdf_documents);
            Self::rebuild_pile(widgets, controller, &state.pdf_documents);
        }
        let signing = documents && pile;
        set_shown(&mut widgets.method, signing);
        let every_one_a_pdf = SignFormat::shared(&state.pdf_documents) == SignFormat::Pades;
        set_active(&mut widgets.separately, every_one_a_pdf);
        set_active(&mut widgets.package, every_one_a_pdf);
        widgets
            .separately
            .set_value(state.sign_format == SignFormat::Pades);
        widgets
            .package
            .set_value(state.sign_format == SignFormat::AsicE);
        set_shown(&mut widgets.pin2, signing && window::asks_pin2_here(state));
        set_shown(&mut widgets.action, signing);
        set_active(
            &mut widgets.sign,
            window::can_sign(state, &widgets.pin2_input.value()),
        );

        // The outcome of the last action.
        let result = state.sign_result.clone().unwrap_or_default();
        widgets.result.set_label(&result);
        set_shown(&mut widgets.result, documents && !result.is_empty());
        widgets.error.set_label(&state.status_message);
        set_shown(&mut widgets.error, !state.status_message.is_empty());

        // The PIN codes window.
        let pin = &mut widgets.pin_codes;
        if opens_pin_codes {
            let sentences = recovery.map(Recovery::sentences);
            for (index, frame) in pin.recovery.iter_mut().enumerate() {
                let text = sentences.map(|pair| pair[index]).unwrap_or_default();
                frame.set_label(text);
                frame.set_label_color(
                    if matches!(
                        recovery,
                        Some(Recovery::UseOtherSoftware | Recovery::Unrecoverable)
                    ) {
                        ERROR
                    } else {
                        Color::Black
                    },
                );
                set_shown(frame, !text.is_empty());
            }
            let tasks = Recovery::tasks(recovery);
            for (task, button) in &mut pin.task_buttons {
                set_shown(button, tasks.contains(task));
            }
            set_shown(&mut pin.tasks, !tasks.is_empty());
            set_shown(&mut pin.form, !tasks.is_empty());
            if !tasks.contains(&pin.task.borrow()) {
                show_pin_task(pin, Recovery::initial_task(recovery), state);
            }
            update_pin_action(pin, state);
            let entries = window::attempts_below_full(state);
            pin.attempts_text.clear();
            pin.attempts_text.begin();
            for entry in &entries {
                if entry.below_floor {
                    let mut mark = Frame::new(0, 0, LINE / 2, LINE, None);
                    mark.set_label(BELOW_FLOOR_SYMBOL);
                    mark.set_label_color(ERROR);
                }
                let width = i32::try_from(entry.text.len()).unwrap_or(0) * 8;
                let mut text = Frame::new(0, 0, width, LINE, None);
                text.set_label(&entry.text);
                text.set_label_color(if entry.below_floor {
                    ERROR
                } else {
                    Color::Black
                });
            }
            pin.attempts_text.end();
            Group::set_current(None::<&Group>);
            set_shown(&mut pin.attempts, !entries.is_empty());
            pin.error.set_label(&state.status_message);
            pin.column.layout();
            pin.window.redraw();
            if recovery.is_some() && !memory.opened_for_card {
                memory.opened_for_card = true;
                pin.window.show();
            }
        } else {
            memory.opened_for_card = false;
            pin.window.hide();
        }

        widgets.column.layout();
        widgets.window.redraw();
    }

    fn run(mut self, controller: Arc<RefineIdController>) -> Result<(), GuiCoreError> {
        self.init_ui(&controller);
        self.controller = Some(Arc::clone(&controller));
        self.render(&controller.state());

        if let Some(ref mut widgets) = self.widgets {
            widgets.window.show();
        }

        #[cfg(debug_assertions)]
        let follower = refineid_dev_errors::follow(app::awake);
        #[cfg(debug_assertions)]
        let mut errors = crate::errors::ErrorsWindow::default();

        while self.app.wait() {
            while let Some(state) = self.state_rx.recv() {
                self.render(&state);
            }
            #[cfg(debug_assertions)]
            while let Some(entry) = follower.next() {
                errors.add(entry);
            }
            // Neither the PIN codes window nor the Errors window keeps the
            // application open.
            if self
                .widgets
                .as_ref()
                .is_some_and(|widgets| !widgets.window.shown())
            {
                break;
            }
        }

        controller.stop();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_typed_code_keeps_its_code_characters_up_to_the_length() {
        assert_eq!(pairing_code("7k x4-m9"), "7KX4M9");
        assert_eq!(pairing_code("7K X4 M9 extra"), "7KX4M9");
        assert_eq!(pairing_code("7k"), "7K");
        assert_eq!(access_number("12a34b567"), "123456");
    }

    #[test]
    fn the_boxes_sit_in_clusters() {
        assert_eq!(code_box_offset(0, 2), 0);
        assert_eq!(code_box_offset(1, 2), CODE_BOX_SIZE + CODE_BOX_SPACING);
        assert_eq!(
            code_box_offset(2, 2),
            2 * CODE_BOX_SIZE + CODE_BOX_SPACING + CODE_GROUP_GAP
        );
        assert_eq!(
            code_boxes_width(PAIRING_CODE_LENGTH, PAIRING_CODE_GROUP_SIZE),
            code_box_offset(PAIRING_CODE_LENGTH - 1, PAIRING_CODE_GROUP_SIZE) + CODE_BOX_SIZE
        );
        assert_eq!(
            code_boxes_width(CAN_DIGITS, CAN_DIGITS),
            CAN_DIGITS as i32 * CODE_BOX_SIZE + (CAN_DIGITS as i32 - 1) * CODE_BOX_SPACING
        );
    }

    #[test]
    fn a_drop_names_its_files() {
        assert_eq!(
            dropped_paths("file:///documents/my%20report.pdf\r\n/documents/notes.txt\n"),
            vec![
                PathBuf::from("/documents/my report.pdf"),
                PathBuf::from("/documents/notes.txt")
            ]
        );
        assert_eq!(percent_decoded("100%"), "100%");
    }
}
