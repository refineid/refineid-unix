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

//! The Errors window of a debug build: every failure a `RefineID` program
//! reports, newest first, as the system log receives it.

use std::cell::RefCell;
use std::rc::Rc;

use fltk::app;
use fltk::button::Button;
use fltk::group::Flex;
use fltk::prelude::*;
use fltk::text::{TextBuffer, TextDisplay};
use fltk::window::Window;
use refineid_dev_errors::Followed;

/// The window's width, in pixels.
const WINDOW_WIDTH: i32 = 560;
/// The window's height, in pixels.
const WINDOW_HEIGHT: i32 = 320;
/// The margin around and between the window's parts, in pixels.
const MARGIN: i32 = 8;
/// The height of the button row, in pixels.
const BUTTON_ROW_HEIGHT: i32 = 30;
/// The width of each button, in pixels.
const BUTTON_WIDTH: i32 = 96;

/// One shown entry: the message and how many failures it stands for.
type Shown = (String, u32);

/// The Errors window, made when the first error arrives.
#[derive(Debug, Default)]
pub(crate) struct ErrorsWindow {
    parts: Option<Parts>,
    entries: Rc<RefCell<Vec<Shown>>>,
}

/// The window and the text it shows.
#[derive(Debug)]
struct Parts {
    window: Window,
    text: TextBuffer,
}

impl ErrorsWindow {
    /// Shows `entry` at the top, folded into an equal one shown earlier,
    /// and opens the window if it is not open.
    pub(crate) fn add(&mut self, entry: Followed) {
        fold(&mut self.entries.borrow_mut(), entry);
        let entries = Rc::clone(&self.entries);
        let parts = self.parts.get_or_insert_with(|| build(entries));
        parts.text.set_text(&listing(&self.entries.borrow()));
        if !parts.window.shown() {
            parts.window.show();
        }
    }
}

/// Puts `entry` first in `entries`, adding its count to an equal message.
fn fold(entries: &mut Vec<Shown>, entry: Followed) {
    let earlier = entries
        .iter()
        .position(|(message, _)| *message == entry.message)
        .map_or(0, |index| entries.remove(index).1);
    entries.insert(
        0,
        (entry.message, earlier.saturating_add(entry.occurrences)),
    );
}

/// The entries as the window shows them, one per line, a count above one
/// written as ` (xN)`.
fn listing(entries: &[Shown]) -> String {
    entries
        .iter()
        .map(|(message, count)| {
            if *count > 1 {
                format!("{message} (x{count})\n")
            } else {
                format!("{message}\n")
            }
        })
        .collect()
}

/// Makes the window: the selectable list above, Copy All and Clear below.
fn build(entries: Rc<RefCell<Vec<Shown>>>) -> Parts {
    let mut window = Window::default()
        .with_size(WINDOW_WIDTH, WINDOW_HEIGHT)
        .with_label("Errors");
    let mut column = Flex::default_fill().column();
    column.set_margin(MARGIN);
    column.set_pad(MARGIN);
    let text = TextBuffer::default();
    let mut display = TextDisplay::default();
    display.set_buffer(text.clone());
    let mut row = Flex::default().row();
    Flex::default();
    let mut copy = Button::default().with_label("Copy All");
    let mut clear = Button::default().with_label("Clear");
    row.fixed(&copy, BUTTON_WIDTH);
    row.fixed(&clear, BUTTON_WIDTH);
    row.end();
    column.fixed(&row, BUTTON_ROW_HEIGHT);
    column.end();
    window.end();
    window.make_resizable(true);

    let copied = text.clone();
    copy.set_callback(move |_| app::copy(&copied.text()));
    let mut cleared = text.clone();
    clear.set_callback(move |_| {
        entries.borrow_mut().clear();
        cleared.set_text("");
    });
    Parts { window, text }
}

#[cfg(test)]
mod tests {
    use refineid_dev_errors::Followed;

    use super::{fold, listing};

    const FIRST: &str = "Rapp: phone session ended: TransportLoss";
    const SECOND: &str = "Pkcs11: signature request failed: Ambiguous";
    const REPEATS: u32 = 3;

    fn followed(message: &str, occurrences: u32) -> Followed {
        Followed {
            message: message.to_owned(),
            occurrences,
        }
    }

    #[test]
    fn the_newest_entry_comes_first_and_repeats_fold() {
        let mut entries = Vec::new();
        fold(&mut entries, followed(FIRST, 1));
        fold(&mut entries, followed(SECOND, 1));
        fold(&mut entries, followed(FIRST, REPEATS - 1));
        assert_eq!(
            listing(&entries),
            format!("{FIRST} (x{REPEATS})\n{SECOND}\n")
        );
    }
}
