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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! One reported failure, from the call to the entries written.

use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::cause::Cause;

/// The identifier every `RefineID` program writes to the system log as.
pub const IDENTIFIER: &str = "refineid";

/// How long a failure that repeats itself is only counted.
///
/// The first report is written at once, and a repeat is written with its
/// count once this long has passed since the last write, or as soon as
/// another failure comes.
pub const REPEAT_WINDOW: Duration = Duration::from_secs(60);

/// The longest entry message kept, in characters.
const MAXIMUM_MESSAGE_CHARACTERS: usize = 240;

/// The directory a `cargo test` binary runs from, under the target
/// directory.
const TEST_BINARY_DIRECTORY: &str = "deps";

/// The part of `RefineID` that reports a failure; an entry begins with its
/// name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    /// The `refineid` command line.
    Cli,
    /// The desktop application.
    Gui,
    /// The PKCS#11 module and its phone slot.
    Pkcs11,
    /// The RAPP requester: pairing, sessions and their transport.
    Rapp,
    /// The PC/SC reader adapter.
    Reader,
}

impl Component {
    /// The name an entry begins with.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cli => "Cli",
            Self::Gui => "Gui",
            Self::Pkcs11 => "Pkcs11",
            Self::Rapp => "Rapp",
            Self::Reader => "Reader",
        }
    }
}

/// One entry to write: what failed, and how many times since its last
/// entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// `component: event: cause`.
    pub(crate) message: String,
    /// How many times the failure came since its last entry.
    pub(crate) occurrences: u32,
}

/// The suffix that carries a count above one: ` (xN)`.
pub(crate) const COUNT_OPEN: &str = " (x";
/// The end of the count suffix.
pub(crate) const COUNT_CLOSE: &str = ")";

impl Entry {
    /// The entry as one log line: the message, and ` (xN)` when it stands
    /// for more than one failure.
    pub(crate) fn line(&self) -> String {
        if self.occurrences > 1 {
            format!(
                "{}{COUNT_OPEN}{}{COUNT_CLOSE}",
                self.message, self.occurrences
            )
        } else {
            self.message.clone()
        }
    }
}

/// The failure this process reported last, and its repeats not yet
/// written.
#[derive(Debug)]
struct Run {
    message: String,
    written_at: Instant,
    unwritten: u32,
}

/// The last failure of this process, shared by its threads.
static LAST: Mutex<Option<Run>> = Mutex::new(None);

/// Records one failure: `component: event: cause`.
///
/// Never fails and never panics its caller: a report that could break
/// the path it watches would be taken out of it. A `cargo test` binary
/// records nothing.
pub fn record(component: Component, event: &'static str, cause: &Cause) {
    if is_test_binary() {
        return;
    }
    let message = message(component, event, cause);
    let mut last = LAST.lock().unwrap_or_else(PoisonError::into_inner);
    for entry in observe(&mut last, message, Instant::now()) {
        write(&entry);
    }
}

/// `component: event: cause` on one line, at most
/// [`MAXIMUM_MESSAGE_CHARACTERS`] long.
fn message(component: Component, event: &str, cause: &Cause) -> String {
    format!("{}: {event}: {}", component.name(), cause.as_str())
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAXIMUM_MESSAGE_CHARACTERS)
        .collect()
}

/// The entries one report writes at `now`, given the run before it: the
/// earlier failure's unwritten repeats when another failure comes, then
/// the new failure; or a repeat with its count once [`REPEAT_WINDOW`]
/// passed since the run was last written; or nothing.
fn observe(last: &mut Option<Run>, message: String, now: Instant) -> Vec<Entry> {
    if let Some(run) = last.as_mut()
        && run.message == message
    {
        run.unwritten = run.unwritten.saturating_add(1);
        if now.saturating_duration_since(run.written_at) < REPEAT_WINDOW {
            return Vec::new();
        }
        let entry = Entry {
            message,
            occurrences: run.unwritten,
        };
        run.unwritten = 0;
        run.written_at = now;
        return vec![entry];
    }
    let mut entries = Vec::new();
    if let Some(run) = last.take()
        && run.unwritten > 0
    {
        entries.push(Entry {
            message: run.message,
            occurrences: run.unwritten,
        });
    }
    entries.push(Entry {
        message: message.clone(),
        occurrences: 1,
    });
    *last = Some(Run {
        message,
        written_at: now,
        unwritten: 0,
    });
    entries
}

/// Whether this process is a `cargo test` binary, which runs from the
/// target directory's `deps`.
fn is_test_binary() -> bool {
    static TEST_BINARY: OnceLock<bool> = OnceLock::new();
    *TEST_BINARY.get_or_init(|| {
        std::env::current_exe().is_ok_and(|path| {
            path.parent()
                .and_then(std::path::Path::file_name)
                .is_some_and(|directory| directory == TEST_BINARY_DIRECTORY)
        })
    })
}

/// Writes `entry` to the system log and to this process's Errors window.
fn write(entry: &Entry) {
    #[cfg(unix)]
    crate::syslog::write(&entry.line());
    crate::follow::deliver(entry);
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{Component, Entry, REPEAT_WINDOW, observe};
    use crate::cause::Cause;

    const FIRST: &str = "Rapp: phone session ended: TransportLoss";
    const SECOND: &str = "Reader: PC/SC call failed: NoService";
    const MOMENT: Duration = Duration::from_secs(1);
    const REPEATS: u32 = 2;

    fn entry(message: &str, occurrences: u32) -> Entry {
        Entry {
            message: message.to_owned(),
            occurrences,
        }
    }

    #[test]
    fn a_new_failure_is_written_at_once() {
        let mut last = None;
        let written = observe(&mut last, FIRST.to_owned(), Instant::now());
        assert_eq!(written, vec![entry(FIRST, 1)]);
    }

    #[test]
    fn a_repeat_inside_the_window_is_only_counted() {
        let start = Instant::now();
        let mut last = None;
        observe(&mut last, FIRST.to_owned(), start);
        let written = observe(&mut last, FIRST.to_owned(), start + MOMENT);
        assert!(written.is_empty());
    }

    #[test]
    fn a_repeat_after_the_window_is_written_with_its_count() {
        let start = Instant::now();
        let mut last = None;
        observe(&mut last, FIRST.to_owned(), start);
        observe(&mut last, FIRST.to_owned(), start + MOMENT);
        let written = observe(&mut last, FIRST.to_owned(), start + REPEAT_WINDOW + MOMENT);
        assert_eq!(written, vec![entry(FIRST, REPEATS)]);
        assert_eq!(written[0].line(), format!("{FIRST} (x{REPEATS})"));
    }

    #[test]
    fn another_failure_first_writes_the_counted_repeats() {
        let start = Instant::now();
        let mut last = None;
        observe(&mut last, FIRST.to_owned(), start);
        observe(&mut last, FIRST.to_owned(), start + MOMENT);
        observe(&mut last, FIRST.to_owned(), start + MOMENT);
        let written = observe(&mut last, SECOND.to_owned(), start + MOMENT);
        assert_eq!(written, vec![entry(FIRST, REPEATS), entry(SECOND, 1)]);
    }

    #[test]
    fn a_message_is_one_bounded_line_led_by_its_component() {
        let cause = Cause::text("line\nbreak");
        assert_eq!(
            super::message(Component::Gui, "event", &cause),
            "Gui: event: line break"
        );
        let long = "x".repeat(super::MAXIMUM_MESSAGE_CHARACTERS);
        let leaked: &'static str = Box::leak(long.into_boxed_str());
        let bounded = super::message(Component::Gui, "event", &Cause::text(leaked));
        assert_eq!(bounded.chars().count(), super::MAXIMUM_MESSAGE_CHARACTERS);
    }
}
