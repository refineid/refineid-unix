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

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::cause::Cause;

/// The identifier every `RefineID` program writes to the system log as.
pub const IDENTIFIER: &str = "refineid";

/// How long a failure that repeats itself is only counted.
///
/// Each component and event is throttled on its own. The first report is
/// written at once, and its repeats are written with their count once
/// this long has passed since its last write, as soon as the same
/// component and event fail with another cause, or when the program ends.
pub const REPEAT_WINDOW: Duration = Duration::from_secs(60);

/// The longest entry message kept, in characters.
const MAXIMUM_MESSAGE_CHARACTERS: usize = 240;

/// The directory a `cargo test` binary runs from, under the target
/// directory.
const TEST_BINARY_DIRECTORY: &str = "deps";

/// The part of `RefineID` that reports a failure; an entry begins with its
/// name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

/// What a run is throttled by: the reporting component and its event.
type Key = (Component, &'static str);

/// The failure one component and event reported last, and its repeats not
/// yet written.
#[derive(Debug)]
struct Run {
    message: String,
    written_at: Instant,
    unwritten: u32,
}

/// The last failure of each component and event in this process, shared
/// by its threads.
static RUNS: Mutex<BTreeMap<Key, Run>> = Mutex::new(BTreeMap::new());

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
    let mut runs = RUNS.lock().unwrap_or_else(PoisonError::into_inner);
    for entry in observe(&mut runs, (component, event), message, Instant::now()) {
        write(&entry);
    }
}

/// Writes every counted repeat not yet written; a program calls it as it
/// ends ([`flush!`](crate::flush!)). A `cargo test` binary writes nothing.
pub fn flush() {
    if is_test_binary() {
        return;
    }
    let mut runs = RUNS.lock().unwrap_or_else(PoisonError::into_inner);
    for entry in unwritten(&mut runs) {
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

/// The entries one report under `key` writes at `now`, given the runs
/// before it: the key's earlier failure's unwritten repeats when it fails
/// with another cause, then the new failure; or a repeat with its count
/// once [`REPEAT_WINDOW`] passed since the run was last written; or
/// nothing. Then the counted repeats of every other run whose window
/// passed.
fn observe(runs: &mut BTreeMap<Key, Run>, key: Key, message: String, now: Instant) -> Vec<Entry> {
    let mut entries = Vec::new();
    match runs.get_mut(&key) {
        Some(run) if run.message == message => {
            run.unwritten = run.unwritten.saturating_add(1);
            if now.saturating_duration_since(run.written_at) >= REPEAT_WINDOW {
                entries.push(take_unwritten(run, now));
            }
        }
        _ => {
            if let Some(run) = runs.remove(&key)
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
            runs.insert(
                key,
                Run {
                    message,
                    written_at: now,
                    unwritten: 0,
                },
            );
        }
    }
    for (_, run) in runs.iter_mut().filter(|(other, _)| **other != key) {
        if run.unwritten > 0 && now.saturating_duration_since(run.written_at) >= REPEAT_WINDOW {
            entries.push(take_unwritten(run, now));
        }
    }
    entries
}

/// The run's unwritten repeats as one entry, written at `now`.
fn take_unwritten(run: &mut Run, now: Instant) -> Entry {
    let entry = Entry {
        message: run.message.clone(),
        occurrences: run.unwritten,
    };
    run.unwritten = 0;
    run.written_at = now;
    entry
}

/// Every run's unwritten repeats, each as one entry, leaving none.
fn unwritten(runs: &mut BTreeMap<Key, Run>) -> Vec<Entry> {
    runs.values_mut()
        .filter(|run| run.unwritten > 0)
        .map(|run| {
            let entry = Entry {
                message: run.message.clone(),
                occurrences: run.unwritten,
            };
            run.unwritten = 0;
            entry
        })
        .collect()
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
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    use super::{Component, Entry, Key, REPEAT_WINDOW, observe, unwritten};
    use crate::cause::Cause;

    const FIRST: &str = "Rapp: phone session ended: TransportLoss";
    const FIRST_KEY: Key = (Component::Rapp, "phone session ended");
    const FIRST_OTHER_CAUSE: &str = "Rapp: phone session ended: Expired";
    const SECOND: &str = "Reader: PC/SC call failed: NoService";
    const SECOND_KEY: Key = (Component::Reader, "PC/SC call failed");
    const THIRD: &str = "Gui: card presence not watched: service down";
    const THIRD_KEY: Key = (Component::Gui, "card presence not watched");
    const CYCLES: u32 = 5;
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
        let mut runs = BTreeMap::new();
        let written = observe(&mut runs, FIRST_KEY, FIRST.to_owned(), Instant::now());
        assert_eq!(written, vec![entry(FIRST, 1)]);
    }

    #[test]
    fn a_repeat_inside_the_window_is_only_counted() {
        let start = Instant::now();
        let mut runs = BTreeMap::new();
        observe(&mut runs, FIRST_KEY, FIRST.to_owned(), start);
        let written = observe(&mut runs, FIRST_KEY, FIRST.to_owned(), start + MOMENT);
        assert!(written.is_empty());
    }

    #[test]
    fn a_repeat_after_the_window_is_written_with_its_count() {
        let start = Instant::now();
        let mut runs = BTreeMap::new();
        observe(&mut runs, FIRST_KEY, FIRST.to_owned(), start);
        observe(&mut runs, FIRST_KEY, FIRST.to_owned(), start + MOMENT);
        let written = observe(
            &mut runs,
            FIRST_KEY,
            FIRST.to_owned(),
            start + REPEAT_WINDOW + MOMENT,
        );
        assert_eq!(written, vec![entry(FIRST, REPEATS)]);
        assert_eq!(written[0].line(), format!("{FIRST} (x{REPEATS})"));
    }

    #[test]
    fn another_cause_first_writes_the_counted_repeats() {
        let start = Instant::now();
        let mut runs = BTreeMap::new();
        observe(&mut runs, FIRST_KEY, FIRST.to_owned(), start);
        observe(&mut runs, FIRST_KEY, FIRST.to_owned(), start + MOMENT);
        observe(&mut runs, FIRST_KEY, FIRST.to_owned(), start + MOMENT);
        let written = observe(
            &mut runs,
            FIRST_KEY,
            FIRST_OTHER_CAUSE.to_owned(),
            start + MOMENT,
        );
        assert_eq!(
            written,
            vec![entry(FIRST, REPEATS), entry(FIRST_OTHER_CAUSE, 1)]
        );
    }

    /// Two failures that alternate inside the window are each written
    /// once, then counted.
    #[test]
    fn alternating_failures_are_throttled_each_on_its_own() {
        let start = Instant::now();
        let mut runs = BTreeMap::new();
        let mut written = Vec::new();
        for _ in 0..CYCLES {
            written.extend(observe(&mut runs, SECOND_KEY, SECOND.to_owned(), start));
            written.extend(observe(&mut runs, THIRD_KEY, THIRD.to_owned(), start));
        }
        assert_eq!(written, vec![entry(SECOND, 1), entry(THIRD, 1)]);
        let later = start + REPEAT_WINDOW;
        let written = observe(&mut runs, SECOND_KEY, SECOND.to_owned(), later);
        assert_eq!(
            written,
            vec![entry(SECOND, CYCLES), entry(THIRD, CYCLES - 1)]
        );
    }

    /// Ending the program writes each run's counted repeats once.
    #[test]
    fn the_flush_writes_every_unwritten_repeat_once() {
        let start = Instant::now();
        let mut runs = BTreeMap::new();
        observe(&mut runs, FIRST_KEY, FIRST.to_owned(), start);
        observe(&mut runs, FIRST_KEY, FIRST.to_owned(), start + MOMENT);
        observe(&mut runs, FIRST_KEY, FIRST.to_owned(), start + MOMENT);
        observe(&mut runs, SECOND_KEY, SECOND.to_owned(), start + MOMENT);
        assert_eq!(unwritten(&mut runs), vec![entry(FIRST, REPEATS)]);
        assert!(unwritten(&mut runs).is_empty());
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
