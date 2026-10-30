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

//! The entries an Errors window shows: this process's own as they are
//! written, and every other `RefineID` program's as the system log
//! receives them, the PKCS#11 module inside a browser among them.

use std::io::{BufRead as _, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, PoisonError};

use crate::record::{COUNT_CLOSE, COUNT_OPEN, Entry, IDENTIFIER};

/// One entry as an Errors window counts it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Followed {
    /// `component: event: cause`.
    pub message: String,
    /// How many failures the entry stands for.
    pub occurrences: u32,
}

/// Where this process's own entries go, and how the window is woken.
#[derive(Debug)]
struct Listener {
    entries: Sender<Followed>,
    wake: fn(),
}

/// The Errors window this process feeds, if one follows.
static LISTENER: Mutex<Option<Listener>> = Mutex::new(None);

/// The entries for an Errors window, until dropped.
#[derive(Debug)]
pub struct Follower {
    entries: Receiver<Followed>,
    reader: Option<Child>,
}

impl Follower {
    /// The next entry that has arrived, if any.
    #[must_use]
    pub fn next(&self) -> Option<Followed> {
        self.entries.try_recv().ok()
    }
}

impl Drop for Follower {
    fn drop(&mut self) {
        *LISTENER.lock().unwrap_or_else(PoisonError::into_inner) = None;
        if let Some(reader) = &mut self.reader {
            let _ = reader.kill();
            let _ = reader.wait();
        }
    }
}

/// Starts following the entries; `wake` is called after each arrives,
/// from whichever thread it arrives on.
///
/// The system log is read with `journalctl` on Linux and from
/// `/var/log/messages` on FreeBSD. Where neither can be read, this
/// process's own entries still arrive.
#[must_use]
pub fn follow(wake: fn()) -> Follower {
    let (sender, entries) = mpsc::channel();
    *LISTENER.lock().unwrap_or_else(PoisonError::into_inner) = Some(Listener {
        entries: sender.clone(),
        wake,
    });
    let reader = log_reader().and_then(|mut command| {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .ok()?;
        let output = child.stdout.take()?;
        std::thread::spawn(move || {
            let own = std::process::id();
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else {
                    break;
                };
                if let Some((pid, followed)) = parse_log_line(&line)
                    && pid != own
                {
                    if sender.send(followed).is_err() {
                        break;
                    }
                    wake();
                }
            }
        });
        Some(child)
    });
    Follower { entries, reader }
}

/// The command that prints the system log's new lines as they come.
fn log_reader() -> Option<Command> {
    if cfg!(target_os = "linux") {
        let mut command = Command::new("journalctl");
        command.args([
            "--follow",
            "--lines=0",
            "--output=short",
            "--identifier",
            IDENTIFIER,
        ]);
        Some(command)
    } else if cfg!(target_os = "freebsd") {
        let mut command = Command::new("tail");
        command.args(["-F", "-n", "0", "/var/log/messages"]);
        Some(command)
    } else {
        None
    }
}

/// Hands this process's own `entry` to its Errors window, if one follows.
pub(crate) fn deliver(entry: &Entry) {
    let listener = LISTENER.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(Listener { entries, wake }) = listener.as_ref()
        && entries
            .send(Followed {
                message: entry.message.clone(),
                occurrences: entry.occurrences,
            })
            .is_ok()
    {
        wake();
    }
}

/// The writer's process identifier and the entry, from a log line that
/// reads `... refineid[pid]: message`; `None` for any other line.
fn parse_log_line(line: &str) -> Option<(u32, Followed)> {
    let tag = format!("{IDENTIFIER}[");
    let start = line.find(&tag)? + tag.len();
    let (pid, rest) = line[start..].split_once("]: ")?;
    let pid = pid.parse().ok()?;
    let (message, occurrences) = rest
        .strip_suffix(COUNT_CLOSE)
        .and_then(|counted| counted.rsplit_once(COUNT_OPEN))
        .and_then(|(message, count)| Some((message, count.parse().ok()?)))
        .unwrap_or((rest, 1));
    Some((
        pid,
        Followed {
            message: message.to_owned(),
            occurrences,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{Followed, parse_log_line};

    const PID: u32 = 42;
    const REPEATS: u32 = 3;
    const MESSAGE: &str = "Pkcs11: signature request failed: Ambiguous";

    fn followed(occurrences: u32) -> Followed {
        Followed {
            message: MESSAGE.to_owned(),
            occurrences,
        }
    }

    #[test]
    fn a_log_line_gives_its_pid_and_message() {
        let line = format!("Jan  1 00:00:00 example refineid[{PID}]: {MESSAGE}");
        assert_eq!(parse_log_line(&line), Some((PID, followed(1))));
    }

    #[test]
    fn a_counted_line_gives_its_count() {
        let line = format!("Jan  1 00:00:00 example refineid[{PID}]: {MESSAGE} (x{REPEATS})");
        assert_eq!(parse_log_line(&line), Some((PID, followed(REPEATS))));
    }

    #[test]
    fn another_programs_line_is_passed_over() {
        assert_eq!(
            parse_log_line("Jan  1 00:00:00 example sshd[42]: session opened"),
            None
        );
    }
}
