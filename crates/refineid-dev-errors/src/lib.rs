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

//! The errors of a debug build, made visible.
//!
//! A debug build (`debug_assertions`) writes every failure a `RefineID`
//! program reports with [`report!`] to the system log under the one
//! identifier [`IDENTIFIER`], at the error level: the CLI, the GUI and
//! the PKCS#11 module inside a browser alike, so `journalctl -t refineid`
//! on Linux, or `/var/log/messages` on FreeBSD, shows them together. The
//! GUI's Errors window follows the same log ([`follow`]).
//!
//! An entry reads `component: event: cause`, for example
//! `Rapp: phone session not opened: Session(ClosedByPeer(Busy))`. A
//! failure that repeats itself is counted and written again with its
//! count, as ` (xN)`, at most once per [`REPEAT_WINDOW`] for each
//! component and event, so a loop that fails the same way on every pass
//! does not flood the log. A program that ends normally writes the counts
//! still pending with [`flush!`].
//!
//! A cause is a name and nothing else: the case of an error value with
//! every payload that is not itself a case dropped, or a fixed text. An
//! entry never carries a PIN, PUK or card access number, their length or
//! digits, a name, certificate content, an APDU or ATR, an address, a
//! host, reader or device name, a serial number or a path.
//!
//! A release build compiles none of this: [`report!`] expands to nothing,
//! so no sink, socket or message text reaches the binary. A `cargo test`
//! binary records nothing, so a test's deliberate failures never reach a
//! developer's log.

#[cfg(debug_assertions)]
mod cause;
#[cfg(debug_assertions)]
mod follow;
#[cfg(debug_assertions)]
mod record;
#[cfg(all(unix, debug_assertions))]
mod syslog;

#[cfg(debug_assertions)]
pub use cause::Cause;
#[cfg(debug_assertions)]
pub use follow::{Followed, Follower, follow};
#[cfg(debug_assertions)]
pub use record::{Component, IDENTIFIER, REPEAT_WINDOW, flush, record};

/// Reports a failure in a debug build; expands to nothing in a release
/// build.
///
/// The first argument names the [`Component`], the second is the event, a
/// `&'static str` such as a string literal, and the third is its cause, one
/// of:
///
/// - a string literal, a fixed description;
/// - `name expression`, a `&'static str` naming the cause;
/// - a variable holding an error value, written as the case it is
///   ([`Cause::case`]).
///
/// ```ignore
/// refineid_dev_errors::report!(Rapp, "phone session not opened", error);
/// refineid_dev_errors::report!(Gui, "document not signed", "no document chosen");
/// ```
///
/// In a release build a variable cause is only borrowed, so it stays used,
/// and nothing else of the call remains.
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! report {
    ($component:ident, $event:expr, $cause:literal) => {
        $crate::record(
            $crate::Component::$component,
            $event,
            &$crate::Cause::text($cause),
        )
    };
    ($component:ident, $event:expr, name $name:expr) => {
        $crate::record(
            $crate::Component::$component,
            $event,
            &$crate::Cause::text($name),
        )
    };
    ($component:ident, $event:expr, $cause:ident) => {
        $crate::record(
            $crate::Component::$component,
            $event,
            &$crate::Cause::case(&$cause),
        )
    };
}

/// Reports a failure in a debug build; expands to nothing in a release
/// build.
#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! report {
    ($component:ident, $event:expr, $cause:literal) => {{}};
    ($component:ident, $event:expr, name $name:expr) => {{}};
    ($component:ident, $event:expr, $cause:ident) => {{
        let _ = &$cause;
    }};
}

/// Writes the counted repeats not yet written, as a program ends, in a
/// debug build; expands to nothing in a release build.
#[cfg(debug_assertions)]
#[macro_export]
macro_rules! flush {
    () => {
        $crate::flush()
    };
}

/// Writes the counted repeats not yet written, as a program ends, in a
/// debug build; expands to nothing in a release build.
#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! flush {
    () => {{}};
}
