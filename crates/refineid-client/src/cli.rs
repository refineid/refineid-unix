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

//! Typed CLI argument structs.
//!
//! Argv flows through three nested trust boundaries:
//!
//! 1. [`argv::ProcessArgv`] (full argv, including the program
//!    name) -> [`Verb`]. [`read_command_line`] runs this in one
//!    call: tokenise, dispatch, and per-subcommand argv parse.
//! 2. Per-subcommand: each `*Args::parse(argv: RemainingArgv)
//!    -> Result<Self, ArgParseError>` validates flag /
//!    positional shape (no duplicates, no missing values, no
//!    unknown flags) and wraps each value in its typed
//!    counterpart where one exists (`Can` for `--can`, `Sha256`
//!    for digests, `PinManageSlot` for slot enums, ...).
//!    Variant-pair parsers (sign-auth vs sign-qualified) take
//!    the slot as a first argument; `pin change 1|2` and its
//!    kin parse the slot from a positional argument. Either
//!    way error messages and `Args::run` dispatch off the same
//!    value.
//! 3. The typed [`Verb`] value flows into `Verb::run`, which
//!    dispatches to `*Args::run`; an operation's handler also
//!    takes the global `verbose` flag. Once a handler
//!    has a typed `Args` value, the compiler refuses to invoke
//!    it with a malformed argv -- the only way to construct an
//!    `Args` is through `parse`.
//!
//! This mirrors the lib-core trust-boundary discipline (see
//! `doc/typing-discipline.md`): every external input gets
//! parse-don't-validated once at its trust boundary, and
//! downstream code consumes typed values without re-checking
//! shape invariants.
//!
//! Pattern per subcommand module:
//!
//! 1. Define `pub struct FooArgs { ... }` with typed fields.
//!    Variant-pair shapes (e.g. `sign-auth` vs
//!    `sign-qualified`, `pin change 1|2`) carry their
//!    identifying enum (e.g. `slot: PinManageSlot`) as a field, so [`Verb::run`] doesn't need
//!    to pass it as a separate argument.
//! 2. Define `impl FooArgs { pub fn parse(...) ->
//!    Result<Self, ArgParseError> { ... } }`. Internally the
//!    parser tags every error with `VerbTag::CardFoo` -- there
//!    is no per-module `const CMD: &str` literal; the
//!    [`VerbTag`] enum is the single source of truth.
//! 3. Define `impl FooArgs { pub fn run(self) ->
//!    std::process::ExitCode { ... } }`, or `run(self, verbose:
//!    bool)` for an operation: it prints nothing on success and its
//!    step report under `-v`. The verb dispatch in [`Verb::run`]
//!    forwards: `Self::CardFoo(a) => a.run(verbose)`. No verb-name
//!    -> handler-name mapping in `bin/refineid.rs`.
//!
//! [`ArgParseError`] is intentionally a single shared enum so
//! the binary has one error formatter that knows how to render
//! every parse failure with consistent wording + the
//! `refineid <command> help` hint.
//!
//! [`Verb`]: verb::Verb
//! [`VerbTag`]: verb::VerbTag

// `pub use verb::{...}` below is the library-facade pattern for
// the cli boundary.  Per-item `#[expect(clippy::pub_use)]` is
// rejected by rustc as a useless lint attribute; the
// suppression lives here as a module-level inner attribute.
#![expect(
    clippy::pub_use,
    reason = "library-facade pattern: the verb-parsing API lives in a private submodule and is re-exported at the cli boundary so command modules don't depend on the private layout"
)]

use alloc::fmt;

pub mod argv;
pub mod card;
pub mod card_decrypt_auth;
pub mod card_emrtd;
pub mod card_export_all;
pub mod card_pair;
pub mod card_pubkey;
pub mod card_sign;
pub mod cert_chain;
pub mod cert_show;
#[cfg(test)]
pub(crate) mod completion;
pub mod document_sign;
pub mod help;
pub mod pin_activate;
pub mod pin_change;
pub mod pin_unblock;
pub mod reader_keyboard;
pub(crate) mod util;
mod verb;
pub(crate) mod word;
// `verb` is private (mod, not pub mod); the parse-argv API
// surfaces through cli::* so cli/* command modules import via
// `super::Verb` rather than reaching into `super::verb::Verb`.
// Per-item `#[expect(clippy::pub_use)]` is rejected by rustc; the
// suppression lives as a module-level inner attribute at the top
// of this file.
pub use verb::{Invocation, ParseError, Verb, VerbParseError, VerbTag, parse_argv};
pub mod verify;

/// CLI argument parse error.
///
/// The `cmd` field carries the typed [`Verb`] the error
/// refers to; `Display` resolves it to the operator-facing
/// label via `Verb::label`. Holding the typed variant
/// (rather than a `&'static str` literal repeated per module)
/// makes the [`Verb`] enum the single source of truth
/// for subcommand identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgParseError {
    /// `--flag VALUE` was given but `VALUE` is missing.
    MissingValue {
        /// Verb the error refers to.
        cmd: VerbTag,
        /// Name of the flag that lacked its value (e.g. `--in`).
        /// Tier 0 `&'static str` from a compile-time set.
        flag: &'static str,
    },
    /// Unknown / mistyped argument.
    Unexpected {
        /// Verb the error refers to.
        cmd: VerbTag,
        /// The literal argv token that wasn't recognised. Tier 0
        /// `String` -- comes from `std::env::args()`, no domain
        /// type.
        got: String,
    },
    /// A required positional or flag is missing.
    Required {
        /// Verb the error refers to.
        cmd: VerbTag,
        /// Name of the missing input (e.g. "PATH" or "--cert").
        /// Tier 0 `&'static str` from a compile-time set.
        name: &'static str,
    },
    /// Mutually-exclusive flags both supplied.
    Conflict {
        /// Verb the error refers to.
        cmd: VerbTag,
        /// Name of the first conflicting flag. Tier 0
        /// `&'static str` from a compile-time set.
        a: &'static str,
        /// Name of the second conflicting flag.
        b: &'static str,
    },
    /// Flag value didn't parse to its typed value.
    BadValue {
        /// Verb the error refers to.
        cmd: VerbTag,
        /// Name of the flag whose value was rejected. Tier 0
        /// `&'static str` from a compile-time set.
        flag: &'static str,
        /// The literal value that didn't parse. Tier 0 `String`
        /// from argv.
        value: String,
        /// Human-readable rejection reason from the typed parser.
        /// Tier 0 `String`; presentational.
        reason: String,
    },
}

impl ArgParseError {
    /// Verb the error refers to.
    #[must_use]
    pub const fn cmd(&self) -> VerbTag {
        match self {
            Self::MissingValue { cmd, .. }
            | Self::Unexpected { cmd, .. }
            | Self::Required { cmd, .. }
            | Self::Conflict { cmd, .. }
            | Self::BadValue { cmd, .. } => *cmd,
        }
    }
}

impl fmt::Display for ArgParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cmd = self.cmd().label();
        match self {
            Self::MissingValue { flag, .. } => {
                write!(f, "{cmd}: {flag} needs an argument")
            }
            Self::Unexpected { got, .. } => {
                write!(f, "{cmd}: unexpected argument {got:?}")
            }
            Self::Required { name, .. } => {
                write!(f, "{cmd}: {name} is required")
            }
            Self::Conflict { a, b, .. } => {
                write!(f, "{cmd}: {a} and {b} are mutually exclusive")
            }
            Self::BadValue {
                flag,
                value,
                reason,
                ..
            } => {
                write!(f, "{cmd}: {flag} value {value:?} rejected: {reason}")
            }
        }
    }
}

impl core::error::Error for ArgParseError {}

/// Read and parse the CLI command line.
///
/// Captures the process argv, runs the trust-boundary parse,
/// renders help and version to stdout and errors to stderr, and
/// surfaces either the typed [`Invocation`] or the
/// already-rendered exit code for the binary to pass through.
///
/// # Errors
/// Help short-circuit returns `Err(ExitStatus::Ok.into())`;
/// parse failure returns `Err(ExitStatus::BadInvocation.into())`.
/// The `Err` value is the rendering of the outcome, not a
/// failure to do work.
pub fn read_command_line() -> Result<Invocation, std::process::ExitCode> {
    argv::ProcessArgv::from_env().resolve_command_line()
}
