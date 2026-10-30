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

//! `card unblock-pin1` / `card unblock-pin2` typed arguments.

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};
use crate::card_pin::PinManageSlot;

/// What `refineid card unblock-pin1 help` and `unblock-pin2 help`
/// prints. The man page refineid(1) carries the same facts.
pub const HELP: &str = "\
usage: refineid card unblock-pin1 | unblock-pin2 [--reader SUBSTR]

Unblock PIN1 or PIN2 with the PUK and set a new PIN.
Prints nothing on success; -v shows each step.
  --reader S  narrow to readers whose name contains S
DANGER: a wrong PUK decrements the PUK counter; exhausting it
permanently bricks the card.
";

/// Parsed `card unblock-pin{1,2} [--reader SUBSTR]` arguments.
///
/// `slot` is set by the dispatcher at parse time -- which
/// subcommand fired (`unblock-pin1` vs `unblock-pin2`) is the
/// only signal for PIN1-vs-PIN2 identity, and we capture it
/// into the typed struct so [`Self::run`] takes no extra
/// argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnblockPinArgs {
    /// Which PIN slot to unblock; set by the dispatcher at
    /// parse time.
    pub slot: PinManageSlot,
    /// Optional reader-name substring (`--reader SUBSTR`).
    /// Tier 0 `String`; presentational input to `ReaderFilter`.
    pub reader_filter: Option<String>,
}

impl UnblockPinArgs {
    /// Execute the `card unblock-pin{1,2}` verb. Silent on success;
    /// `verbose` prints the step report.
    #[must_use]
    pub fn run(self, verbose: bool) -> std::process::ExitCode {
        use crate::exit_status::ExitStatus;
        let Self {
            slot,
            reader_filter,
        } = self;
        let cmd = match slot {
            PinManageSlot::Pin1 => "card unblock-pin1",
            PinManageSlot::Pin2 => "card unblock-pin2",
        };
        let label = super::util::pin_name(slot);
        let backend = refineid_lib_pcsc::PcscBackend;
        let typed_reader_filter = reader_filter
            .as_deref()
            .map(refineid_lib_core::backend::ReaderFilter::new);
        let session =
            match crate::card_pin::establish_trusted_session(backend, typed_reader_filter.as_ref())
            {
                Ok(s) => s,
                Err(crate::card_pin::CardPinError::ReaderPick(pe)) => {
                    return super::util::reader_pick_exit(cmd, &pe);
                }
                Err(e) => {
                    eprintln!("{cmd}: {e}");
                    return ExitStatus::RuntimeFailure.into();
                }
            };
        let ctx = session.into_pin_management_context();
        let puk_raw = match super::util::prompt_pin(cmd, super::util::PROMPT_PUK) {
            Ok(p) => p,
            Err(exit) => return exit,
        };
        let puk = match refineid_lib_core::pin::Puk::new(puk_raw) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{cmd}: PUK: {e}");
                return ExitStatus::BadInvocation.into();
            }
        };
        let new1 = match super::util::prompt_new_pin_pair(cmd, label, None) {
            Ok(p) => p,
            Err(exit) => return exit,
        };
        let options = crate::card_pin::UnblockPinOptions {
            slot,
            puk,
            new_pin: new1,
            reader_filter,
        };
        match crate::card_pin::unblock_pin_first(backend, ctx, options) {
            Ok(report) => {
                let succeeded =
                    matches!(report.outcome, refineid_lib_core::auth::UnblockOutcome::Ok);
                super::util::show_outcome(verbose, succeeded, &report);
                match report.outcome {
                    refineid_lib_core::auth::UnblockOutcome::Ok => ExitStatus::Ok.into(),
                    refineid_lib_core::auth::UnblockOutcome::WrongPuk { .. }
                    | refineid_lib_core::auth::UnblockOutcome::PukLocked
                    | refineid_lib_core::auth::UnblockOutcome::Invalidated => {
                        ExitStatus::CardCredentialRejected.into()
                    }
                    refineid_lib_core::auth::UnblockOutcome::LengthError
                    | refineid_lib_core::auth::UnblockOutcome::Other(_) => {
                        ExitStatus::RuntimeFailure.into()
                    }
                }
            }
            Err(crate::card_pin::CardPinError::ReaderPick(pe)) => {
                super::util::reader_pick_exit(cmd, &pe)
            }
            Err(
                e @ (crate::card_pin::CardPinError::PinPolicy(_)
                | crate::card_pin::CardPinError::RetryFloor(_)),
            ) => {
                eprintln!("{cmd}: {e}");
                ExitStatus::CardCredentialRejected.into()
            }
            Err(e) => {
                eprintln!("{cmd}: {e}");
                ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice for the given
    /// `slot`. The caller (the verb dispatcher) selects the
    /// slot from which subcommand fired and we carry it into
    /// the typed [`UnblockPinArgs`] so [`Self::run`] needs no
    /// extra argument.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation.
    pub fn parse(slot: PinManageSlot, argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let cmd = match slot {
            PinManageSlot::Pin1 => VerbTag::CardUnblockPin1,
            PinManageSlot::Pin2 => VerbTag::CardUnblockPin2,
        };
        let mut reader_filter: Option<String> = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--reader" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd,
                        flag: "--reader",
                    })?;
                    reader_filter = Some(value.clone());
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd,
                        got: other.to_owned(),
                    });
                }
            }
        }
        Ok(Self {
            slot,
            reader_filter,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn parses_empty_argv() -> TestResult {
        let a = UnblockPinArgs::parse(PinManageSlot::Pin1, argv(&[]))?;
        check_true(a.reader_filter.is_none(), "reader_filter=None")?;
        check(&a.slot, &PinManageSlot::Pin1, "slot")
    }

    #[test]
    fn parses_reader_filter() -> TestResult {
        let a = UnblockPinArgs::parse(PinManageSlot::Pin2, argv(&["--reader", "OMNIKEY"]))?;
        check(
            &a.reader_filter.as_deref(),
            &Some("OMNIKEY"),
            "reader_filter",
        )?;
        check(&a.slot, &PinManageSlot::Pin2, "slot")
    }

    #[test]
    fn unknown_flag_rejected() -> TestResult {
        let r = UnblockPinArgs::parse(PinManageSlot::Pin1, argv(&["--foo"]));
        check_true(
            matches!(r, Err(ArgParseError::Unexpected { .. })),
            "Unexpected",
        )
    }
}
