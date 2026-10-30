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

//! `card change-pin1` / `card change-pin2` typed arguments.

use refineid_lib_core::auth::check_retry_floor;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};
use crate::card_pin::PinManageSlot;

/// What `refineid card change-pin1 help` and `change-pin2 help`
/// prints. The man page refineid(1) carries the same facts.
pub const HELP: &str = "\
usage: refineid card change-pin1 | change-pin2 [--reader SUBSTR] [--can NNNNNN]

Rotate PIN1 (authentication) or PIN2 (qualified signature). Prompts
for the current PIN, then the new PIN twice.
Prints nothing on success; -v shows each step.
  --reader S    narrow to readers whose name contains S
  --can NNNNNN  CAN from the card front; needed on the contactless
                interface
";

/// Parsed `card change-pin{1,2} [--reader SUBSTR]` arguments.
///
/// `slot` is set by the dispatcher at parse time -- which
/// subcommand fired (`change-pin1` vs `change-pin2`) is the
/// only signal for PIN1-vs-PIN2 identity, and we capture it
/// into the typed struct so [`Self::run`] takes no extra
/// argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePinArgs {
    /// Which PIN slot to rotate; set by the dispatcher at parse
    /// time.
    pub slot: PinManageSlot,
    /// Optional reader-name substring (`--reader SUBSTR`).
    /// Tier 0 `String`; presentational input to `ReaderFilter`.
    pub reader_filter: Option<String>,
    /// `--can NNNNNN`: opens the PACE channel when the card is
    /// on the contactless interface. Omit on contact.
    pub can: Option<refineid_lib_core::can::Can>,
}

impl ChangePinArgs {
    /// Execute the `card change-pin{1,2}` verb. Silent on success;
    /// `verbose` prints the step report.
    #[must_use]
    pub fn run(self, verbose: bool) -> std::process::ExitCode {
        use crate::exit_status::ExitStatus;
        let Self {
            slot,
            reader_filter,
            can: _,
        } = self;
        let cmd = match slot {
            PinManageSlot::Pin1 => "card change-pin1",
            PinManageSlot::Pin2 => "card change-pin2",
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
        let retry_status = match crate::card_pin::probe_pin_status_for_cli(backend, &ctx, slot) {
            Ok(status) => status,
            Err(error) => {
                eprintln!("{cmd}: {error}");
                return ExitStatus::RuntimeFailure.into();
            }
        };
        // A change presents the current PIN, so it is a PIN attempt: refuse
        // below the retry floor before prompting.
        if let Err(refusal) = check_retry_floor(slot.as_pin_slot(), retry_status) {
            eprintln!("{cmd}: {refusal}");
            return ExitStatus::CardCredentialRejected.into();
        }
        let (current_env, new_env) = match slot {
            PinManageSlot::Pin1 => ("REFINEID_CURRENT_PIN1", "REFINEID_NEW_PIN1"),
            PinManageSlot::Pin2 => ("REFINEID_CURRENT_PIN2", "REFINEID_NEW_PIN2"),
        };
        let current =
            match super::util::pin_env_or_prompt(cmd, current_env, &format!("current {label}: ")) {
                Ok(p) => p,
                Err(exit) => return exit.into(),
            };
        let new1 = match super::util::new_pin_env_or_prompt(cmd, new_env, label, None) {
            Ok(p) => p,
            Err(exit) => return exit,
        };
        let options = crate::card_pin::ChangePinOptions {
            slot,
            current,
            new: new1,
            reader_filter,
        };
        match crate::card_pin::change_pin_first_for_cli(backend, ctx, options) {
            Ok(report) => {
                let succeeded = matches!(
                    report.outcome,
                    refineid_lib_core::auth::ChangePinOutcome::Ok
                );
                super::util::show_outcome(verbose, succeeded, &report);
                match report.outcome {
                    refineid_lib_core::auth::ChangePinOutcome::Ok => ExitStatus::Ok.into(),
                    refineid_lib_core::auth::ChangePinOutcome::WrongCurrentPin { .. }
                    | refineid_lib_core::auth::ChangePinOutcome::Locked => {
                        ExitStatus::CardCredentialRejected.into()
                    }
                    refineid_lib_core::auth::ChangePinOutcome::LengthError
                    | refineid_lib_core::auth::ChangePinOutcome::Other(_) => {
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
    /// the typed [`ChangePinArgs`] so [`Self::run`] needs no
    /// extra argument.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation.
    pub fn parse(slot: PinManageSlot, argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let cmd = match slot {
            PinManageSlot::Pin1 => VerbTag::CardChangePin1,
            PinManageSlot::Pin2 => VerbTag::CardChangePin2,
        };
        let mut reader_filter: Option<String> = None;
        let mut can: Option<refineid_lib_core::can::Can> = None;
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
                "--can" => {
                    let value = iter
                        .next()
                        .ok_or(ArgParseError::MissingValue { cmd, flag: "--can" })?;
                    let parsed = refineid_lib_core::can::Can::new(value).map_err(|e| {
                        ArgParseError::BadValue {
                            cmd,
                            flag: "--can",
                            value: value.clone(),
                            reason: format!("{e}"),
                        }
                    })?;
                    can = Some(parsed);
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
            can,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn parses_empty_argv_with_no_reader_filter() -> TestResult {
        let a = ChangePinArgs::parse(PinManageSlot::Pin1, argv(&[]))?;
        check_true(a.reader_filter.is_none(), "reader_filter=None")?;
        check(&a.slot, &PinManageSlot::Pin1, "slot")
    }

    #[test]
    fn parses_reader_filter() -> TestResult {
        let a = ChangePinArgs::parse(PinManageSlot::Pin2, argv(&["--reader", "ACS"]))?;
        check(&a.reader_filter.as_deref(), &Some("ACS"), "reader_filter")?;
        check(&a.slot, &PinManageSlot::Pin2, "slot")
    }

    #[test]
    fn unknown_flag_rejected() -> TestResult {
        let r = ChangePinArgs::parse(PinManageSlot::Pin1, argv(&["--enforce-strong"]));
        check_true(
            matches!(r, Err(ArgParseError::Unexpected { .. })),
            "Unexpected",
        )
    }

    #[test]
    fn reader_without_value_rejected() -> TestResult {
        let r = ChangePinArgs::parse(PinManageSlot::Pin1, argv(&["--reader"]));
        check_true(
            matches!(r, Err(ArgParseError::MissingValue { .. })),
            "MissingValue",
        )
    }
}
