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

//! `pin change 1|2` typed arguments.

use refineid_lib_core::auth::check_retry_floor;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};
use crate::card_pin::PinManageSlot;

/// What `refineid pin change help` prints. The man page
/// refineid(1) carries the same facts.
pub const HELP: &str = "\
usage: refineid pin change 1|2 [--reader SUBSTR] [--can NNNNNN]

Rotate PIN 1 (authentication) or PIN 2 (qualified signature). Prompts
for the current PIN, then the new PIN twice.
Prints nothing on success; -v shows each step.
  --reader S    narrow to readers whose name contains S
  --can NNNNNN  CAN from the card front; needed on the contactless
                interface
";

/// Parsed `pin change 1|2 [--reader SUBSTR] [--can NNNNNN]`
/// arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePinArgs {
    /// Which PIN slot to rotate: the `1|2` argument.
    pub slot: PinManageSlot,
    /// Optional reader-name substring (`--reader SUBSTR`).
    /// Tier 0 `String`; presentational input to `ReaderFilter`.
    pub reader_filter: Option<String>,
    /// `--can NNNNNN`: opens the PACE channel when the card is
    /// on the contactless interface. Omit on contact.
    pub can: Option<refineid_lib_core::can::Can>,
}

impl ChangePinArgs {
    /// Execute the `pin change` verb. Silent on success;
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
            PinManageSlot::Pin1 => "pin change 1",
            PinManageSlot::Pin2 => "pin change 2",
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

    /// Parse the post-subcommand argv slice: the required `1|2`
    /// and the options, in any order.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let cmd = VerbTag::PinChange;
        let mut slot: Option<PinManageSlot> = None;
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
                other => match super::util::pin_number(other) {
                    Some(number) if slot.is_none() => slot = Some(number),
                    _ => {
                        return Err(ArgParseError::Unexpected {
                            cmd,
                            got: other.to_owned(),
                        });
                    }
                },
            }
        }
        let slot = slot.ok_or(ArgParseError::Required {
            cmd,
            name: super::util::PIN_NUMBER,
        })?;
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
    fn parses_pin_number_with_no_reader_filter() -> TestResult {
        let a = ChangePinArgs::parse(argv(&["1"]))?;
        check_true(a.reader_filter.is_none(), "reader_filter=None")?;
        check(&a.slot, &PinManageSlot::Pin1, "slot")
    }

    #[test]
    fn parses_reader_filter_before_pin_number() -> TestResult {
        let a = ChangePinArgs::parse(argv(&["--reader", "Synthetic Card Reader", "2"]))?;
        check(
            &a.reader_filter.as_deref(),
            &Some("Synthetic Card Reader"),
            "reader_filter",
        )?;
        check(&a.slot, &PinManageSlot::Pin2, "slot")
    }

    #[test]
    fn pin_number_is_required_and_one_or_two() -> TestResult {
        check_true(
            matches!(
                ChangePinArgs::parse(argv(&[])),
                Err(ArgParseError::Required { .. })
            ),
            "missing number",
        )?;
        for bad in [&["3"][..], &["0"], &["pin1"], &["1", "2"], &["1", "1"]] {
            check_true(
                matches!(
                    ChangePinArgs::parse(argv(bad)),
                    Err(ArgParseError::Unexpected { .. })
                ),
                &format!("{bad:?} rejected"),
            )?;
        }
        Ok(())
    }

    #[test]
    fn unknown_flag_rejected() -> TestResult {
        let r = ChangePinArgs::parse(argv(&["1", "--enforce-strong"]));
        check_true(
            matches!(r, Err(ArgParseError::Unexpected { .. })),
            "Unexpected",
        )
    }

    #[test]
    fn reader_without_value_rejected() -> TestResult {
        let r = ChangePinArgs::parse(argv(&["1", "--reader"]));
        check_true(
            matches!(r, Err(ArgParseError::MissingValue { .. })),
            "MissingValue",
        )
    }
}
