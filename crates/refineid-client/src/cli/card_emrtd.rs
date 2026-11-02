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

//! `card emrtd` typed arguments.

use std::path::PathBuf;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};

/// What `refineid card emrtd help`
/// prints. The man page refineid(1) carries the same facts.
pub const HELP: &str = "\
usage: refineid card emrtd [--save-face PATH] [--save-signature PATH]
                           [--reader SUBSTR]

eMRTD file extraction: the same read as the eMRTD section of `card`,
plus flags that write artefacts to disk. Prompts for the CAN.
  --save-face P       face image
  --save-signature P  displayed-signature image
  --reader S          narrow to readers whose name contains S
";

/// Parsed `card emrtd [--save-face PATH] [--save-signature PATH]
/// [--reader SUBSTR]` arguments. The CAN is not an argument: it is
/// read from the terminal when the verb runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmrtdArgs {
    /// Optional path to save DG2 face image (`--save-face PATH`).
    pub save_face: Option<PathBuf>,
    /// Optional path to save DG7 displayed signature image
    /// (`--save-signature PATH`).
    pub save_signature: Option<PathBuf>,
    /// Optional substring match against reader names
    /// (`--reader SUBSTR`). Tier 0 `String`; presentational
    /// input to `ReaderFilter::new`.
    pub reader_filter: Option<String>,
}

impl EmrtdArgs {
    /// Execute the `card emrtd` verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        let Self {
            save_face,
            save_signature,
            reader_filter,
        } = self;
        let Some(can) = super::util::prompt_can_if_tty() else {
            eprintln!("card emrtd: needs the CAN, entered at the terminal prompt");
            return crate::exit_status::ExitStatus::BadInvocation.into();
        };
        let backend = refineid_lib_pcsc::PcscBackend;
        let options = crate::card_emrtd::EmrtdReadOptions {
            can,
            save_face,
            save_signature,
            reader_filter,
        };
        match crate::card_emrtd::read_first(backend, &options) {
            Ok(report) => {
                print!("{report}");
                crate::exit_status::ExitStatus::Ok.into()
            }
            Err(crate::card_emrtd::EmrtdReadError::ReaderPick(pe)) => {
                super::util::reader_pick_exit("card emrtd", &pe)
            }
            Err(e) => {
                eprintln!("card emrtd: {e}");
                crate::exit_status::ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice.
    ///
    /// # Errors
    /// [`ArgParseError`] for a missing flag value or an unknown
    /// argument.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut save_face: Option<PathBuf> = None;
        let mut save_signature: Option<PathBuf> = None;
        let mut reader_filter: Option<String> = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--save-face" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardEmrtd,
                        flag: "--save-face",
                    })?;
                    save_face = Some(PathBuf::from(value));
                }
                "--save-signature" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardEmrtd,
                        flag: "--save-signature",
                    })?;
                    save_signature = Some(PathBuf::from(value));
                }
                "--reader" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardEmrtd,
                        flag: "--reader",
                    })?;
                    reader_filter = Some(value.clone());
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::CardEmrtd,
                        got: other.to_owned(),
                    });
                }
            }
        }
        Ok(Self {
            save_face,
            save_signature,
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
    fn parses_no_arguments() -> TestResult {
        let a = EmrtdArgs::parse(argv(&[]))?;
        check_true(a.save_face.is_none(), "save_face=None")?;
        check_true(a.save_signature.is_none(), "save_signature=None")
    }

    #[test]
    fn can_is_not_an_argument() -> TestResult {
        let r = EmrtdArgs::parse(argv(&["--can", "123456"]));
        check_true(
            matches!(&r, Err(ArgParseError::Unexpected { got, .. }) if got == "--can"),
            "Unexpected(--can)",
        )
    }

    #[test]
    fn save_paths_recorded() -> TestResult {
        let a = EmrtdArgs::parse(argv(&["--save-face", "/f", "--save-signature", "/s"]))?;
        check(&a.save_face, &Some(PathBuf::from("/f")), "save_face")?;
        check(
            &a.save_signature,
            &Some(PathBuf::from("/s")),
            "save_signature",
        )
    }
}
