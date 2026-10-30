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

//! `card` (unified readout) typed arguments.

use std::path::PathBuf;

use refineid_lib_core::can::Can;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};

/// What `refineid card help`
/// prints. The man page refineid(1) carries the same facts.
pub const HELP: &str = "\
usage: refineid card [--offline] [--reader SUBSTR] [--can NNNNNN | --no-can]
                     [--crl-file PATH] [--save-cert DIR] [--remote]

Per-card readout: certificates, chain walk and revocation, PIN retry
counters, and with --can the eMRTD section. With no card in a reader,
reads the card through the paired phone.
  --offline        skip every network fetch
  --reader S       narrow to readers whose name contains S
  --can NNNNNN     CAN from the card front; enables eMRTD
  --no-can         skip the eMRTD section (no prompt)
  --crl-file P     use a pre-fetched CRL instead of HTTP fetch
  --save-cert DIR  write each slot's DER to DIR
  --remote         read the card through the paired phone only
Without --can or --no-can on a terminal, prompts for the CAN
(empty = skip).
";

/// CAN selection mode at the argv layer.
///
/// `--can NNNNNN` / `--no-can` / neither is a closed three-way
/// state, modelled as an enum so the mutual-exclusion rule
/// holds at the type level rather than via a runtime check on
/// two parallel `Option<String> + bool` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardCanArg {
    /// `--can NNNNNN` -- explicit, already parse-validated
    /// into a typed [`Can`].
    Explicit(Can),
    /// `--no-can` -- explicit "skip the eMRTD section".
    Skip,
    /// Neither flag supplied -- the handler chooses (TTY
    /// prompt on interactive invocations; skip otherwise).
    Default,
}

/// Parsed `card [--offline] [--reader SUBSTR] [--can NNNNNN |
/// --no-can] [--crl-file PATH] [--save-cert DIR]` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardArgs {
    /// Optional reader-name substring (`--reader SUBSTR`).
    /// Tier 0 `String`; presentational input to `ReaderFilter`.
    pub reader_filter: Option<String>,
    /// When `true`, suppress every network fetch (CRL + OCSP +
    /// AIA caIssuers). Set by `--offline`.
    pub offline: bool,
    /// CAN handling: typed value (`--can NNNNNN`), prompt
    /// interactively, or skip (`--no-can`).
    pub can: CardCanArg,
    /// Pre-fetched CRL file (`--crl-file PATH`); replaces the
    /// CRL fetch step.
    pub crl_file: Option<PathBuf>,
    /// Directory to dump each slot's cert DER to
    /// (`--save-cert DIR`).
    pub save_cert_dir: Option<PathBuf>,
    /// Force checking paired remote card reader (`--remote`).
    pub remote: bool,
}

impl CardArgs {
    /// Execute the bare `card` (unified per-card readout) verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        let Self {
            reader_filter,
            offline,
            can,
            crl_file,
            save_cert_dir,
            remote,
        } = self;

        if remote {
            return Self::run_remote_card_check();
        }

        // Resolve the typed CardCanArg into Option<Can>:
        // Explicit wins, Skip = None, Default falls back to a
        // TTY prompt (interactive use) or None (piped / non-TTY).
        let can: Option<Can> = match can {
            CardCanArg::Explicit(c) => Some(c),
            CardCanArg::Skip => None,
            CardCanArg::Default => super::util::prompt_can_if_tty(),
        };
        let backend = refineid_lib_pcsc::PcscBackend;
        let options = crate::card_check::CardCheckOptions {
            reader_filter,
            offline,
            can: can.as_ref(),
            crl_file,
            save_cert_dir,
            now: None,
        };
        match crate::card_check::check_all(backend, &options) {
            Ok(reports) if reports.is_empty() => {
                if let Some(exit) = Self::try_remote_card_check() {
                    return exit;
                }
                eprintln!("no FINEID card present in any connected reader");
                crate::exit_status::ExitStatus::NoCardPresent.into()
            }
            Ok(reports) => {
                for (i, r) in reports.iter().enumerate() {
                    if i > 0 {
                        println!();
                    }
                    print!("{r}");
                }
                crate::exit_status::ExitStatus::Ok.into()
            }
            Err(crate::card_check::CardCheckError::ReaderPick(pe)) => {
                if let Some(exit) = Self::try_remote_card_check() {
                    return exit;
                }
                super::util::reader_pick_exit("card", &pe)
            }
            Err(e) => {
                eprintln!("card: {e}");
                crate::exit_status::ExitStatus::RuntimeFailure.into()
            }
        }
    }

    fn try_remote_card_check() -> Option<std::process::ExitCode> {
        let mut reader = refineid_rapp_core::remote::RemoteReader::open_local().ok()?;
        let pair = reader.phone()?;
        Some(Self::run_remote_card_check_with_pair(&mut reader, &pair))
    }

    fn run_remote_card_check() -> std::process::ExitCode {
        let Ok(mut reader) = refineid_rapp_core::remote::RemoteReader::open_local() else {
            eprintln!("cannot open the paired-phone store.");
            return std::process::ExitCode::FAILURE;
        };
        let Some(pair) = reader.phone() else {
            eprintln!("no phone paired. Run `refineid pair` first.");
            return std::process::ExitCode::FAILURE;
        };
        Self::run_remote_card_check_with_pair(&mut reader, &pair)
    }

    fn run_remote_card_check_with_pair(
        reader: &mut refineid_rapp_core::remote::RemoteReader,
        pair: &refineid_rapp_core::remote::PairSummary,
    ) -> std::process::ExitCode {
        use refineid_rapp_core::operations::{CardOperation, CardOperationResult};
        let dev_name = &pair.peer_display_name;
        let platform = &pair.peer_platform;
        println!("Connecting to paired remote reader: {dev_name} ({platform})...");

        let identity_res = reader.execute(
            Some(pair.pair_id),
            &CardOperation::ReadIdentity,
            super::card_pair::DISCOVERY_TIMEOUT,
        );
        let inspect_res = reader.execute(
            Some(pair.pair_id),
            &CardOperation::InspectCard,
            super::card_pair::DISCOVERY_TIMEOUT,
        );

        println!(
            "================================================================================"
        );
        println!("Remote FINEID Card (via {dev_name} - {platform})");
        println!(
            "================================================================================"
        );
        println!("  Pair ID:      {}", pair.pair_id_hex());

        match identity_res {
            Ok(CardOperationResult::Identity(identity)) => {
                println!("  Card Holder:  {}", identity.holder_name);
                println!("  Card ID:      {}", identity.card_id);
                println!(
                    "  Valid:        {} to {}",
                    identity.issuance_date, identity.expiration_date
                );
            }
            Ok(_) => {}
            Err(e) => {
                println!("  Identity:     (Read error: {e})");
            }
        }

        match inspect_res {
            // RAPP v26.10.29 section 9.1: the inspection carries the answer
            // to reset, or its historical bytes; PIN state stays on the phone.
            Ok(CardOperationResult::Inspection(insp)) if insp.answer_to_reset.is_empty() => {
                println!("  ATR:          (not exposed by the phone)");
            }
            Ok(CardOperationResult::Inspection(insp)) => {
                println!("  ATR:          {}", hex::encode(&insp.answer_to_reset));
            }
            Ok(_) => {}
            Err(e) => {
                println!("  Card Status:  (Inspect error: {e})");
            }
        }
        println!(
            "================================================================================"
        );
        std::process::ExitCode::SUCCESS
    }

    /// Parse the post-subcommand argv slice.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation, including:
    ///
    /// - `--can` value rejected by [`Can::new`].
    /// - `--can` and `--no-can` both supplied (Conflict).
    /// - Empty `--can` value (also a Conflict-with-skip case in
    ///   the original CLI; reported as `BadValue` here).
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut reader_filter: Option<String> = None;
        let mut offline = false;
        let mut can_explicit: Option<Can> = None;
        let mut no_can = false;
        let mut crl_file: Option<PathBuf> = None;
        let mut save_cert_dir: Option<PathBuf> = None;
        let mut remote = false;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--reader" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardCheck,
                        flag: "--reader",
                    })?;
                    reader_filter = Some(value.clone());
                }
                "--offline" => offline = true,
                "--can" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardCheck,
                        flag: "--can",
                    })?;
                    if value.is_empty() {
                        return Err(ArgParseError::BadValue {
                            cmd: VerbTag::CardCheck,
                            flag: "--can",
                            value: value.clone(),
                            reason: "empty (use --no-can to skip)".to_owned(),
                        });
                    }
                    let parsed = Can::new(value).map_err(|e| ArgParseError::BadValue {
                        cmd: VerbTag::CardCheck,
                        flag: "--can",
                        value: value.clone(),
                        reason: format!("{e}"),
                    })?;
                    can_explicit = Some(parsed);
                }
                "--no-can" => no_can = true,
                "--crl-file" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardCheck,
                        flag: "--crl-file",
                    })?;
                    crl_file = Some(PathBuf::from(value));
                }
                "--save-cert" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardCheck,
                        flag: "--save-cert",
                    })?;
                    save_cert_dir = Some(PathBuf::from(value));
                }
                "--remote" => remote = true,
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::CardCheck,
                        got: other.to_owned(),
                    });
                }
            }
        }
        let can = match (can_explicit, no_can) {
            (Some(_), true) => {
                return Err(ArgParseError::Conflict {
                    cmd: VerbTag::CardCheck,
                    a: "--can",
                    b: "--no-can",
                });
            }
            (Some(c), false) => CardCanArg::Explicit(c),
            (None, true) => CardCanArg::Skip,
            (None, false) => CardCanArg::Default,
        };
        Ok(Self {
            reader_filter,
            offline,
            can,
            crl_file,
            save_cert_dir,
            remote,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn defaults() -> TestResult {
        let a = CardArgs::parse(argv(&[]))?;
        check_true(!a.offline, "offline=false")?;
        check_true(a.reader_filter.is_none(), "reader_filter=None")?;
        check(&a.can, &CardCanArg::Default, "can")?;
        Ok(())
    }

    #[test]
    fn offline_flag() -> TestResult {
        let a = CardArgs::parse(argv(&["--offline"]))?;
        check_true(a.offline, "offline=true")
    }

    #[test]
    fn no_can_sets_skip() -> TestResult {
        let a = CardArgs::parse(argv(&["--no-can"]))?;
        check(&a.can, &CardCanArg::Skip, "can")
    }

    #[test]
    fn can_value_validates_via_can_newtype() -> TestResult {
        let a = CardArgs::parse(argv(&["--can", "123456"]))?;
        check_true(matches!(a.can, CardCanArg::Explicit(_)), "can=Explicit(_)")
    }

    #[test]
    fn malformed_can_rejected() -> TestResult {
        let r = CardArgs::parse(argv(&["--can", "12"]));
        check_true(
            matches!(r, Err(ArgParseError::BadValue { flag: "--can", .. })),
            "BadValue(--can)",
        )
    }

    #[test]
    fn empty_can_rejected() -> TestResult {
        let r = CardArgs::parse(argv(&["--can", ""]));
        check_true(
            matches!(r, Err(ArgParseError::BadValue { flag: "--can", .. })),
            "BadValue(--can)",
        )
    }

    #[test]
    fn can_and_no_can_conflict() -> TestResult {
        let r = CardArgs::parse(argv(&["--can", "123456", "--no-can"]));
        check_true(
            matches!(
                r,
                Err(ArgParseError::Conflict {
                    a: "--can",
                    b: "--no-can",
                    ..
                })
            ),
            "Conflict(--can,--no-can)",
        )
    }

    #[test]
    fn all_paths_parsed() -> TestResult {
        let a = CardArgs::parse(argv(&[
            "--reader",
            "OMNIKEY",
            "--crl-file",
            "/c.crl",
            "--save-cert",
            "/certs",
        ]))?;
        check(
            &a.reader_filter.as_deref(),
            &Some("OMNIKEY"),
            "reader_filter",
        )?;
        check(&a.crl_file, &Some(PathBuf::from("/c.crl")), "crl_file")?;
        check(
            &a.save_cert_dir,
            &Some(PathBuf::from("/certs")),
            "save_cert_dir",
        )?;
        Ok(())
    }
}
