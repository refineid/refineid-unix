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

//! `document verify` typed arguments.
//!
//! The counterpart of `document sign`: given the signed document, say
//! who signed it, when, and whether the signature holds. A query, so
//! the verdict is printed; the exit status repeats it for scripts.

use core::fmt::Write as _;
use std::path::PathBuf;

use refineid_lib_core::document::{DocumentReport, Revocation, SignatureReport};

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};
use crate::exit_status::ExitStatus;

/// What `refineid document verify help`
/// prints. The man page refineid(1) carries the same facts.
pub const HELP: &str = "\
usage: refineid document verify FILE [FILE ...]

Verify the signatures of a signed document: a PDF, an ASiC-E or BDOC
container, or a CMS structure with the document attached. Prints one
line per signature: the signer, the time a timestamp proves the
signature existed, and the verdict. -v adds each fact behind it.
Exits 0 when every signature is valid, 1 when one is not or its
certificate is revoked.
";

/// This verb's tag, for error messages.
const CMD: VerbTag = VerbTag::DocumentVerify;

/// The indent of a signature line under its file.
const SIGNATURE_INDENT: &str = "  ";

/// The indent of a fact row under its signature.
const FACT_INDENT: &str = "    ";

/// The width the fact names are padded to.
const FACT_WIDTH: usize = 18;

/// The column a signer's name is padded to on the signature line.
const SIGNER_WIDTH: usize = 40;

/// What stands in for a time that was not proven.
const NO_TIME: &str = "-";

/// Parsed `document verify FILE [FILE ...]` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentVerifyArgs {
    /// The documents to judge, in command-line order.
    pub inputs: Vec<PathBuf>,
}

impl DocumentVerifyArgs {
    /// Execute the verb: print each document's report, exit by the
    /// aggregate verdict.
    #[must_use]
    pub fn run(self, verbose: bool) -> std::process::ExitCode {
        let now = crate::card_check::now_date_time();
        let mut status = ExitStatus::Ok;
        for (index, path) in self.inputs.iter().enumerate() {
            if index > 0 {
                println!();
            }
            match crate::document_verify::verify_file(path, now) {
                Ok(report) => {
                    print!("{}", render(&path.display().to_string(), &report, verbose));
                    if !report.is_valid() && status == ExitStatus::Ok {
                        status = ExitStatus::VerifyFailed;
                    }
                }
                Err(error) => {
                    eprintln!("{}: {error}", CMD.label());
                    status = ExitStatus::RuntimeFailure;
                }
            }
        }
        status.into()
    }

    /// Parse the post-subcommand argv slice: every argument is a file.
    ///
    /// # Errors
    /// [`ArgParseError`] when no file is named or an option is given.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut inputs = Vec::new();
        for arg in argv.into_vec() {
            if arg.starts_with("--") {
                return Err(ArgParseError::Unexpected { cmd: CMD, got: arg });
            }
            inputs.push(PathBuf::from(arg));
        }
        if inputs.is_empty() {
            return Err(ArgParseError::Required {
                cmd: CMD,
                name: "FILE",
            });
        }
        Ok(Self { inputs })
    }
}

/// The report of one document: its name, one line per signature, and
/// with `verbose` the facts behind each line and the document
/// timestamps.
fn render(name: &str, report: &DocumentReport, verbose: bool) -> String {
    let mut out = format!("{name}\n");
    for signature in &report.signatures {
        push_signature_line(&mut out, signature);
        if verbose {
            push_facts(&mut out, signature);
        }
    }
    if verbose {
        for stamped in &report.document_timestamps {
            let _ = writeln!(out, "{SIGNATURE_INDENT}document timestamp {stamped}");
        }
    }
    out
}

/// `  <signer>  <time>  <verdict>`.
fn push_signature_line(out: &mut String, signature: &SignatureReport) {
    let time = signature
        .proof_of_existence
        .map_or_else(|| NO_TIME.to_owned(), |time| time.to_string());
    let _ = writeln!(
        out,
        "{SIGNATURE_INDENT}{:<SIGNER_WIDTH$}  {time}  {}",
        signer(signature),
        verdict(signature)
    );
}

/// The holder's name and electronic identifier.
fn signer(signature: &SignatureReport) -> String {
    match &signature.signer.identifier {
        Some(identifier) if signature.signer.name.is_empty() => identifier.as_str().to_owned(),
        Some(identifier) => format!("{} {}", signature.signer.name, identifier.as_str()),
        None => signature.signer.name.clone(),
    }
}

/// The verdict and, when there is one, the reasons or the caveat.
fn verdict(signature: &SignatureReport) -> String {
    if signature.revocation == Revocation::Revoked {
        return "revoked".to_owned();
    }
    let mut failed = Vec::new();
    if !signature.document_intact {
        failed.push("document changed");
    }
    if !signature.signature_valid {
        failed.push("signature invalid");
    }
    if !signature.chain_verified {
        failed.push("certificate chain unverified");
    }
    if !signature.timestamps_valid {
        failed.push("no valid timestamp");
    }
    if !failed.is_empty() {
        return format!("not valid: {}", failed.join(", "));
    }
    match signature.revocation {
        Revocation::Good { .. } => "valid".to_owned(),
        Revocation::Unavailable => "valid, revocation not checked".to_owned(),
        Revocation::Revoked => "revoked".to_owned(),
    }
}

/// The fact rows behind one signature line.
fn push_facts(out: &mut String, signature: &SignatureReport) {
    push_fact(out, "document intact", yes_no(signature.document_intact));
    push_fact(out, "signature", yes_no(signature.signature_valid));
    push_fact(out, "certificate chain", yes_no(signature.chain_verified));
    let timestamp = match signature.proof_of_existence {
        Some(time) if signature.timestamps_valid => format!("yes {time}"),
        Some(time) => format!("no {time}"),
        None => "no".to_owned(),
    };
    push_fact(out, "timestamp", timestamp);
    let revocation = match signature.revocation {
        Revocation::Good { checked_at } => format!("good at {checked_at}"),
        Revocation::Revoked => "revoked".to_owned(),
        Revocation::Unavailable => "not checked".to_owned(),
    };
    push_fact(out, "revocation", revocation);
}

/// One `    <name>  <value>` row.
fn push_fact(out: &mut String, name: &str, value: impl AsRef<str>) {
    let _ = writeln!(out, "{FACT_INDENT}{name:<FACT_WIDTH$}{}", value.as_ref());
}

/// `yes` or `no`.
const fn yes_no(holds: bool) -> &'static str {
    if holds { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn every_argument_is_a_file() -> TestResult {
        let args = DocumentVerifyArgs::parse(argv(&["/documents/a.pdf", "/documents/b.asice"]))?;
        check(
            &args.inputs,
            &vec![
                PathBuf::from("/documents/a.pdf"),
                PathBuf::from("/documents/b.asice"),
            ],
            "inputs",
        )
    }

    #[test]
    fn a_file_is_required() -> TestResult {
        check_true(
            matches!(
                DocumentVerifyArgs::parse(argv(&[])),
                Err(ArgParseError::Required { name: "FILE", .. })
            ),
            "no file is refused",
        )
    }

    #[test]
    fn options_are_refused() -> TestResult {
        check_true(
            matches!(
                DocumentVerifyArgs::parse(argv(&["--offline", "/documents/a.pdf"])),
                Err(ArgParseError::Unexpected { .. })
            ),
            "an option is refused",
        )
    }
}
