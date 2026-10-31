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

use core::fmt::Display;
use std::path::PathBuf;

use refineid_lib_core::document::{
    CertificatePath, DocumentReport, DocumentTimestamp, Revocation, SignatureEntry,
    SignatureReport, SignatureTimestamp, SignerIdentity, SubjectName, UnsupportedSignature,
};
use refineid_lib_core::x509::DateTime;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};
use crate::document_verify::DocumentVerifyError;
use crate::exit_status::ExitStatus;

/// What `refineid document verify help`
/// prints. The man page refineid(1) carries the same facts.
pub const HELP: &str = "\
usage: refineid document verify FILE [FILE ...]

Verify the signatures of a signed document: a PDF, an ASiC-E or BDOC
container, or a CMS structure with the document attached. Prints one
record per signature, records separated by a blank line, each line
`key: value`:

  file: the file as named
  signer: the certificate's common name as it reads
  signed: the time a timestamp proves, or -
  verdict: valid, not valid, revoked or unsupported
  reason: one line per cause of not valid or unsupported
  revocation: not checked, when a valid signature's revocation
    could not be checked

-v adds intact, signature, chain, claimed, timestamp,
timestamp-chain, revocation and document-timestamp lines. A file that
cannot be judged prints file and error.
Exits 70 when any file cannot be judged, else 1 when any signature
is not valid, revoked or unsupported, else 0.
";

/// This verb's tag, for error messages.
const CMD: VerbTag = VerbTag::DocumentVerify;

/// What stands in for a value that is absent.
const NONE: &str = "-";

/// The separator of a key and its value.
const KEY_SEPARATOR: &str = ": ";

/// The separator of the certificates on a path.
const PATH_SEPARATOR: &str = " > ";

/// Parsed `document verify FILE [FILE ...]` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentVerifyArgs {
    /// The documents to judge, in command-line order.
    pub inputs: Vec<PathBuf>,
}

impl DocumentVerifyArgs {
    /// Execute the verb: print each document's records, exit by the
    /// aggregate verdict.
    #[must_use]
    pub fn run(self, verbose: bool) -> std::process::ExitCode {
        let now = crate::card_check::now_date_time();
        let mut outcomes = Vec::new();
        let mut records = Vec::new();
        for path in &self.inputs {
            let file = path.display().to_string();
            match crate::document_verify::verify_file(path, now) {
                Ok(report) => {
                    records.extend(report_records(&file, &report, verbose));
                    outcomes.push(if report.is_valid() {
                        FileOutcome::Valid
                    } else {
                        FileOutcome::Rejected
                    });
                }
                Err(error) => {
                    records.push(error_record(&file, &error));
                    outcomes.push(FileOutcome::Unjudged);
                }
            }
        }
        print!("{}", join_records(&records));
        exit_status(&outcomes).into()
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

/// What one file came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileOutcome {
    /// Every signature is valid.
    Valid,
    /// A signature is not valid, revoked or unsupported.
    Rejected,
    /// The file could not be judged.
    Unjudged,
}

/// The exit status of a run: a file that could not be judged
/// outranks a rejected signature, which outranks success.
fn exit_status(outcomes: &[FileOutcome]) -> ExitStatus {
    if outcomes.contains(&FileOutcome::Unjudged) {
        ExitStatus::RuntimeFailure
    } else if outcomes.contains(&FileOutcome::Rejected) {
        ExitStatus::VerifyFailed
    } else {
        ExitStatus::Ok
    }
}

/// The key of one record line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    /// The file as named on the command line.
    File,
    /// Why the file could not be judged.
    Error,
    /// The signer certificate's subject name.
    Signer,
    /// The proven time of the signature.
    Signed,
    /// The verdict.
    Verdict,
    /// One cause of a negative verdict.
    Reason,
    /// The revocation basis.
    Revocation,
    /// Whether the signed content is unchanged.
    Intact,
    /// Whether the signature verifies.
    Signature,
    /// The signer's certificate path.
    Chain,
    /// The signing time the signature claims.
    Claimed,
    /// One signature timestamp.
    Timestamp,
    /// The path of the timestamp on the line before.
    TimestampChain,
    /// One document timestamp covering the signature.
    DocumentTimestamp,
}

impl Key {
    /// The key as printed.
    const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Error => "error",
            Self::Signer => "signer",
            Self::Signed => "signed",
            Self::Verdict => "verdict",
            Self::Reason => "reason",
            Self::Revocation => "revocation",
            Self::Intact => "intact",
            Self::Signature => "signature",
            Self::Chain => "chain",
            Self::Claimed => "claimed",
            Self::Timestamp => "timestamp",
            Self::TimestampChain => "timestamp-chain",
            Self::DocumentTimestamp => "document-timestamp",
        }
    }
}

/// The verdict on one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Every check holds and nothing says the signer is revoked.
    Valid,
    /// At least one check fails.
    NotValid,
    /// A verified answer says the signer is revoked.
    Revoked,
    /// The signature's profile is not implemented.
    Unsupported,
}

impl Verdict {
    /// The verdict as printed.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::NotValid => "not valid",
            Self::Revoked => "revoked",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One cause of a negative verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// The signed content no longer matches.
    DocumentChanged,
    /// The signature does not verify.
    SignatureInvalid,
    /// The signer does not chain to a trust anchor.
    ChainUnverified,
    /// No verified timestamp proves the signature's time.
    NoProvenTime,
    /// The signature's profile is not implemented.
    ProfileNotSupported,
}

impl Reason {
    /// The reason as printed.
    const fn as_str(self) -> &'static str {
        match self {
            Self::DocumentChanged => "document changed",
            Self::SignatureInvalid => "signature invalid",
            Self::ChainUnverified => "certificate chain unverified",
            Self::NoProvenTime => "no proven time",
            Self::ProfileNotSupported => "profile not supported",
        }
    }
}

/// One record: `key: value` lines, each ending in a newline.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Record(String);

impl Record {
    /// Append one `key: value` line, every control character in the
    /// value written as `\x` and two hexadecimal digits so the value
    /// stays on its line.
    fn line(&mut self, key: Key, value: impl Display) {
        self.0.push_str(key.as_str());
        self.0.push_str(KEY_SEPARATOR);
        for character in value.to_string().chars() {
            if character.is_control() {
                self.0.push_str(&format!("\\x{:02x}", u32::from(character)));
            } else {
                self.0.push(character);
            }
        }
        self.0.push('\n');
    }
}

/// The records, one blank line between each.
fn join_records(records: &[Record]) -> String {
    records
        .iter()
        .map(|record| record.0.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The record of a file that could not be judged.
fn error_record(file: &str, error: &DocumentVerifyError) -> Record {
    let mut record = Record::default();
    record.line(Key::File, file);
    match error {
        DocumentVerifyError::Read { source, .. } => record.line(Key::Error, source),
        DocumentVerifyError::Failure { failure, .. } => record.line(Key::Error, failure),
    }
    record
}

/// One record per signature of `report`.
fn report_records(file: &str, report: &DocumentReport, verbose: bool) -> Vec<Record> {
    report
        .signatures
        .iter()
        .map(|entry| match entry {
            SignatureEntry::Judged(signature) => judged_record(file, signature, verbose),
            SignatureEntry::Unsupported(signature) => unsupported_record(file, signature),
        })
        .collect()
}

/// The record of a signature of an unsupported profile.
fn unsupported_record(file: &str, signature: &UnsupportedSignature) -> Record {
    let mut record = Record::default();
    record.line(Key::File, file);
    record.line(
        Key::Signer,
        signature.signer.as_ref().map_or(NONE, signer_name),
    );
    record.line(Key::Signed, NONE);
    record.line(Key::Verdict, Verdict::Unsupported.as_str());
    record.line(Key::Reason, Reason::ProfileNotSupported.as_str());
    record
}

/// The record of a judged signature; `verbose` adds every fact
/// behind the verdict.
fn judged_record(file: &str, signature: &SignatureReport, verbose: bool) -> Record {
    let mut record = Record::default();
    record.line(Key::File, file);
    record.line(Key::Signer, signer_name(&signature.signer));
    record.line(Key::Signed, time_or_none(signature.proof_of_existence));
    let verdict = verdict(signature);
    record.line(Key::Verdict, verdict.as_str());
    if verdict == Verdict::NotValid {
        for reason in reasons(signature) {
            record.line(Key::Reason, reason.as_str());
        }
    }
    if !verbose {
        if verdict == Verdict::Valid && signature.revocation == Revocation::Unavailable {
            record.line(Key::Revocation, "not checked");
        }
        return record;
    }
    record.line(Key::Intact, yes_no(signature.document_intact));
    record.line(Key::Signature, yes_no(signature.signature_valid));
    record.line(Key::Chain, path(&signature.chain));
    record.line(Key::Claimed, time_or_none(signature.claimed_signing_time));
    for timestamp in &signature.signature_timestamps {
        match timestamp {
            SignatureTimestamp::Proven {
                generated_at,
                chain,
            } => {
                record.line(Key::Timestamp, format!("{generated_at} proven"));
                record.line(Key::TimestampChain, path(chain));
            }
            SignatureTimestamp::Unproven { claimed_at, chain } => {
                record.line(
                    Key::Timestamp,
                    format!("{} unproven", time_or_none(*claimed_at)),
                );
                record.line(
                    Key::TimestampChain,
                    chain.as_ref().map_or_else(|| NONE.to_owned(), path),
                );
            }
        }
    }
    record.line(
        Key::Revocation,
        match signature.revocation {
            Revocation::Good { checked_at } => format!("good {checked_at}"),
            Revocation::Revoked { revoked_at } => format!("revoked {revoked_at}"),
            Revocation::Unavailable => "not checked".to_owned(),
        },
    );
    for stamped in &signature.document_timestamps {
        record.line(
            Key::DocumentTimestamp,
            match stamped {
                DocumentTimestamp::Proven { generated_at } => format!("{generated_at} proven"),
                DocumentTimestamp::Unproven { claimed_at } => {
                    format!("{} unproven", time_or_none(*claimed_at))
                }
            },
        );
    }
    record
}

/// The signer's name as the certificate spells it, or `-` when it is
/// empty.
fn signer_name(signer: &SignerIdentity) -> &str {
    let name = signer.name.as_str();
    if name.is_empty() { NONE } else { name }
}

/// The verdict the facts reach: revoked first, then not valid.
fn verdict(signature: &SignatureReport) -> Verdict {
    if matches!(signature.revocation, Revocation::Revoked { .. }) {
        Verdict::Revoked
    } else if signature.is_valid() {
        Verdict::Valid
    } else {
        Verdict::NotValid
    }
}

/// Every cause of a not valid verdict, in check order.
fn reasons(signature: &SignatureReport) -> Vec<Reason> {
    [
        (signature.document_intact, Reason::DocumentChanged),
        (signature.signature_valid, Reason::SignatureInvalid),
        (signature.chain_verified, Reason::ChainUnverified),
        (signature.timestamps_valid, Reason::NoProvenTime),
    ]
    .into_iter()
    .filter_map(|(holds, reason)| (!holds).then_some(reason))
    .collect()
}

/// A path's subject names, nearest first, joined by ` > `; a path
/// that does not end in a trust anchor ends in ` > -`. A `>` in a
/// common name is written `\>`, as RFC 4514 already writes it in a
/// distinguished name, so ` > ` only ever separates.
fn path(path: &CertificatePath) -> String {
    let mut names: Vec<String> = path
        .certificates
        .iter()
        .map(|certificate| chain_name(SubjectName::of(certificate)))
        .collect();
    if !path.anchored {
        names.push(NONE.to_owned());
    }
    names.join(PATH_SEPARATOR)
}

/// One name on a path line: a common name with every `>` written
/// `\>`, a distinguished name as RFC 4514 escapes it.
fn chain_name(name: SubjectName) -> String {
    match name {
        SubjectName::CommonName(name) => name.replace('>', r"\>"),
        SubjectName::Distinguished(name) => name,
    }
}

/// The time, or `-`.
fn time_or_none(time: Option<DateTime>) -> String {
    time.map_or_else(|| NONE.to_owned(), |time| time.to_string())
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
    use refineid_lib_core::document::DocumentFailure;
    use refineid_lib_core::x509::OwnedCert;

    /// A public DVV intermediate, standing in for every certificate.
    const INTERMEDIATE_DER: &[u8] =
        include_bytes!("../../test-vectors/fineid-intermediate-01-citizen-g4e.der");
    /// The public DVV root that issued it.
    const ROOT_DER: &[u8] = include_bytes!("../../trust-anchors/dvv-gov-root-ca-g3-ecc.der");
    /// The signer's common name.
    const SIGNER: &str = "SURNAME GIVEN 12345678X";
    /// A name carrying a newline, a carriage return and NUL.
    const NAME_WITH_CONTROLS: &str = "SURNAME\nGIVEN\r\0";
    /// A common name carrying the path separator.
    const NAME_WITH_ARROW: &str = "Synthetic > CA";
    /// A distinguished name RFC 4514 already escaped.
    const ESCAPED_DISTINGUISHED: &str = r"O=Synthetic \> CA,C=FI";
    /// The file as named.
    const FILE: &str = "/documents/a.pdf";
    /// A second file.
    const OTHER_FILE: &str = "/documents/b.asice";
    /// The year and month of every fixture time.
    const YEAR: u16 = 2026;
    /// See [`YEAR`].
    const MONTH: u8 = 6;
    /// The hour of every fixture time.
    const HOUR: u8 = 12;
    /// The claimed signing day.
    const CLAIMED: u8 = 9;
    /// The signature timestamp day.
    const STAMPED: u8 = 10;
    /// The revocation answer day.
    const ANSWERED: u8 = 11;
    /// The document timestamp day.
    const ARCHIVED: u8 = 12;

    /// Noon on `day` of the fixture month.
    fn at(day: u8) -> Result<DateTime, Box<dyn core::error::Error>> {
        Ok(DateTime::new(YEAR, MONTH, day, HOUR, 0, 0)?)
    }

    /// The DVV intermediate and root, anchored or not.
    fn dvv_path(anchored: bool) -> Result<CertificatePath, Box<dyn core::error::Error>> {
        let mut certificates = vec![OwnedCert::from_der(INTERMEDIATE_DER)?];
        if anchored {
            certificates.push(OwnedCert::from_der(ROOT_DER)?);
        }
        Ok(CertificatePath {
            certificates,
            anchored,
        })
    }

    /// A valid signature, timestamped and answered good.
    fn valid() -> Result<SignatureReport, Box<dyn core::error::Error>> {
        Ok(SignatureReport {
            signer: SignerIdentity {
                name: SubjectName::CommonName(SIGNER.to_owned()),
                identifier: None,
            },
            signer_certificate: OwnedCert::from_der(INTERMEDIATE_DER)?,
            chain: dvv_path(true)?,
            document_intact: true,
            signature_valid: true,
            chain_verified: true,
            claimed_signing_time: Some(at(CLAIMED)?),
            proof_of_existence: Some(at(STAMPED)?),
            signature_timestamps: vec![SignatureTimestamp::Proven {
                generated_at: at(STAMPED)?,
                chain: dvv_path(true)?,
            }],
            document_timestamps: Vec::new(),
            timestamps_valid: true,
            covers_whole_document: true,
            revocation: Revocation::Good {
                checked_at: at(ANSWERED)?,
            },
        })
    }

    /// The default records of one report.
    fn rendered(signatures: Vec<SignatureEntry>, verbose: bool) -> String {
        join_records(&report_records(
            FILE,
            &DocumentReport { signatures },
            verbose,
        ))
    }

    #[test]
    fn a_valid_signature_is_one_record() -> TestResult {
        check(
            &rendered(vec![SignatureEntry::Judged(valid()?)], false).as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: valid
",
            "record",
        )
    }

    #[test]
    fn every_reason_of_a_not_valid_signature_is_a_line() -> TestResult {
        let mut signature = valid()?;
        signature.document_intact = false;
        signature.timestamps_valid = false;
        signature.proof_of_existence = None;
        check(
            &rendered(vec![SignatureEntry::Judged(signature)], false).as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: -
verdict: not valid
reason: document changed
reason: no proven time
",
            "record",
        )
    }

    #[test]
    fn a_revoked_signer_is_revoked_without_reasons() -> TestResult {
        let mut signature = valid()?;
        signature.chain_verified = false;
        signature.revocation = Revocation::Revoked {
            revoked_at: at(ANSWERED)?,
        };
        check(
            &rendered(vec![SignatureEntry::Judged(signature)], false).as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: revoked
",
            "record",
        )
    }

    #[test]
    fn an_unsupported_signature_names_its_reason() -> TestResult {
        check(
            &rendered(
                vec![SignatureEntry::Unsupported(UnsupportedSignature {
                    signer: None,
                    profile: "PDF signature subfilter",
                })],
                true,
            )
            .as_str(),
            &"\
file: /documents/a.pdf
signer: -
signed: -
verdict: unsupported
reason: profile not supported
",
            "record",
        )
    }

    #[test]
    fn an_unchecked_revocation_follows_a_valid_verdict() -> TestResult {
        let mut signature = valid()?;
        signature.revocation = Revocation::Unavailable;
        check(
            &rendered(vec![SignatureEntry::Judged(signature)], false).as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: valid
revocation: not checked
",
            "record",
        )
    }

    #[test]
    fn two_signatures_are_two_records() -> TestResult {
        let mut second = valid()?;
        second.signature_valid = false;
        check(
            &rendered(
                vec![
                    SignatureEntry::Judged(valid()?),
                    SignatureEntry::Judged(second),
                ],
                false,
            )
            .as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: valid

file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: not valid
reason: signature invalid
",
            "records",
        )
    }

    #[test]
    fn two_files_are_records_in_command_line_order() -> TestResult {
        let report = DocumentReport {
            signatures: vec![SignatureEntry::Judged(valid()?)],
        };
        let mut records = report_records(FILE, &report, false);
        records.push(error_record(
            OTHER_FILE,
            &DocumentVerifyError::Failure {
                path: PathBuf::from(OTHER_FILE),
                failure: DocumentFailure::NoSignatures,
            },
        ));
        check(
            &join_records(&records).as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: valid

file: /documents/b.asice
error: the document carries no signatures
",
            "records",
        )
    }

    #[test]
    fn a_file_that_cannot_be_judged_is_a_file_and_an_error() -> TestResult {
        let record = error_record(
            FILE,
            &DocumentVerifyError::Failure {
                path: PathBuf::from(FILE),
                failure: DocumentFailure::NotASignedDocument,
            },
        );
        check(
            &join_records(&[record]).as_str(),
            &"\
file: /documents/a.pdf
error: not a signed document
",
            "record",
        )
    }

    #[test]
    fn verbose_adds_every_fact_behind_the_verdict() -> TestResult {
        let mut signature = valid()?;
        signature
            .signature_timestamps
            .push(SignatureTimestamp::Unproven {
                claimed_at: Some(at(STAMPED)?),
                chain: Some(dvv_path(false)?),
            });
        signature
            .signature_timestamps
            .push(SignatureTimestamp::Unproven {
                claimed_at: None,
                chain: None,
            });
        signature.timestamps_valid = false;
        signature.document_timestamps = vec![
            DocumentTimestamp::Proven {
                generated_at: at(ARCHIVED)?,
            },
            DocumentTimestamp::Unproven {
                claimed_at: Some(at(ARCHIVED)?),
            },
        ];
        check(
            &rendered(vec![SignatureEntry::Judged(signature)], true).as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: not valid
reason: no proven time
intact: yes
signature: yes
chain: DVV Citizen Certificates - G4E > DVV Gov. Root CA - G3 ECC
claimed: 2026-06-09T12:00:00Z
timestamp: 2026-06-10T12:00:00Z proven
timestamp-chain: DVV Citizen Certificates - G4E > DVV Gov. Root CA - G3 ECC
timestamp: 2026-06-10T12:00:00Z unproven
timestamp-chain: DVV Citizen Certificates - G4E > -
timestamp: - unproven
timestamp-chain: -
revocation: good 2026-06-11T12:00:00Z
document-timestamp: 2026-06-12T12:00:00Z proven
document-timestamp: 2026-06-12T12:00:00Z unproven
",
            "record",
        )
    }

    #[test]
    fn an_unanchored_path_ends_in_a_dash() -> TestResult {
        let mut signature = valid()?;
        signature.chain = dvv_path(false)?;
        signature.chain_verified = false;
        signature.signature_timestamps = vec![SignatureTimestamp::Proven {
            generated_at: at(STAMPED)?,
            chain: dvv_path(false)?,
        }];
        signature.claimed_signing_time = None;
        signature.revocation = Revocation::Unavailable;
        check(
            &rendered(vec![SignatureEntry::Judged(signature)], true).as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: not valid
reason: certificate chain unverified
intact: yes
signature: yes
chain: DVV Citizen Certificates - G4E > -
claimed: -
timestamp: 2026-06-10T12:00:00Z proven
timestamp-chain: DVV Citizen Certificates - G4E > -
revocation: not checked
",
            "record",
        )
    }

    #[test]
    fn a_revoked_record_carries_the_revocation_time_with_v() -> TestResult {
        let mut signature = valid()?;
        signature.revocation = Revocation::Revoked {
            revoked_at: at(ANSWERED)?,
        };
        let out = rendered(vec![SignatureEntry::Judged(signature)], true);
        check_true(
            out.contains("\nverdict: revoked\n")
                && out.contains("\nrevocation: revoked 2026-06-11T12:00:00Z\n"),
            "revoked with its time",
        )
    }

    #[test]
    fn a_not_valid_verdict_always_names_a_reason() -> TestResult {
        /// Both outcomes of one check.
        const OUTCOMES: [bool; 2] = [false, true];
        for intact in OUTCOMES {
            for signed in OUTCOMES {
                for chained in OUTCOMES {
                    for stamped in OUTCOMES {
                        let mut signature = valid()?;
                        signature.document_intact = intact;
                        signature.signature_valid = signed;
                        signature.chain_verified = chained;
                        signature.timestamps_valid = stamped;
                        signature.covers_whole_document = false;
                        let not_valid = verdict(&signature) == Verdict::NotValid;
                        check_true(
                            !not_valid || !reasons(&signature).is_empty(),
                            "a not valid verdict has a reason",
                        )?;
                        check_true(
                            not_valid != signature.is_valid(),
                            "covering the whole document is reported, not judged",
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn a_rejected_file_and_an_unjudged_file_exit_seventy_in_either_order() -> TestResult {
        check(
            &exit_status(&[FileOutcome::Rejected, FileOutcome::Unjudged]),
            &ExitStatus::RuntimeFailure,
            "rejected then unjudged",
        )?;
        check(
            &exit_status(&[FileOutcome::Unjudged, FileOutcome::Rejected]),
            &ExitStatus::RuntimeFailure,
            "unjudged then rejected",
        )?;
        check(
            &exit_status(&[FileOutcome::Valid, FileOutcome::Rejected]),
            &ExitStatus::VerifyFailed,
            "valid then rejected",
        )?;
        check(
            &exit_status(&[FileOutcome::Rejected, FileOutcome::Valid]),
            &ExitStatus::VerifyFailed,
            "rejected then valid",
        )?;
        check(
            &exit_status(&[FileOutcome::Valid, FileOutcome::Valid]),
            &ExitStatus::Ok,
            "all valid",
        )
    }

    #[test]
    fn control_characters_stay_on_their_line() -> TestResult {
        let mut signature = valid()?;
        signature.signer.name = SubjectName::CommonName(NAME_WITH_CONTROLS.to_owned());
        let out = rendered(vec![SignatureEntry::Judged(signature)], false);
        check(
            &out.lines().nth(1),
            &Some(r"signer: SURNAME\x0aGIVEN\x0d\x00"),
            "escaped signer line",
        )?;
        check(&out.lines().count(), &4_usize, "four lines")
    }

    #[test]
    fn a_greater_than_sign_in_a_common_name_is_escaped_on_a_path() -> TestResult {
        check(
            &chain_name(SubjectName::CommonName(NAME_WITH_ARROW.to_owned())).as_str(),
            &r"Synthetic \> CA",
            "escaped common name",
        )?;
        check(
            &chain_name(SubjectName::Distinguished(ESCAPED_DISTINGUISHED.to_owned())).as_str(),
            &ESCAPED_DISTINGUISHED,
            "distinguished name as RFC 4514 wrote it",
        )
    }

    #[test]
    fn no_line_is_indented_or_tabbed() -> TestResult {
        let out = rendered(vec![SignatureEntry::Judged(valid()?)], true);
        check_true(
            out.lines()
                .all(|line| !line.starts_with(' ') && !line.contains('\t') && line.contains(": ")),
            "flush key: value lines",
        )
    }

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
