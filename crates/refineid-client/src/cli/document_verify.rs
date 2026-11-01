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

use refineid_doc_sign::NameExt as _;
use refineid_doc_sign::crl::CrlReason;
use refineid_doc_sign::verification::{
    CertificationPath, DocumentReport, Revocation, SignatureOutcome, SignatureReport, SignatureRow,
    TimestampReport,
};
use refineid_doc_sign::x509::{DateTime, OwnedCert};

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
  countersigns: on an XAdES counter-signature only, the common name
    of the signer it counter-signs; its verdict leaves the exit
    status as it is
  signed: the time a timestamp proves, or - when the signature is
    judged as of now
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
        let now = refineid_doc_sign::now_date_time();
        let mut outcomes = Vec::new();
        let mut records = Vec::new();
        for path in &self.inputs {
            let file = path.display().to_string();
            match crate::document_verify::verify_file(path, now) {
                Ok(report) => {
                    records.extend(
                        views(&report)
                            .iter()
                            .map(|view| view.record(&file, verbose)),
                    );
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
    /// The signer an `XAdES` counter-signature counter-signs.
    Countersigns,
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
            Self::Countersigns => "countersigns",
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

/// What one signature row comes to, ready to print.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SignatureView {
    /// The signer's name, or `-`.
    signer: String,
    /// For a counter-signature, the name of the signer it
    /// counter-signs, or `-`.
    countersigns: Option<String>,
    /// The judgement, or why there is none.
    judgement: Judgement,
}

/// A row judged, or not.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Judgement {
    /// The signature's profile is not implemented.
    Unsupported,
    /// The facts behind the verdict.
    Judged(Box<Facts>),
}

/// Every fact a judged record prints.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Facts {
    /// The proven time.
    signed: Option<DateTime>,
    /// The verdict.
    verdict: Verdict,
    /// Whether the signed content is unchanged.
    intact: bool,
    /// Whether the signature verifies.
    signature: bool,
    /// Whether the signer chains to a trust anchor.
    chained: bool,
    /// The signer's path line.
    chain: String,
    /// The signing time the signature claims.
    claimed: Option<DateTime>,
    /// One `timestamp` and `timestamp-chain` line pair per signature
    /// or archive timestamp.
    timestamps: Vec<(String, String)>,
    /// The revocation status.
    revocation: Revocation,
    /// One line per document timestamp covering the signature.
    document_timestamps: Vec<String>,
}

/// The view of every row of `report`, in document order.
fn views(report: &DocumentReport) -> Vec<SignatureView> {
    let rows = report.rows();
    rows.iter().map(|row| view(rows, row)).collect()
}

/// The view of `row`, one of `rows`.
fn view(rows: &[SignatureRow], row: &SignatureRow) -> SignatureView {
    let countersigns = row.counter_signs().map(|index| {
        rows.get(index)
            .and_then(SignatureRow::signer)
            .map_or_else(|| NONE.to_owned(), |signer| name_or_none(signer.name()))
    });
    let signer = row
        .signer()
        .map_or_else(|| NONE.to_owned(), |signer| name_or_none(signer.name()));
    let judgement = match row.outcome() {
        SignatureOutcome::Judged(report) => Judgement::Judged(Box::new(facts(report))),
        SignatureOutcome::Unsupported { .. } => Judgement::Unsupported,
    };
    SignatureView {
        signer,
        countersigns,
        judgement,
    }
}

/// The facts of a judged signature.
fn facts(report: &SignatureReport) -> Facts {
    let timestamps = report
        .timestamps()
        .iter()
        .chain(
            report
                .archive_timestamps()
                .iter()
                .map(|archive| archive.timestamp()),
        )
        .map(timestamp_lines)
        .collect();
    Facts {
        signed: report.proof_of_existence(),
        verdict: verdict(report),
        intact: report.document_intact(),
        signature: report.signature_valid(),
        chained: report.chain_verified(),
        chain: path(&[], report.chain()),
        claimed: report.claimed_signing_time(),
        timestamps,
        revocation: report.revocation(),
        document_timestamps: report
            .covering_document_timestamps()
            .iter()
            .map(|stamped| proven_or_not(stamped.timestamp()))
            .collect(),
    }
}

/// The `timestamp` and `timestamp-chain` values of one token: its time
/// and whether it is proven, and its signer's path, signer first.
fn timestamp_lines(timestamp: &TimestampReport) -> (String, String) {
    let chain = timestamp.authority().map_or_else(
        || NONE.to_owned(),
        |authority| path(core::slice::from_ref(authority.signer()), authority.chain()),
    );
    (proven_or_not(timestamp), chain)
}

/// A token's time with `proven` when it is anchored, else the time it
/// claims, or `-`, with `unproven`.
fn proven_or_not(timestamp: &TimestampReport) -> String {
    timestamp.proven_time().map_or_else(
        || format!("{} unproven", time_or_none(timestamp.claimed_time())),
        |time| format!("{time} proven"),
    )
}

impl SignatureView {
    /// The record of this signature in `file`; `verbose` adds every
    /// fact behind the verdict.
    fn record(&self, file: &str, verbose: bool) -> Record {
        let mut record = Record::default();
        record.line(Key::File, file);
        record.line(Key::Signer, &self.signer);
        if let Some(countersigned) = &self.countersigns {
            record.line(Key::Countersigns, countersigned);
        }
        let facts = match &self.judgement {
            Judgement::Unsupported => {
                record.line(Key::Signed, NONE);
                record.line(Key::Verdict, Verdict::Unsupported.as_str());
                record.line(Key::Reason, Reason::ProfileNotSupported.as_str());
                return record;
            }
            Judgement::Judged(facts) => facts,
        };
        record.line(Key::Signed, time_or_none(facts.signed));
        record.line(Key::Verdict, facts.verdict.as_str());
        if facts.verdict == Verdict::NotValid {
            for reason in facts.reasons() {
                record.line(Key::Reason, reason.as_str());
            }
        }
        if !verbose {
            if facts.verdict == Verdict::Valid && facts.revocation == Revocation::Unavailable {
                record.line(Key::Revocation, "not checked");
            }
            return record;
        }
        record.line(Key::Intact, yes_no(facts.intact));
        record.line(Key::Signature, yes_no(facts.signature));
        record.line(Key::Chain, &facts.chain);
        record.line(Key::Claimed, time_or_none(facts.claimed));
        for (timestamp, chain) in &facts.timestamps {
            record.line(Key::Timestamp, timestamp);
            record.line(Key::TimestampChain, chain);
        }
        record.line(
            Key::Revocation,
            match facts.revocation {
                Revocation::Good { at } => format!("good {at}"),
                Revocation::Revoked { at, reason } => {
                    format!("revoked {at} {}", reason_name(reason))
                }
                Revocation::Unavailable => "not checked".to_owned(),
            },
        );
        for stamped in &facts.document_timestamps {
            record.line(Key::DocumentTimestamp, stamped);
        }
        record
    }
}

impl Facts {
    /// Every cause of a not valid verdict, in check order.
    fn reasons(&self) -> Vec<Reason> {
        [
            (self.intact, Reason::DocumentChanged),
            (self.signature, Reason::SignatureInvalid),
            (self.chained, Reason::ChainUnverified),
        ]
        .into_iter()
        .filter_map(|(holds, reason)| (!holds).then_some(reason))
        .collect()
    }
}

/// A name as the certificate spells it, or `-` when it is empty.
fn name_or_none(name: &str) -> String {
    if name.is_empty() {
        NONE.to_owned()
    } else {
        name.to_owned()
    }
}

/// The verdict the facts reach: revoked first, then not valid.
fn verdict(signature: &SignatureReport) -> Verdict {
    if signature
        .revocation()
        .revoked_before(signature.proof_of_existence())
    {
        Verdict::Revoked
    } else if signature.is_valid() {
        Verdict::Valid
    } else {
        Verdict::NotValid
    }
}

/// `leading` and then `path`'s certificates, nearest first, by subject
/// name, joined by ` > `; a path that does not end in a trust anchor
/// ends in ` > -`.
fn path(leading: &[OwnedCert], path: &CertificationPath) -> String {
    let mut names: Vec<String> = leading
        .iter()
        .chain(path.certificates())
        .map(chain_name)
        .collect();
    if !path.is_anchored() {
        names.push(NONE.to_owned());
    }
    names.join(PATH_SEPARATOR)
}

/// One name on a path line: the common name with every `>` written
/// `\>`, as RFC 4514 already writes it in a distinguished name, so
/// ` > ` only ever separates; the distinguished name as RFC 4514
/// escapes it when there is no common name.
fn chain_name(certificate: &OwnedCert) -> String {
    let subject = certificate.view().subject;
    subject.common_name().map_or_else(
        || subject.rfc4514().unwrap_or_default(),
        |name| name.as_str().replace('>', r"\>"),
    )
}

/// The revocation reason as RFC 5280 sec.5.3.1 names it. An answer
/// that states none, or a code RFC 5280 does not define, is
/// `unspecified`: RFC 5280 has the extension left out in place of that
/// code.
const fn reason_name(reason: Option<CrlReason>) -> &'static str {
    match reason {
        None | Some(CrlReason::Unspecified) => "unspecified",
        Some(CrlReason::KeyCompromise) => "keyCompromise",
        Some(CrlReason::CaCompromise) => "cACompromise",
        Some(CrlReason::AffiliationChanged) => "affiliationChanged",
        Some(CrlReason::Superseded) => "superseded",
        Some(CrlReason::CessationOfOperation) => "cessationOfOperation",
        Some(CrlReason::CertificateHold) => "certificateHold",
        Some(CrlReason::RemoveFromCrl) => "removeFromCRL",
        Some(CrlReason::PrivilegeWithdrawn) => "privilegeWithdrawn",
        Some(CrlReason::AaCompromise) => "aACompromise",
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
    use refineid_doc_sign::verification::DocumentFailure;

    /// A public DVV intermediate, standing in for every certificate.
    const INTERMEDIATE_DER: &[u8] =
        include_bytes!("../../test-vectors/fineid-intermediate-01-citizen-g4e.der");
    /// The signer's common name.
    const SIGNER: &str = "SURNAME GIVEN 12345678X";
    /// A name carrying a newline, a carriage return and NUL.
    const NAME_WITH_CONTROLS: &str = "SURNAME\nGIVEN\r\0";
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
    /// The day a revoked signer was revoked, before the timestamp.
    const REVOKED: u8 = 8;
    /// The claimed signing day.
    const CLAIMED: u8 = 9;
    /// The signature timestamp day.
    const STAMPED: u8 = 10;
    /// The revocation answer day.
    const ANSWERED: u8 = 11;
    /// The document timestamp day.
    const ARCHIVED: u8 = 12;
    /// The path line of the DVV intermediate under its root.
    const DVV_PATH: &str = "DVV Citizen Certificates - G4E > DVV Gov. Root CA - G3 ECC";

    /// Noon on `day` of the fixture month.
    fn at(day: u8) -> Result<DateTime, Box<dyn core::error::Error>> {
        Ok(DateTime::new(YEAR, MONTH, day, HOUR, 0, 0)?)
    }

    /// The facts of a valid signature, timestamped and answered good.
    fn valid() -> Result<Facts, Box<dyn core::error::Error>> {
        Ok(Facts {
            signed: Some(at(STAMPED)?),
            verdict: Verdict::Valid,
            intact: true,
            signature: true,
            chained: true,
            chain: DVV_PATH.to_owned(),
            claimed: Some(at(CLAIMED)?),
            timestamps: vec![(format!("{} proven", at(STAMPED)?), DVV_PATH.to_owned())],
            revocation: Revocation::Good { at: at(ANSWERED)? },
            document_timestamps: Vec::new(),
        })
    }

    /// A signature over the document by [`SIGNER`] with `facts`.
    fn signed(facts: Facts) -> SignatureView {
        SignatureView {
            signer: SIGNER.to_owned(),
            countersigns: None,
            judgement: Judgement::Judged(Box::new(facts)),
        }
    }

    /// The records of `views`, joined.
    fn rendered(views: &[SignatureView], verbose: bool) -> String {
        join_records(
            &views
                .iter()
                .map(|view| view.record(FILE, verbose))
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn a_valid_signature_is_one_record() -> TestResult {
        check(
            &rendered(&[signed(valid()?)], false).as_str(),
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
        let mut facts = valid()?;
        facts.verdict = Verdict::NotValid;
        facts.intact = false;
        facts.chained = false;
        check(
            &rendered(&[signed(facts)], false).as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: not valid
reason: document changed
reason: certificate chain unverified
",
            "record",
        )
    }

    #[test]
    fn an_untimestamped_signature_is_valid_with_no_signed_time() -> TestResult {
        let mut facts = valid()?;
        facts.signed = None;
        facts.timestamps = Vec::new();
        check(
            &rendered(&[signed(facts)], false).as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: -
verdict: valid
",
            "record",
        )
    }

    #[test]
    fn a_revoked_line_names_the_reason_as_rfc_5280_does() -> TestResult {
        for (reason, name) in [
            (Some(CrlReason::KeyCompromise), "keyCompromise"),
            (Some(CrlReason::CaCompromise), "cACompromise"),
            (Some(CrlReason::AffiliationChanged), "affiliationChanged"),
            (Some(CrlReason::Superseded), "superseded"),
            (
                Some(CrlReason::CessationOfOperation),
                "cessationOfOperation",
            ),
            (Some(CrlReason::CertificateHold), "certificateHold"),
            (Some(CrlReason::RemoveFromCrl), "removeFromCRL"),
            (Some(CrlReason::PrivilegeWithdrawn), "privilegeWithdrawn"),
            (Some(CrlReason::AaCompromise), "aACompromise"),
            (Some(CrlReason::Unspecified), "unspecified"),
            (None, "unspecified"),
        ] {
            let mut facts = valid()?;
            facts.revocation = Revocation::Revoked {
                at: at(REVOKED)?,
                reason,
            };
            let out = rendered(&[signed(facts)], true);
            check_true(
                out.contains(&format!(
                    "\nrevocation: revoked 2026-06-08T12:00:00Z {name}\n"
                )),
                name,
            )?;
        }
        Ok(())
    }

    #[test]
    fn a_revoked_signer_is_revoked_without_reasons() -> TestResult {
        let mut facts = valid()?;
        facts.verdict = Verdict::Revoked;
        facts.chained = false;
        facts.revocation = Revocation::Revoked {
            at: at(REVOKED)?,
            reason: None,
        };
        check(
            &rendered(&[signed(facts)], false).as_str(),
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
                &[SignatureView {
                    signer: NONE.to_owned(),
                    countersigns: None,
                    judgement: Judgement::Unsupported,
                }],
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
    fn a_counter_signature_names_the_signer_it_countersigns() -> TestResult {
        let counter = SignatureView {
            signer: "SECOND SIGNER 87654321Y".to_owned(),
            countersigns: Some(SIGNER.to_owned()),
            judgement: Judgement::Judged(Box::new(valid()?)),
        };
        check(
            &rendered(&[signed(valid()?), counter], false).as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: valid

file: /documents/a.pdf
signer: SECOND SIGNER 87654321Y
countersigns: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: valid
",
            "records",
        )
    }

    #[test]
    fn an_unchecked_revocation_follows_a_valid_verdict() -> TestResult {
        let mut facts = valid()?;
        facts.revocation = Revocation::Unavailable;
        check(
            &rendered(&[signed(facts)], false).as_str(),
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
    fn two_files_are_records_in_command_line_order() -> TestResult {
        let mut records = vec![signed(valid()?).record(FILE, false)];
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
        let mut facts = valid()?;
        facts.timestamps.push((
            format!("{} unproven", at(STAMPED)?),
            "DVV Citizen Certificates - G4E > -".to_owned(),
        ));
        facts
            .timestamps
            .push(("- unproven".to_owned(), NONE.to_owned()));
        facts.document_timestamps = vec![
            format!("{} proven", at(ARCHIVED)?),
            format!("{} unproven", at(ARCHIVED)?),
        ];
        check(
            &rendered(&[signed(facts)], true).as_str(),
            &"\
file: /documents/a.pdf
signer: SURNAME GIVEN 12345678X
signed: 2026-06-10T12:00:00Z
verdict: valid
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
    fn a_path_names_each_certificate_and_an_unanchored_one_ends_in_a_dash() -> TestResult {
        let intermediate = OwnedCert::from_der(INTERMEDIATE_DER)?;
        check(
            &path(&[], &CertificationPath::Partial(vec![intermediate.clone()])).as_str(),
            &"DVV Citizen Certificates - G4E > -",
            "partial",
        )?;
        check(
            &path(
                core::slice::from_ref(&intermediate),
                &CertificationPath::Anchored(Vec::new()),
            )
            .as_str(),
            &"DVV Citizen Certificates - G4E",
            "a leading signer on an anchored path",
        )
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
        let mut view = signed(valid()?);
        view.signer = NAME_WITH_CONTROLS.to_owned();
        let out = rendered(&[view], false);
        check(
            &out.lines().nth(1),
            &Some(r"signer: SURNAME\x0aGIVEN\x0d\x00"),
            "escaped signer line",
        )?;
        check(&out.lines().count(), &4_usize, "four lines")
    }

    #[test]
    fn no_line_is_indented_or_tabbed() -> TestResult {
        let out = rendered(&[signed(valid()?)], true);
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
