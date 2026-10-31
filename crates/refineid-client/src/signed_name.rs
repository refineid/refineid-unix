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

//! The name the unix apps give a signed document.
//!
//! `<stem>-signed-<UTC time>.<extension>`, beside the (first) input,
//! with the RFC 3339 time's colons as dashes. The stem keeps its own
//! spaces; the suffix adds none, so the name passes through a shell
//! unquoted when the input did.
//!
//! The time is the signature's best-signature-time (ETSI EN 319 102-1
//! clause 5.5), the earliest generation time of its signature
//! timestamps, and the signer's clock when it carries none.

use std::path::{Path, PathBuf};

use refineid_lib_core::sign::document::Format;
use refineid_lib_core::sign::timestamp::VerifiedTimestampToken;
use refineid_lib_core::x509::DateTime;

/// The word between a signed document's stem and its signing time.
const SIGNED_LABEL: &str = "signed";
/// The stem of a container that covers several files.
const PORTFOLIO_STEM: &str = "portfolio";
/// The separator in an RFC 3339 time that file systems refuse.
const TIME_SEPARATOR: char = ':';
/// What [`TIME_SEPARATOR`] becomes in a file name.
const FILE_NAME_TIME_SEPARATOR: &str = "-";
/// What joins the stem, the label and the time.
const NAME_SEPARATOR: &str = "-";

/// Where the signed form of `inputs` goes.
///
/// The stem is the single input's file stem, or `portfolio` for a set.
/// `PAdES` keeps the input's extension as written; every other format
/// takes [`Format::extension`]. The file lands in the directory of the
/// first input.
#[must_use]
pub fn signed_document_path(inputs: &[PathBuf], format: Format, signed_at: DateTime) -> PathBuf {
    let single = match inputs {
        [only] => Some(only.as_path()),
        _ => None,
    };
    let stem = single
        .and_then(Path::file_stem)
        .map_or_else(|| PORTFOLIO_STEM.into(), |stem| stem.to_string_lossy());
    let extension = match (format, single.and_then(Path::extension)) {
        (Format::Pades, Some(own)) => own.to_string_lossy(),
        _ => format.extension().into(),
    };
    let time = signed_at
        .to_string()
        .replace(TIME_SEPARATOR, FILE_NAME_TIME_SEPARATOR);
    let name = format!("{stem}{NAME_SEPARATOR}{SIGNED_LABEL}{NAME_SEPARATOR}{time}.{extension}");
    inputs
        .first()
        .and_then(|first| first.parent())
        .map_or_else(|| PathBuf::from(&name), |dir| dir.join(&name))
}

/// The earliest authenticated `genTime` among a signature's verified
/// signature timestamps: its best-signature-time (ETSI EN 319 102-1
/// clause 5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BestSignatureTime(DateTime);

impl BestSignatureTime {
    /// The earliest generation time among `tokens`, the timestamps over
    /// the signature value; `None` when there are none. An archive or
    /// document timestamp covers more than the signature and is not
    /// one of them.
    #[must_use]
    pub fn of_signature_timestamps(tokens: &[VerifiedTimestampToken]) -> Option<Self> {
        tokens
            .iter()
            .map(|token| token.generated_at)
            .min()
            .map(Self)
    }

    /// The instant.
    #[must_use]
    pub const fn instant(self) -> DateTime {
        self.0
    }
}

/// The default name of a document not yet signed: its inputs, its
/// format and the clock reading that stands in when the signature
/// carries no timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSignedName {
    inputs: Vec<PathBuf>,
    format: Format,
    clock: DateTime,
}

impl PendingSignedName {
    /// The name of `inputs` signed as `format`, falling back to `clock`.
    #[must_use]
    pub const fn new(inputs: Vec<PathBuf>, format: Format, clock: DateTime) -> Self {
        Self {
            inputs,
            format,
            clock,
        }
    }

    /// The path, named by `best` when the signature has one and by the
    /// clock otherwise.
    #[must_use]
    pub fn path(&self, best: Option<BestSignatureTime>) -> PathBuf {
        let at = best.map_or(self.clock, BestSignatureTime::instant);
        signed_document_path(&self.inputs, self.format, at)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use refineid_lib_core::sign::document::Format;
    use refineid_lib_core::sign::timestamp::VerifiedTimestampToken;
    use refineid_lib_core::x509::DateTime;

    use super::{BestSignatureTime, PendingSignedName, signed_document_path};
    use crate::test_util::{TestResult, check};

    /// A synthetic signing time, 2001-02-03T04:05:06Z.
    const SIGNED_YEAR: u16 = 2001;
    const SIGNED_MONTH: u8 = 2;
    const SIGNED_DAY: u8 = 3;
    const SIGNED_HOUR: u8 = 4;
    const SIGNED_MINUTE: u8 = 5;
    const SIGNED_SECOND: u8 = 6;

    fn signed_at() -> Result<DateTime, String> {
        DateTime::new(
            SIGNED_YEAR,
            SIGNED_MONTH,
            SIGNED_DAY,
            SIGNED_HOUR,
            SIGNED_MINUTE,
            SIGNED_SECOND,
        )
        .map_err(|e| format!("signing time: {e}"))
    }

    fn named(inputs: &[&str], format: Format) -> Result<PathBuf, String> {
        let inputs: Vec<PathBuf> = inputs.iter().map(PathBuf::from).collect();
        Ok(signed_document_path(&inputs, format, signed_at()?))
    }

    #[test]
    fn a_signed_document_is_named_by_stem_and_utc_signing_time() -> TestResult {
        check(
            &named(&["/documents/report.pdf"], Format::Pades)?,
            &PathBuf::from("/documents/report-signed-2001-02-03T04-05-06Z.pdf"),
            "pades",
        )?;
        check(
            &named(&["/documents/report.pdf"], Format::AsicEXades)?,
            &PathBuf::from("/documents/report-signed-2001-02-03T04-05-06Z.asice"),
            "asice over a pdf",
        )
    }

    #[test]
    fn pades_keeps_the_extension_as_written() -> TestResult {
        check(
            &named(&["/documents/Report.PDF"], Format::Pades)?,
            &PathBuf::from("/documents/Report-signed-2001-02-03T04-05-06Z.PDF"),
            "uppercase kept",
        )
    }

    #[test]
    fn a_container_takes_the_container_extension() -> TestResult {
        check(
            &named(&["/documents/notes.txt"], Format::AsicEXades)?,
            &PathBuf::from("/documents/notes-signed-2001-02-03T04-05-06Z.asice"),
            "asice-xades",
        )?;
        check(
            &named(&["/documents/notes.txt"], Format::AsicECades)?,
            &PathBuf::from("/documents/notes-signed-2001-02-03T04-05-06Z.asice"),
            "asice-cades",
        )
    }

    #[test]
    fn a_set_is_a_portfolio_beside_the_first_input() -> TestResult {
        check(
            &named(
                &["/documents/report.pdf", "/attachments/notes.txt"],
                Format::AsicEXades,
            )?,
            &PathBuf::from("/documents/portfolio-signed-2001-02-03T04-05-06Z.asice"),
            "portfolio",
        )
    }

    #[test]
    fn cades_takes_its_cms_extensions() -> TestResult {
        check(
            &named(&["/documents/notes.txt"], Format::Cades)?,
            &PathBuf::from("/documents/notes-signed-2001-02-03T04-05-06Z.p7m"),
            "attached",
        )?;
        check(
            &named(&["/documents/notes.txt"], Format::CadesDetached)?,
            &PathBuf::from("/documents/notes-signed-2001-02-03T04-05-06Z.p7s"),
            "detached",
        )
    }

    #[test]
    fn a_relative_input_names_a_relative_output() -> TestResult {
        check(
            &named(&["report.pdf"], Format::Pades)?,
            &PathBuf::from("report-signed-2001-02-03T04-05-06Z.pdf"),
            "relative",
        )
    }

    /// A synthetic clock reading, 2001-02-03T05:00:00Z.
    const CLOCK_HOUR: u8 = 5;
    const CLOCK_MINUTE: u8 = 0;
    const CLOCK_SECOND: u8 = 0;
    /// A later synthetic timestamp generation time,
    /// 2001-02-03T04:05:07Z.
    const LATER_SECOND: u8 = 7;

    fn clock() -> Result<DateTime, String> {
        DateTime::new(
            SIGNED_YEAR,
            SIGNED_MONTH,
            SIGNED_DAY,
            CLOCK_HOUR,
            CLOCK_MINUTE,
            CLOCK_SECOND,
        )
        .map_err(|e| format!("clock: {e}"))
    }

    fn later() -> Result<DateTime, String> {
        DateTime::new(
            SIGNED_YEAR,
            SIGNED_MONTH,
            SIGNED_DAY,
            SIGNED_HOUR,
            SIGNED_MINUTE,
            LATER_SECOND,
        )
        .map_err(|e| format!("later time: {e}"))
    }

    fn token_at(generated_at: DateTime) -> VerifiedTimestampToken {
        VerifiedTimestampToken {
            token: Vec::new(),
            signer_certificate: Vec::new(),
            embedded_certificates: Vec::new(),
            generated_at,
        }
    }

    fn pending() -> Result<PendingSignedName, String> {
        Ok(PendingSignedName::new(
            vec![PathBuf::from("/documents/report.pdf")],
            Format::Pades,
            clock()?,
        ))
    }

    #[test]
    fn the_name_carries_the_signature_timestamp_time() -> TestResult {
        let best = BestSignatureTime::of_signature_timestamps(&[token_at(signed_at()?)]);
        check(
            &pending()?.path(best),
            &PathBuf::from("/documents/report-signed-2001-02-03T04-05-06Z.pdf"),
            "timestamp time, not the clock",
        )
    }

    #[test]
    fn without_a_signature_timestamp_the_name_carries_the_clock() -> TestResult {
        let best = BestSignatureTime::of_signature_timestamps(&[]);
        check(&best, &None, "no timestamp, no best time")?;
        check(
            &pending()?.path(best),
            &PathBuf::from("/documents/report-signed-2001-02-03T05-00-00Z.pdf"),
            "the clock",
        )
    }

    #[test]
    fn several_signature_timestamps_give_the_earliest_time() -> TestResult {
        let best = BestSignatureTime::of_signature_timestamps(&[
            token_at(later()?),
            token_at(signed_at()?),
        ]);
        check(
            &best.map(BestSignatureTime::instant),
            &Some(signed_at()?),
            "earliest genTime",
        )
    }
}
