// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     https://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! The signatures, document timestamps and validation store of a PDF.
//!
//! [`PdfDocument::parse`] follows the cross-reference chain from the
//! last `startxref` through every `/Prev` section, classic tables,
//! cross-reference streams and hybrid files alike, with the same index
//! the `PAdES` writer in [`crate::sign::pades`] extends documents with.
//! Every live object carrying both `/ByteRange` and `/Contents` is a
//! signature dictionary; its declared byte range is checked against
//! the file before the `CMS` in the hole is handed out. Nothing here
//! verifies a signature: the caller digests the spans with
//! [`ByteRange::digest`] and judges the `CMS` itself.
//!
//! # Conformance
//!
//! - ISO 32000-1 sec.12.8.1: the signature dictionary, `/ByteRange`
//!   (two spans of the file around the `/Contents` hex string) and
//!   `/Contents` (a DER-encoded `CMS` object, zero padded to the
//!   reserved size).
//! - ISO 32000-1 sec.7.9.4: the `/M` date string.
//! - `ETSI EN 319 142-1` V1.2.1 clause 5.4.2: the `/DSS` dictionary in
//!   the catalog, with `/Certs`, `/OCSPs` and `/CRLs` arrays of
//!   indirect references to streams holding DER. `/VRI` is not read:
//!   clause 6.3 requirement v puts everything a `VRI` entry names in
//!   those arrays too.
//! - `ETSI EN 319 142-1` V1.2.1 clause 5.4.3: the document timestamp
//!   dictionary, `/Type /DocTimeStamp` with `/SubFilter /ETSI.RFC3161`.
//! - `ETSI EN 319 142-2` V1.2.1 clause 4.2.2: the signature
//!   subfilters `adbe.pkcs7.detached` and `ETSI.CAdES.detached`.
//!
//! Only the newest revision's catalog is read for the `/DSS`: an
//! incremental update that extends the store rewrites it with the
//! earlier entries carried forward. An encrypted document is refused;
//! its strings and streams would need the document key to read.

use crate::ber::{BerTlv, Sequence};
use crate::document::{DocumentFailure, DocumentFile};
use crate::sign::cades::DigestAlgorithm;
use crate::sign::pades::PdfError;
use crate::sign::pades::index::{
    PdfDictionary, PdfIndex, PdfValueParser, complete_object_reference, dictionary_at, find_first,
    parse_usize, validation_references,
};
use crate::sign::validation::ValidationMaterial;
use crate::x509::DateTime;

/// The header every PDF file starts with (ISO 32000-1 sec.7.5.2).
const PDF_HEADER: &[u8] = b"%PDF-";

/// Signature dictionary key naming the signed spans
/// (ISO 32000-1 sec.12.8.1, Table 252).
const KEY_BYTE_RANGE: &[u8] = b"ByteRange";

/// Signature dictionary key holding the signature value.
const KEY_CONTENTS: &[u8] = b"Contents";

/// Dictionary key naming the dictionary's type.
const KEY_TYPE: &[u8] = b"Type";

/// Signature dictionary key naming the encoding of `/Contents`.
const KEY_SUBFILTER: &[u8] = b"SubFilter";

/// Signature dictionary key holding the claimed signing time.
const KEY_SIGNING_TIME: &[u8] = b"M";

/// Trailer key referencing the catalog (ISO 32000-1 sec.7.5.5).
const KEY_ROOT: &[u8] = b"Root";

/// Trailer key present on an encrypted document (ISO 32000-1 sec.7.6.1).
const KEY_ENCRYPT: &[u8] = b"Encrypt";

/// Catalog key of the document security store
/// (`ETSI EN 319 142-1` V1.2.1 clause 5.4.2.2).
const KEY_DSS: &[u8] = b"DSS";

/// `/DSS` key listing certificate streams.
const KEY_CERTS: &[u8] = b"Certs";

/// `/DSS` key listing `OCSPResponse` streams.
const KEY_OCSPS: &[u8] = b"OCSPs";

/// `/DSS` key listing `CertificateList` streams.
const KEY_CRLS: &[u8] = b"CRLs";

/// `/Type` of a signature dictionary (ISO 32000-1 sec.12.8.1).
const TYPE_SIGNATURE: &[u8] = b"Sig";

/// `/Type` of a document timestamp dictionary
/// (`ETSI EN 319 142-1` V1.2.1 clause 5.4.3).
const TYPE_DOCUMENT_TIMESTAMP: &[u8] = b"DocTimeStamp";

/// `/SubFilter` of a `PAdES` signature
/// (`ETSI EN 319 142-2` V1.2.1 clause 4.2.2).
const SUBFILTER_ETSI_CADES_DETACHED: &[u8] = b"ETSI.CAdES.detached";

/// `/SubFilter` of a PKCS#7 detached signature
/// (`ETSI EN 319 142-2` V1.2.1 clause 4.2.2).
const SUBFILTER_ADBE_PKCS7_DETACHED: &[u8] = b"adbe.pkcs7.detached";

/// `/SubFilter` of a document timestamp
/// (`ETSI EN 319 142-1` V1.2.1 clause 5.4.3).
const SUBFILTER_ETSI_RFC3161: &[u8] = b"ETSI.RFC3161";

/// Integers in a `/ByteRange` with exactly two spans.
const BYTE_RANGE_ENTRIES: usize = 4;

/// Opening delimiter of a hex string (ISO 32000-1 sec.7.3.4.3).
const HEX_STRING_OPEN: u8 = b'<';

/// Closing delimiter of a hex string.
const HEX_STRING_CLOSE: u8 = b'>';

/// Opening delimiter of a literal string (ISO 32000-1 sec.7.3.4.2).
const LITERAL_STRING_OPEN: u8 = b'(';

/// Closing delimiter of a literal string.
const LITERAL_STRING_CLOSE: u8 = b')';

/// Escape character inside a literal string.
const LITERAL_STRING_ESCAPE: u8 = b'\\';

/// Bits carried by one hex digit.
const HEX_DIGIT_BITS: u32 = 4;

/// Why a PDF yielded no signature list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfReadError {
    /// The file does not start with the `%PDF-` header.
    NotAPdf,
    /// The structure named does not parse, or contradicts the file.
    Malformed(&'static str),
    /// The document uses a feature this reader does not implement,
    /// named so the refusal says what it was.
    Unsupported(&'static str),
}

impl core::fmt::Display for PdfReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAPdf => f.write_str("not a PDF: no %PDF- header"),
            Self::Malformed(what) => write!(f, "malformed PDF: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported PDF: {what}"),
        }
    }
}

impl core::error::Error for PdfReadError {}

impl From<PdfReadError> for DocumentFailure {
    fn from(error: PdfReadError) -> Self {
        match error {
            PdfReadError::NotAPdf => Self::NotASignedDocument,
            PdfReadError::Malformed(what) => Self::Unreadable(what),
            PdfReadError::Unsupported(what) => Self::UnsupportedProfile(what),
        }
    }
}

impl PdfReadError {
    /// The reader's view of an index failure, `what` naming the
    /// structure that was being read.
    const fn from_index(error: PdfError, what: &'static str) -> Self {
        match error {
            PdfError::NotAPdf => Self::NotAPdf,
            PdfError::UnsupportedCrossReferenceStream => {
                Self::Unsupported("stream filter or predictor")
            }
            PdfError::UnsupportedEncryption => Self::Unsupported("encrypted document"),
            PdfError::MissingStartXref
            | PdfError::MissingTrailer
            | PdfError::MissingCatalogReference
            | PdfError::MissingObject(_)
            | PdfError::MissingPageTree
            | PdfError::UnreadableForm
            | PdfError::UnreadableValidationStore
            | PdfError::SignatureTooLarge { .. } => Self::Malformed(what),
        }
    }
}

/// The encoding a signature dictionary declares for `/Contents`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubFilter {
    /// `ETSI.CAdES.detached`: a `PAdES` `CAdES` signature.
    EtsiCadesDetached,
    /// `adbe.pkcs7.detached`: a PKCS#7 detached signature.
    AdbePkcs7Detached,
    /// `ETSI.RFC3161`: an RFC 3161 timestamp token.
    EtsiRfc3161,
    /// Absent, or a subfilter outside `ETSI EN 319 142-2` clause 4.2.2.
    Other,
}

impl SubFilter {
    /// The subfilter a decoded `/SubFilter` name declares.
    fn from_name(name: &[u8]) -> Self {
        if name == SUBFILTER_ETSI_CADES_DETACHED {
            Self::EtsiCadesDetached
        } else if name == SUBFILTER_ADBE_PKCS7_DETACHED {
            Self::AdbePkcs7Detached
        } else if name == SUBFILTER_ETSI_RFC3161 {
            Self::EtsiRfc3161
        } else {
            Self::Other
        }
    }
}

/// What a signature dictionary is, from its `/Type` and `/SubFilter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    /// `/Type /Sig`, or no `/Type`: a signature in the declared
    /// encoding.
    Signature(SubFilter),
    /// `/Type /DocTimeStamp` with `/SubFilter /ETSI.RFC3161`.
    DocumentTimestamp,
}

/// The two signed spans of one signature, checked against the file.
///
/// The first span starts at offset zero and ends where the hole opens;
/// the second starts where the hole closes. The hole is the
/// `/Contents` hex string with its delimiters (ISO 32000-1 sec.12.8.1)
/// and is never empty; both spans lie within the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// Offset of the hole's opening `<`, which is the first span's
    /// length.
    hole_start: usize,
    /// Offset one past the hole's closing `>`, where the second span
    /// starts.
    hole_end: usize,
    /// Offset one past the second span.
    end: usize,
}

impl ByteRange {
    /// Check the four declared integers against a file of
    /// `file_length` bytes.
    fn from_declaration(
        values: [usize; BYTE_RANGE_ENTRIES],
        file_length: usize,
    ) -> Result<Self, PdfReadError> {
        const MALFORMED: PdfReadError = PdfReadError::Malformed("ByteRange");
        let [first_start, first_length, second_start, second_length] = values;
        let end = second_start.checked_add(second_length).ok_or(MALFORMED)?;
        if first_start != 0 || second_start <= first_length || end > file_length {
            return Err(MALFORMED);
        }
        Ok(Self {
            hole_start: first_length,
            hole_end: second_start,
            end,
        })
    }

    /// The two signed spans, in file order.
    #[must_use]
    pub const fn spans(&self) -> [core::ops::Range<usize>; 2] {
        [0..self.hole_start, self.hole_end..self.end]
    }

    /// The hole between the spans: the `/Contents` hex string.
    #[must_use]
    pub const fn hole(&self) -> core::ops::Range<usize> {
        self.hole_start..self.hole_end
    }

    /// Offset one past the second span: the length of the revision
    /// this signature covers.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.end
    }

    /// Digest of both spans of `file`, in order, under `algorithm`.
    ///
    /// A file shorter than the spans contributes only the bytes it
    /// has, so a digest over the wrong file mismatches rather than
    /// panics.
    #[must_use]
    pub fn digest(&self, file: &DocumentFile, algorithm: DigestAlgorithm) -> Vec<u8> {
        let bytes = file.as_bytes();
        let mut signed = Vec::with_capacity(self.end.saturating_sub(self.hole().len()));
        for span in self.spans() {
            signed.extend_from_slice(bytes.get(span).unwrap_or_default());
        }
        algorithm.digest(&signed)
    }
}

/// One signature or document timestamp dictionary of the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfSignature {
    /// What the dictionary declares itself to be.
    pub kind: SignatureKind,
    /// The DER element in the `/Contents` hole, padding removed: a
    /// `CMS` `ContentInfo`, or an RFC 3161 `TimeStampToken`.
    pub cms: Vec<u8>,
    /// The signed spans.
    pub byte_range: ByteRange,
    /// Whether the second span ends at the end of the file.
    pub covers_whole_document: bool,
    /// The `/M` entry, converted to UTC; `None` when absent, when it
    /// does not parse as an ISO 32000-1 sec.7.9.4 date, or when it
    /// carries no offset from UT.
    pub signing_time_entry: Option<DateTime>,
}

/// The signatures and validation store of one parsed PDF.
#[derive(Debug, Clone)]
pub struct PdfDocument<'a> {
    /// The file the offsets refer to.
    file: &'a DocumentFile,
    /// Every signature dictionary, in object-number order.
    signatures: Vec<PdfSignature>,
    /// The newest catalog's `/DSS` contents.
    validation_store: ValidationMaterial,
}

impl<'a> PdfDocument<'a> {
    /// Index `file` and read its signature dictionaries and `/DSS`.
    ///
    /// # Errors
    /// [`PdfReadError::NotAPdf`] without the header,
    /// [`PdfReadError::Unsupported`] for an encrypted document or a
    /// stream filter the index does not decode, and
    /// [`PdfReadError::Malformed`] when the cross-reference chain, a
    /// signature dictionary or the `/DSS` does not parse or a byte
    /// range contradicts the file.
    pub fn parse(file: &'a DocumentFile) -> Result<Self, PdfReadError> {
        let bytes = file.as_bytes();
        if !bytes.starts_with(PDF_HEADER) {
            return Err(PdfReadError::NotAPdf);
        }
        let index = PdfIndex::parse(bytes)
            .map_err(|error| PdfReadError::from_index(error, "cross-reference chain"))?;
        let trailer = PdfDictionary::parse(index.trailer())
            .map_err(|_ignored| PdfReadError::Malformed("trailer"))?;
        if trailer
            .entry(KEY_ENCRYPT)
            .map_err(|_ignored| PdfReadError::Malformed("trailer"))?
            .is_some()
        {
            return Err(PdfReadError::Unsupported("encrypted document"));
        }

        let mut signatures = Vec::new();
        for (_reference, dictionary) in index.object_dictionaries() {
            if let Some(signature) = signature_from_dictionary(&dictionary, bytes)? {
                signatures.push(signature);
            }
        }
        let validation_store = validation_store(&index, index.trailer(), &trailer)?;
        Ok(Self {
            file,
            signatures,
            validation_store,
        })
    }

    /// The file the byte ranges refer to.
    #[must_use]
    pub const fn file(&self) -> &'a DocumentFile {
        self.file
    }

    /// Every signature and document timestamp dictionary, in
    /// object-number order.
    #[must_use]
    pub fn signatures(&self) -> &[PdfSignature] {
        &self.signatures
    }

    /// The certificates, `OCSP` responses and `CRL`s of the newest
    /// catalog's `/DSS`, each the raw stream content; empty when the
    /// document has no store.
    #[must_use]
    pub const fn validation_store(&self) -> &ValidationMaterial {
        &self.validation_store
    }
}

/// The signature `dictionary` declares, or `None` when it carries no
/// `/ByteRange` and `/Contents` pair.
fn signature_from_dictionary(
    dictionary: &[u8],
    file: &[u8],
) -> Result<Option<PdfSignature>, PdfReadError> {
    const MALFORMED: PdfReadError = PdfReadError::Malformed("signature dictionary");
    if find_first(dictionary, KEY_BYTE_RANGE).is_none()
        || find_first(dictionary, KEY_CONTENTS).is_none()
    {
        return Ok(None);
    }
    let parsed = PdfDictionary::parse(dictionary).map_err(|_ignored| MALFORMED)?;
    let value = |key: &[u8]| -> Result<Option<&[u8]>, PdfReadError> {
        let entry = parsed.entry(key).map_err(|_ignored| MALFORMED)?;
        Ok(entry.and_then(|entry| dictionary.get(entry.value.clone())))
    };
    let (Some(byte_range), Some(contents)) = (value(KEY_BYTE_RANGE)?, value(KEY_CONTENTS)?) else {
        return Ok(None);
    };

    let byte_range = ByteRange::from_declaration(byte_range_values(byte_range)?, file.len())?;
    let hole = file
        .get(byte_range.hole())
        .ok_or(PdfReadError::Malformed("ByteRange"))?;
    let carried = hex_string(hole).ok_or(PdfReadError::Malformed("ByteRange hole"))?;
    let declared = hex_string(contents).ok_or(PdfReadError::Malformed("Contents"))?;
    if carried != declared {
        return Err(PdfReadError::Malformed(
            "Contents outside the ByteRange hole",
        ));
    }
    let element = BerTlv::<Sequence>::parse(&carried)
        .map_err(|_ignored| PdfReadError::Malformed("Contents"))?;
    let cms = carried
        .get(..element.size)
        .ok_or(PdfReadError::Malformed("Contents"))?
        .to_vec();

    let subfilter = value(KEY_SUBFILTER)?
        .map(name_value)
        .transpose()?
        .map_or(SubFilter::Other, |name| SubFilter::from_name(&name));
    let kind = match value(KEY_TYPE)?.map(name_value).transpose()? {
        None => SignatureKind::Signature(subfilter),
        Some(name) if name == TYPE_SIGNATURE => SignatureKind::Signature(subfilter),
        Some(name) if name == TYPE_DOCUMENT_TIMESTAMP => {
            if subfilter != SubFilter::EtsiRfc3161 {
                return Err(PdfReadError::Unsupported("document timestamp subfilter"));
            }
            SignatureKind::DocumentTimestamp
        }
        Some(_) => return Err(PdfReadError::Malformed("signature dictionary type")),
    };
    let signing_time_entry = value(KEY_SIGNING_TIME)?.and_then(pdf_date);

    Ok(Some(PdfSignature {
        kind,
        cms,
        byte_range,
        covers_whole_document: byte_range.end() == file.len(),
        signing_time_entry,
    }))
}

/// The four non-negative integers of a `/ByteRange` array.
fn byte_range_values(value: &[u8]) -> Result<[usize; BYTE_RANGE_ENTRIES], PdfReadError> {
    const MALFORMED: PdfReadError = PdfReadError::Malformed("ByteRange");
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    if !parser.consume(b"[") {
        return Err(MALFORMED);
    }
    let mut values = [0_usize; BYTE_RANGE_ENTRIES];
    for slot in &mut values {
        *slot = parser
            .unsigned_digits()
            .and_then(parse_usize)
            .ok_or(MALFORMED)?;
    }
    parser.skip_trivia();
    if !parser.consume(b"]") {
        return Err(MALFORMED);
    }
    parser.require_end().map_err(|_ignored| MALFORMED)?;
    Ok(values)
}

/// The decoded bytes of a name value such as `/Sig`.
fn name_value(value: &[u8]) -> Result<Vec<u8>, PdfReadError> {
    const MALFORMED: PdfReadError = PdfReadError::Malformed("signature dictionary name");
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    let name = parser.name().map_err(|_ignored| MALFORMED)?;
    parser.require_end().map_err(|_ignored| MALFORMED)?;
    Ok(name)
}

/// The bytes a hex string `<...>` encodes, with trivia around it.
///
/// White space between digits is ignored and an odd final digit is
/// followed by zero (ISO 32000-1 sec.7.3.4.3). `None` when the value
/// is not exactly one hex string.
fn hex_string(value: &[u8]) -> Option<Vec<u8>> {
    let start = value
        .iter()
        .position(|byte| !PdfValueParser::is_whitespace(*byte))?;
    let end = value
        .iter()
        .rposition(|byte| !PdfValueParser::is_whitespace(*byte))?;
    if value.get(start) != Some(&HEX_STRING_OPEN) || value.get(end) != Some(&HEX_STRING_CLOSE) {
        return None;
    }
    let digits = value.get(start.saturating_add(1)..end)?;
    let mut decoded = Vec::with_capacity(digits.len() / 2);
    let mut pending: Option<u8> = None;
    for byte in digits {
        if PdfValueParser::is_whitespace(*byte) {
            continue;
        }
        let digit = PdfValueParser::hex_digit(*byte)?;
        match pending.take() {
            Some(high) => decoded.push((high << HEX_DIGIT_BITS) | digit),
            None => pending = Some(digit),
        }
    }
    if let Some(high) = pending {
        decoded.push(high << HEX_DIGIT_BITS);
    }
    Some(decoded)
}

/// The bytes of a text string value, literal or hex, when it needs no
/// escape decoding.
fn plain_string(value: &[u8]) -> Option<Vec<u8>> {
    let start = value
        .iter()
        .position(|byte| !PdfValueParser::is_whitespace(*byte))?;
    if value.get(start) == Some(&HEX_STRING_OPEN) {
        return hex_string(value);
    }
    let end = value
        .iter()
        .rposition(|byte| !PdfValueParser::is_whitespace(*byte))?;
    if value.get(start) != Some(&LITERAL_STRING_OPEN)
        || value.get(end) != Some(&LITERAL_STRING_CLOSE)
    {
        return None;
    }
    let text = value.get(start.saturating_add(1)..end)?;
    if text.iter().any(|byte| {
        *byte == LITERAL_STRING_ESCAPE
            || *byte == LITERAL_STRING_OPEN
            || *byte == LITERAL_STRING_CLOSE
    }) {
        return None;
    }
    Some(text.to_vec())
}

/// An ISO 32000-1 sec.7.9.4 date value as a UTC instant.
fn pdf_date(value: &[u8]) -> Option<DateTime> {
    PdfDate::parse(&plain_string(value)?)?.utc()
}

/// The fields of a `D:YYYYMMDDHHmmSSOHH'mm'` date string.
struct PdfDate {
    /// Calendar year.
    year: u16,
    /// Month, `1..=12`.
    month: u8,
    /// Day of the month.
    day: u8,
    /// Hour of the local time.
    hour: u8,
    /// Minute of the local time.
    minute: u8,
    /// Second of the local time.
    second: u8,
    /// Local time minus UT, in seconds.
    offset_seconds: i64,
}

impl PdfDate {
    /// The prefix every date string carries.
    const PREFIX: &'static [u8] = b"D:";
    /// Digits in the year field.
    const YEAR_DIGITS: usize = 4;
    /// Digits in every other field.
    const FIELD_DIGITS: usize = 2;
    /// Default month and day when the string stops before them.
    const FIRST: u8 = 1;
    /// Offset marker: the time is UT.
    const UNIVERSAL: u8 = b'Z';
    /// Offset marker: local time is later than UT.
    const AHEAD: u8 = b'+';
    /// Offset marker: local time is earlier than UT.
    const BEHIND: u8 = b'-';
    /// Separator after the offset hours and minutes.
    const APOSTROPHE: u8 = b'\'';
    /// Seconds in a minute and minutes in an hour.
    const SIXTY: i64 = 60;

    /// The fields of `text`; `None` when it does not parse or carries
    /// no relationship to UT.
    fn parse(text: &[u8]) -> Option<Self> {
        let mut rest = text.strip_prefix(Self::PREFIX)?;
        let year = u16::try_from(Self::digits(&mut rest, Self::YEAR_DIGITS)?).ok()?;
        let mut fields = [Self::FIRST, Self::FIRST, 0, 0, 0];
        for field in &mut fields {
            if !rest.first().is_some_and(u8::is_ascii_digit) {
                break;
            }
            *field = u8::try_from(Self::digits(&mut rest, Self::FIELD_DIGITS)?).ok()?;
        }
        let [month, day, hour, minute, second] = fields;
        let (&marker, mut rest) = rest.split_first()?;
        let sign = match marker {
            Self::UNIVERSAL => 0,
            Self::AHEAD => 1,
            Self::BEHIND => -1,
            _ => return None,
        };
        let mut offset_minutes = 0_i64;
        if !rest.is_empty() {
            let hours = i64::from(Self::digits(&mut rest, Self::FIELD_DIGITS)?);
            rest = rest.strip_prefix(&[Self::APOSTROPHE]).unwrap_or(rest);
            let minutes = if rest.is_empty() {
                0
            } else {
                i64::from(Self::digits(&mut rest, Self::FIELD_DIGITS)?)
            };
            rest = rest.strip_prefix(&[Self::APOSTROPHE]).unwrap_or(rest);
            if !rest.is_empty() || minutes >= Self::SIXTY {
                return None;
            }
            offset_minutes = hours.checked_mul(Self::SIXTY)?.checked_add(minutes)?;
        }
        Some(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            offset_seconds: offset_minutes.checked_mul(Self::SIXTY)?.checked_mul(sign)?,
        })
    }

    /// `count` ASCII digits from the front of `rest`, as a number.
    fn digits(rest: &mut &[u8], count: usize) -> Option<u32> {
        let field = rest.get(..count)?;
        if !field.iter().all(u8::is_ascii_digit) {
            return None;
        }
        *rest = rest.get(count..)?;
        core::str::from_utf8(field).ok()?.parse().ok()
    }

    /// The UTC instant the local fields and offset name.
    fn utc(&self) -> Option<DateTime> {
        let local = DateTime::new(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
        .ok()?;
        let local_seconds = i64::try_from(local.unix_duration().as_secs()).ok()?;
        let utc_seconds = u64::try_from(local_seconds.checked_sub(self.offset_seconds)?).ok()?;
        DateTime::from_unix_duration(core::time::Duration::from_secs(utc_seconds)).ok()
    }
}

/// The newest catalog's `/DSS` arrays, each entry's stream content.
fn validation_store(
    index: &PdfIndex<'_>,
    trailer_bytes: &[u8],
    trailer: &PdfDictionary,
) -> Result<ValidationMaterial, PdfReadError> {
    const MALFORMED: PdfReadError = PdfReadError::Malformed("DSS");
    let root = trailer
        .entry(KEY_ROOT)
        .map_err(|_ignored| PdfReadError::Malformed("trailer"))?
        .and_then(|entry| trailer_bytes.get(entry.value.clone()))
        .ok_or(PdfReadError::Malformed("trailer /Root"))?;
    let catalog_reference = complete_object_reference(root)
        .ok()
        .flatten()
        .ok_or(PdfReadError::Malformed("trailer /Root"))?;
    let catalog = index
        .object_body_reference(catalog_reference)
        .and_then(|body| dictionary_at(&body, 0))
        .map(|(dictionary, _end)| dictionary)
        .ok_or(PdfReadError::Malformed("catalog"))?;
    let parsed =
        PdfDictionary::parse(&catalog).map_err(|_ignored| PdfReadError::Malformed("catalog"))?;
    let Some(store_value) = parsed
        .entry(KEY_DSS)
        .map_err(|_ignored| PdfReadError::Malformed("catalog"))?
        .and_then(|entry| catalog.get(entry.value.clone()))
    else {
        return Ok(ValidationMaterial::default());
    };

    let store = match complete_object_reference(store_value).map_err(|_ignored| MALFORMED)? {
        Some(reference) => index
            .object_body_reference(reference)
            .and_then(|body| dictionary_at(&body, 0))
            .map(|(dictionary, _end)| dictionary)
            .ok_or(MALFORMED)?,
        None => store_value.to_vec(),
    };
    let parsed = PdfDictionary::parse(&store).map_err(|_ignored| MALFORMED)?;
    let category = |key: &[u8]| -> Result<Vec<Vec<u8>>, PdfReadError> {
        let Some(value) = parsed
            .entry(key)
            .map_err(|_ignored| MALFORMED)?
            .and_then(|entry| store.get(entry.value.clone()))
        else {
            return Ok(Vec::new());
        };
        let references = validation_references(index, value)
            .map_err(|error| PdfReadError::from_index(error, "DSS"))?;
        references
            .into_iter()
            .map(|reference| {
                index
                    .stream_payload(reference)
                    .map_err(|error| PdfReadError::from_index(error, "DSS stream"))?
                    .ok_or(PdfReadError::Malformed("DSS stream"))
            })
            .collect()
    };
    Ok(ValidationMaterial {
        certificates: category(KEY_CERTS)?,
        ocsp_responses: category(KEY_OCSPS)?,
        crls: category(KEY_CRLS)?,
    })
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        PdfDate, PdfDocument, PdfReadError, SignatureKind, SubFilter, find_first, pdf_date,
    };
    use crate::ber::{BerTag, Sequence, tlv};
    use crate::document::DocumentFile;
    use crate::sign::cades::DigestAlgorithm;
    use crate::sign::pades::{
        SignatureMetadata, append_validation_store, prepare, prepare_document_timestamp,
    };
    use crate::x509::DateTime;

    /// Signature space reserved by the fixtures, in bytes.
    const FIXTURE_CAPACITY: usize = 256;

    /// Payload of the synthetic `CMS` blob.
    const SYNTHETIC_SIGNED_DATA: &[u8] = b"synthetic signed data";

    /// Payload of the synthetic timestamp token.
    const SYNTHETIC_TIMESTAMP_TOKEN: &[u8] = b"synthetic timestamp token";

    /// Synthetic `/DSS` certificate stream content.
    const SYNTHETIC_CERTIFICATE: &[u8] = b"synthetic certificate";

    /// Synthetic `/DSS` `OCSP` stream content.
    const SYNTHETIC_OCSP_RESPONSE: &[u8] = b"synthetic ocsp response";

    /// Synthetic `/DSS` `CRL` stream content.
    const SYNTHETIC_CRL: &[u8] = b"synthetic crl";

    /// The `/M` entry the fixtures write: local time two hours ahead
    /// of UT.
    const SIGNING_TIME_ENTRY: &str = "D:20260102030405+02'00'";

    /// [`SIGNING_TIME_ENTRY`] in UTC.
    const SIGNING_TIME_UTC: (u16, u8, u8, u8, u8, u8) = (2026, 1, 2, 1, 4, 5);

    /// The page objects every fixture starts from, numbered from one.
    const PAGE_OBJECTS: [&str; 3] = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
    ];

    /// Number of the first object in a fixture.
    const FIRST_OBJECT: usize = 1;

    /// Digits of a cross-reference table offset (ISO 32000-1 sec.7.5.4).
    const XREF_OFFSET_DIGITS: usize = 10;

    /// Digits of a cross-reference table generation.
    const XREF_GENERATION_DIGITS: usize = 5;

    /// Generation of the free-list head, object zero.
    const FREE_HEAD_GENERATION: u32 = 65_535;

    /// Offset written for the free-list head, and generation of every
    /// fixture object.
    const ZERO: usize = 0;

    /// Hour, minute and second of a date string that stops at the day.
    const MIDNIGHT: u8 = 0;

    /// Cross-reference stream entry type of an object at a byte offset
    /// (ISO 32000-1 sec.7.5.8.3, Table 18).
    const XREF_TYPE_DIRECT: u8 = 1;

    /// `miniz_oxide` compression level for the flate fixture.
    const FLATE_LEVEL: u8 = 6;

    /// A DER `SEQUENCE` around `content`, standing in for a `CMS`
    /// `ContentInfo`.
    fn sequence(content: &[u8]) -> Vec<u8> {
        tlv(
            u8::try_from(Sequence::TAG).expect("SEQUENCE is a one-byte tag"),
            content,
        )
    }

    /// Bytes of `objects`, numbered from one, behind the PDF header.
    fn objects_prefix(objects: &[Vec<u8>]) -> (Vec<u8>, Vec<usize>) {
        let mut pdf = Vec::from("%PDF-1.7\n");
        let mut offsets = Vec::new();
        for (index, body) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n", index + FIRST_OBJECT).as_bytes());
            pdf.extend_from_slice(body);
            pdf.extend_from_slice(b"\nendobj\n");
        }
        (pdf, offsets)
    }

    /// A PDF of `objects` closed by a classic cross-reference table,
    /// with `trailer_extra` inside the trailer dictionary.
    fn classic_pdf(objects: &[Vec<u8>], trailer_extra: &str) -> Vec<u8> {
        let (mut pdf, offsets) = objects_prefix(objects);
        let xref_at = pdf.len();
        let size = objects.len() + FIRST_OBJECT;
        pdf.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
        pdf.extend_from_slice(
            format!(
                "{ZERO:0offset$} {FREE_HEAD_GENERATION} f \n",
                offset = XREF_OFFSET_DIGITS
            )
            .as_bytes(),
        );
        for offset in &offsets {
            pdf.extend_from_slice(
                format!(
                    "{offset:0width$} {ZERO:0generation$} n \n",
                    width = XREF_OFFSET_DIGITS,
                    generation = XREF_GENERATION_DIGITS
                )
                .as_bytes(),
            );
        }
        pdf.extend_from_slice(
            format!(
                "trailer\n<< /Size {size} /Root 1 0 R{trailer_extra} >>\nstartxref\n{xref_at}\n%%EOF\n"
            )
            .as_bytes(),
        );
        pdf
    }

    /// The page objects as owned bodies.
    fn page_objects() -> Vec<Vec<u8>> {
        PAGE_OBJECTS.iter().map(|body| Vec::from(*body)).collect()
    }

    /// The page objects closed by an unfiltered cross-reference stream
    /// (ISO 32000-1 sec.7.5.8).
    fn stream_pdf() -> Vec<u8> {
        let objects = page_objects();
        let (mut pdf, mut offsets) = objects_prefix(&objects);
        let stream_number = objects.len() + FIRST_OBJECT;
        let xref_at = pdf.len();
        offsets.push(xref_at);
        let widths = [size_of::<u8>(), size_of::<u32>(), size_of::<u16>()];
        let mut rows = Vec::new();
        for offset in &offsets {
            rows.push(XREF_TYPE_DIRECT);
            rows.extend_from_slice(&u32::try_from(*offset).expect("small fixture").to_be_bytes());
            rows.extend_from_slice(&u16::MIN.to_be_bytes());
        }
        pdf.extend_from_slice(
            format!(
                "{stream_number} 0 obj\n<< /Type /XRef /Size {} /Root 1 0 R /Index [{FIRST_OBJECT} {}] \
                 /W [{} {} {}] /Length {} >>\nstream\n",
                stream_number + FIRST_OBJECT,
                offsets.len(),
                widths[0],
                widths[1],
                widths[2],
                rows.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&rows);
        pdf.extend_from_slice(
            format!("\nendstream\nendobj\nstartxref\n{xref_at}\n%%EOF\n").as_bytes(),
        );
        pdf
    }

    /// `pdf` signed once with the synthetic `CMS`, and the digest the
    /// writer computed over the placeholder's spans.
    fn signed(pdf: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let metadata = SignatureMetadata {
            signing_time: Some(SIGNING_TIME_ENTRY.to_owned()),
            ..SignatureMetadata::default()
        };
        let placeholder = prepare(pdf, &metadata, FIXTURE_CAPACITY).expect("the fixture prepares");
        let digest = placeholder.digest(DigestAlgorithm::Sha256);
        let document = placeholder
            .finish(&sequence(SYNTHETIC_SIGNED_DATA))
            .expect("the CMS fits");
        (document, digest)
    }

    #[test]
    fn one_signature_is_found_with_its_kind_subfilter_and_time() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let file = DocumentFile::from_file(pdf);
        let document = PdfDocument::parse(&file).expect("the signed PDF parses");
        let [signature] = document.signatures() else {
            panic!("exactly one signature");
        };
        assert_eq!(
            signature.kind,
            SignatureKind::Signature(SubFilter::EtsiCadesDetached)
        );
        assert_eq!(signature.cms, sequence(SYNTHETIC_SIGNED_DATA));
        assert!(signature.covers_whole_document);
        let (year, month, day, hour, minute, second) = SIGNING_TIME_UTC;
        assert_eq!(
            signature.signing_time_entry,
            Some(DateTime::new(year, month, day, hour, minute, second).expect("valid date"))
        );
        assert!(document.validation_store().is_empty());
    }

    #[test]
    fn the_digest_over_the_spans_equals_the_writers_digest() {
        let (pdf, digest) = signed(&classic_pdf(&page_objects(), ""));
        let file = DocumentFile::from_file(pdf);
        let document = PdfDocument::parse(&file).expect("the signed PDF parses");
        let [signature] = document.signatures() else {
            panic!("exactly one signature");
        };
        assert_eq!(
            signature
                .byte_range
                .digest(document.file(), DigestAlgorithm::Sha256),
            digest
        );
    }

    #[test]
    fn a_document_timestamp_is_recognised() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let stamped = prepare_document_timestamp(&pdf, FIXTURE_CAPACITY)
            .expect("the timestamp prepares")
            .finish(&sequence(SYNTHETIC_TIMESTAMP_TOKEN))
            .expect("the token fits");
        let file = DocumentFile::from_file(stamped);
        let document = PdfDocument::parse(&file).expect("the stamped PDF parses");
        let [signature, timestamp] = document.signatures() else {
            panic!("a signature and a document timestamp");
        };
        assert_eq!(
            signature.kind,
            SignatureKind::Signature(SubFilter::EtsiCadesDetached)
        );
        assert!(!signature.covers_whole_document);
        assert_eq!(timestamp.kind, SignatureKind::DocumentTimestamp);
        assert_eq!(timestamp.cms, sequence(SYNTHETIC_TIMESTAMP_TOKEN));
        assert!(timestamp.covers_whole_document);
        assert_eq!(timestamp.signing_time_entry, None);
    }

    #[test]
    fn serial_signatures_each_keep_their_own_range() {
        let (once, _first_digest) = signed(&classic_pdf(&page_objects(), ""));
        let (twice, second_digest) = signed(&once);
        let file = DocumentFile::from_file(twice);
        let document = PdfDocument::parse(&file).expect("the twice-signed PDF parses");
        let [first, second] = document.signatures() else {
            panic!("two signatures");
        };
        assert!(!first.covers_whole_document);
        assert_eq!(first.byte_range.end(), once.len());
        assert!(second.covers_whole_document);
        assert_eq!(
            second
                .byte_range
                .digest(document.file(), DigestAlgorithm::Sha256),
            second_digest
        );
    }

    #[test]
    fn the_validation_store_reads_back_byte_exact() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let stored = append_validation_store(
            &pdf,
            &[SYNTHETIC_CERTIFICATE.to_vec()],
            &[SYNTHETIC_OCSP_RESPONSE.to_vec()],
            &[SYNTHETIC_CRL.to_vec()],
        )
        .expect("the store appends");
        let file = DocumentFile::from_file(stored);
        let document = PdfDocument::parse(&file).expect("the PDF with a store parses");
        let store = document.validation_store();
        assert_eq!(store.certificates, [SYNTHETIC_CERTIFICATE]);
        assert_eq!(store.ocsp_responses, [SYNTHETIC_OCSP_RESPONSE]);
        assert_eq!(store.crls, [SYNTHETIC_CRL]);
        let [signature] = document.signatures() else {
            panic!("exactly one signature");
        };
        assert!(!signature.covers_whole_document);
    }

    #[test]
    fn a_later_store_update_carries_earlier_entries_forward() {
        let (pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let first = append_validation_store(&pdf, &[SYNTHETIC_CERTIFICATE.to_vec()], &[], &[])
            .expect("the first store appends");
        let second = append_validation_store(&first, &[], &[], &[SYNTHETIC_CRL.to_vec()])
            .expect("the second store appends");
        let file = DocumentFile::from_file(second);
        let document = PdfDocument::parse(&file).expect("the PDF parses");
        let store = document.validation_store();
        assert_eq!(store.certificates, [SYNTHETIC_CERTIFICATE]);
        assert!(store.ocsp_responses.is_empty());
        assert_eq!(store.crls, [SYNTHETIC_CRL]);
    }

    #[test]
    fn a_direct_store_with_a_flate_stream_is_decoded() {
        let compressed =
            miniz_oxide::deflate::compress_to_vec_zlib(SYNTHETIC_CERTIFICATE, FLATE_LEVEL);
        let mut stream = Vec::from(
            format!(
                "<< /Length {} /Filter /FlateDecode >>\nstream\n",
                compressed.len()
            )
            .as_bytes(),
        );
        stream.extend_from_slice(&compressed);
        stream.extend_from_slice(b"\nendstream");
        let mut objects = page_objects();
        objects[0] = Vec::from(
            "<< /Type /Catalog /Pages 2 0 R /DSS << /Type /DSS /Certs [4 0 R] /VRI << >> >> >>",
        );
        objects.push(stream);
        let file = DocumentFile::from_file(classic_pdf(&objects, ""));
        let document = PdfDocument::parse(&file).expect("the PDF parses");
        assert_eq!(
            document.validation_store().certificates,
            [SYNTHETIC_CERTIFICATE]
        );
        assert!(document.signatures().is_empty());
    }

    #[test]
    fn a_cross_reference_stream_pdf_is_read() {
        let (pdf, digest) = signed(&stream_pdf());
        assert!(
            find_first(&pdf, b"/Type /XRef").is_some(),
            "the fixture is closed by a stream"
        );
        let stored = append_validation_store(&pdf, &[SYNTHETIC_CERTIFICATE.to_vec()], &[], &[])
            .expect("the store appends behind a stream");
        let file = DocumentFile::from_file(stored);
        let document = PdfDocument::parse(&file).expect("the stream PDF parses");
        let [signature] = document.signatures() else {
            panic!("exactly one signature");
        };
        assert_eq!(
            signature.kind,
            SignatureKind::Signature(SubFilter::EtsiCadesDetached)
        );
        assert_eq!(
            signature
                .byte_range
                .digest(document.file(), DigestAlgorithm::Sha256),
            digest
        );
        assert_eq!(
            document.validation_store().certificates,
            [SYNTHETIC_CERTIFICATE]
        );
    }

    #[test]
    fn a_byte_range_not_starting_at_zero_is_rejected() {
        let (mut pdf, _digest) = signed(&classic_pdf(&page_objects(), ""));
        let key = b"/ByteRange [";
        let open = find_first(&pdf, key).expect("the range is written") + key.len();
        let close = open + find_first(&pdf[open..], b"]").expect("the range closes");
        let declared = String::from_utf8(pdf[open..close].to_vec()).expect("ASCII range");
        let mut values: Vec<usize> = declared
            .split_ascii_whitespace()
            .map(|value| value.parse().expect("integer"))
            .collect();
        values[ZERO] = FIRST_OBJECT;
        let rewritten = values
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let padded = format!("{rewritten:>width$}", width = declared.len());
        pdf[open..close].copy_from_slice(padded.as_bytes());
        let file = DocumentFile::from_file(pdf);
        assert_eq!(
            PdfDocument::parse(&file).map(|document| document.signatures().len()),
            Err(PdfReadError::Malformed("ByteRange"))
        );
    }

    #[test]
    fn an_encrypted_trailer_is_refused() {
        let file = DocumentFile::from_file(classic_pdf(&page_objects(), " /Encrypt 9 0 R"));
        assert_eq!(
            PdfDocument::parse(&file).map(|document| document.signatures().len()),
            Err(PdfReadError::Unsupported("encrypted document"))
        );
    }

    #[test]
    fn a_file_without_the_header_is_not_a_pdf() {
        let file = DocumentFile::from_file(Vec::from(SYNTHETIC_SIGNED_DATA));
        assert_eq!(
            PdfDocument::parse(&file).map(|document| document.signatures().len()),
            Err(PdfReadError::NotAPdf)
        );
    }

    #[test]
    fn dates_without_a_relationship_to_ut_are_not_read() {
        assert!(PdfDate::parse(b"D:20260102030405").is_none());
        assert!(PdfDate::parse(b"20260102030405Z").is_none());
        let (year, month, day, _hour, _minute, _second) = SIGNING_TIME_UTC;
        assert_eq!(
            pdf_date(b"(D:20260102Z)"),
            Some(
                DateTime::new(year, month, day, MIDNIGHT, MIDNIGHT, MIDNIGHT).expect("valid date")
            )
        );
        assert_eq!(
            pdf_date(SIGNING_TIME_ENTRY.as_bytes()),
            None,
            "a bare value is not a string"
        );
    }
}
