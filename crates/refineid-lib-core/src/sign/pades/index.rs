//! The cross-reference index and value grammar shared by the `PAdES`
//! writer and the document reader.
//!
//! [`PdfIndex`] follows `startxref` and the `/Prev` chain through
//! classic tables, cross-reference streams and hybrid files, keeping
//! the newest entry for each object number. [`PdfValueParser`] and
//! [`PdfDictionary`] read the value grammar with exact byte spans, so
//! a caller can either interpret a value or carry it forward
//! unchanged.
//!
//! # Conformance
//!
//! - ISO 32000-1 sec.7.3: objects, names, strings, dictionaries.
//! - ISO 32000-1 sec.7.5.4, sec.7.5.5, sec.7.5.6: the cross-reference
//!   table, the trailer and incremental updates.
//! - ISO 32000-1 sec.7.5.7, sec.7.5.8: object and cross-reference
//!   streams, read in `xref_stream`.

use std::collections::HashMap;

use super::PdfError;
use super::xref_stream;

/// Maximum nesting accepted while retaining existing PDF values.
///
/// The document security store can carry extension dictionaries and a
/// `/VRI` tree that this writer must preserve without interpreting. A
/// fixed bound keeps that preservation from becoming an unbounded parser
/// recursion on an attacker-supplied PDF.
pub(crate) const MAX_PDF_VALUE_DEPTH: usize = 64;

/// One indirect PDF object reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PdfObjectReference {
    pub(crate) number: u32,
    pub(crate) generation: u16,
}

impl PdfObjectReference {
    pub(crate) fn rendered(self) -> String {
        format!("{} {} R", self.number, self.generation)
    }
}

/// One top-level dictionary entry, retaining the exact value byte span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PdfDictionaryEntry {
    /// Decoded name bytes, without the leading slash.
    pub(crate) name: Vec<u8>,
    /// Exact value bytes in the dictionary source.
    pub(crate) value: core::ops::Range<usize>,
}

/// A parsed top-level dictionary.
pub(crate) struct PdfDictionary {
    pub(crate) entries: Vec<PdfDictionaryEntry>,
    /// Offset of the outer dictionary's closing `>>`.
    pub(crate) closing: usize,
}

impl PdfDictionary {
    /// Parse one complete dictionary, with only trivia around it.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, PdfError> {
        let mut parser = PdfValueParser::new(bytes);
        parser.skip_trivia();
        let dictionary = parser.dictionary(1)?;
        parser.require_end()?;
        Ok(dictionary)
    }

    /// Parse the dictionary that opens `bytes`, ignoring what follows
    /// it, such as the `stream` keyword and payload of a stream object.
    pub(crate) fn parse_leading(bytes: &[u8]) -> Result<Self, PdfError> {
        let mut parser = PdfValueParser::new(bytes);
        parser.skip_trivia();
        parser.dictionary(1)
    }

    /// The sole entry whose decoded name equals `name`.
    ///
    /// Duplicate spellings such as `/DSS` and `/D#53S` are ambiguous;
    /// refuse them instead of silently choosing which earlier store to
    /// discard.
    pub(crate) fn entry(&self, name: &[u8]) -> Result<Option<&PdfDictionaryEntry>, PdfError> {
        let mut matching = self.entries.iter().filter(|entry| entry.name == name);
        let found = matching.next();
        if matching.next().is_some() {
            return Err(PdfError::UnreadableValidationStore);
        }
        Ok(found)
    }
}

/// Byte-oriented parser for the PDF value grammar needed to retain a DSS.
pub(crate) struct PdfValueParser<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) offset: usize,
}

impl<'a> PdfValueParser<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn dictionary(&mut self, depth: usize) -> Result<PdfDictionary, PdfError> {
        Self::check_depth(depth)?;
        if !self.consume(b"<<") {
            return Err(PdfError::UnreadableValidationStore);
        }
        let mut entries = Vec::new();
        loop {
            self.skip_trivia();
            let closing = self.offset;
            if self.consume(b">>") {
                return Ok(PdfDictionary { entries, closing });
            }
            let name = self.name()?;
            self.skip_trivia();
            let value = self.value(depth)?;
            entries.push(PdfDictionaryEntry { name, value });
        }
    }

    pub(crate) fn value(&mut self, depth: usize) -> Result<core::ops::Range<usize>, PdfError> {
        self.skip_trivia();
        let start = self.offset;
        if self.starts_with(b"<<") {
            let _dictionary = self.dictionary(depth.saturating_add(1))?;
        } else if self.consume(b"[") {
            self.array_remainder(depth.saturating_add(1))?;
        } else if self.consume(b"(") {
            self.literal_string_remainder()?;
        } else if self.consume(b"<") {
            self.hex_string_remainder()?;
        } else if self.starts_with(b"/") {
            let _name = self.name()?;
        } else {
            let first = self.atom()?;
            self.consume_reference_tail(first);
        }
        Ok(start..self.offset)
    }

    pub(crate) fn array_remainder(&mut self, depth: usize) -> Result<(), PdfError> {
        Self::check_depth(depth)?;
        loop {
            self.skip_trivia();
            if self.consume(b"]") {
                return Ok(());
            }
            let _value = self.value(depth)?;
        }
    }

    pub(crate) fn literal_string_remainder(&mut self) -> Result<(), PdfError> {
        let mut depth = 1_usize;
        while let Some(byte) = self.bytes.get(self.offset).copied() {
            self.offset = self.offset.saturating_add(1);
            match byte {
                b'\\' => {
                    let Some(escaped) = self.bytes.get(self.offset).copied() else {
                        return Err(PdfError::UnreadableValidationStore);
                    };
                    self.offset = self.offset.saturating_add(1);
                    if escaped == b'\r' && self.bytes.get(self.offset) == Some(&b'\n') {
                        self.offset = self.offset.saturating_add(1);
                    }
                }
                b'(' => {
                    depth = depth.saturating_add(1);
                    Self::check_depth(depth)?;
                }
                b')' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or(PdfError::UnreadableValidationStore)?;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Err(PdfError::UnreadableValidationStore)
    }

    pub(crate) fn hex_string_remainder(&mut self) -> Result<(), PdfError> {
        while let Some(byte) = self.bytes.get(self.offset).copied() {
            self.offset = self.offset.saturating_add(1);
            if byte == b'>' {
                return Ok(());
            }
        }
        Err(PdfError::UnreadableValidationStore)
    }

    /// A name decoded according to PDF's `#xx` byte escapes.
    pub(crate) fn name(&mut self) -> Result<Vec<u8>, PdfError> {
        if !self.consume(b"/") {
            return Err(PdfError::UnreadableValidationStore);
        }
        let mut decoded = Vec::new();
        while let Some(byte) = self.bytes.get(self.offset).copied() {
            if Self::is_whitespace(byte) || Self::is_delimiter(byte) {
                break;
            }
            if byte == b'#' {
                let high = self
                    .bytes
                    .get(self.offset.saturating_add(1))
                    .and_then(|byte| Self::hex_digit(*byte));
                let low = self
                    .bytes
                    .get(self.offset.saturating_add(2))
                    .and_then(|byte| Self::hex_digit(*byte));
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(PdfError::UnreadableValidationStore);
                };
                decoded.push(high.saturating_mul(16).saturating_add(low));
                self.offset = self.offset.saturating_add(3);
            } else {
                decoded.push(byte);
                self.offset = self.offset.saturating_add(1);
            }
        }
        Ok(decoded)
    }

    /// One non-delimiter token.
    pub(crate) fn atom(&mut self) -> Result<core::ops::Range<usize>, PdfError> {
        let start = self.offset;
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| !Self::is_whitespace(*byte) && !Self::is_delimiter(*byte))
        {
            self.offset = self.offset.saturating_add(1);
        }
        if start == self.offset {
            return Err(PdfError::UnreadableValidationStore);
        }
        Ok(start..self.offset)
    }

    /// Extend an atom value across `N N R` when that complete shape follows.
    pub(crate) fn consume_reference_tail(&mut self, first: core::ops::Range<usize>) {
        if parse_u32(&self.bytes[first]).is_none() {
            return;
        }
        let after_first = self.offset;
        let Some(_generation) = self.unsigned_u16() else {
            self.offset = after_first;
            return;
        };
        self.skip_trivia();
        if !self.consume_keyword(b"R") {
            self.offset = after_first;
        }
    }

    /// A complete indirect reference at the current position.
    pub(crate) fn reference(&mut self) -> Option<PdfObjectReference> {
        let start = self.offset;
        let number = self.unsigned_u32()?;
        let Some(generation) = self.unsigned_u16() else {
            self.offset = start;
            return None;
        };
        self.skip_trivia();
        if !self.consume_keyword(b"R") {
            self.offset = start;
            return None;
        }
        Some(PdfObjectReference { number, generation })
    }

    pub(crate) fn unsigned_u32(&mut self) -> Option<u32> {
        self.unsigned_digits().and_then(parse_u32)
    }

    pub(crate) fn unsigned_u16(&mut self) -> Option<u16> {
        self.unsigned_digits().and_then(parse_u16)
    }

    pub(crate) fn unsigned_digits(&mut self) -> Option<&'a [u8]> {
        self.skip_trivia();
        let start = self.offset;
        while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
            self.offset = self.offset.saturating_add(1);
        }
        if start == self.offset
            || self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| !Self::is_whitespace(*byte) && !Self::is_delimiter(*byte))
        {
            self.offset = start;
            return None;
        }
        self.bytes.get(start..self.offset)
    }

    pub(crate) fn consume_keyword(&mut self, keyword: &[u8]) -> bool {
        if !self.starts_with(keyword) {
            return false;
        }
        let after = self.offset.saturating_add(keyword.len());
        if self
            .bytes
            .get(after)
            .is_some_and(|byte| !Self::is_whitespace(*byte) && !Self::is_delimiter(*byte))
        {
            return false;
        }
        self.offset = after;
        true
    }

    pub(crate) fn require_end(&mut self) -> Result<(), PdfError> {
        self.skip_trivia();
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PdfError::UnreadableValidationStore)
        }
    }

    pub(crate) fn skip_trivia(&mut self) {
        loop {
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| Self::is_whitespace(*byte))
            {
                self.offset = self.offset.saturating_add(1);
            }
            if self.bytes.get(self.offset) != Some(&b'%') {
                return;
            }
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| *byte != b'\r' && *byte != b'\n')
            {
                self.offset = self.offset.saturating_add(1);
            }
        }
    }

    pub(crate) fn consume(&mut self, token: &[u8]) -> bool {
        if !self.starts_with(token) {
            return false;
        }
        self.offset = self.offset.saturating_add(token.len());
        true
    }

    pub(crate) fn starts_with(&self, token: &[u8]) -> bool {
        self.bytes
            .get(self.offset..)
            .is_some_and(|rest| rest.starts_with(token))
    }

    pub(crate) const fn is_whitespace(byte: u8) -> bool {
        byte == 0 || byte == b'\t' || byte == b'\n' || byte == 12 || byte == b'\r' || byte == b' '
    }

    pub(crate) const fn is_delimiter(byte: u8) -> bool {
        matches!(byte, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'/' | b'%')
    }

    pub(crate) const fn hex_digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    pub(crate) const fn check_depth(depth: usize) -> Result<(), PdfError> {
        if depth <= MAX_PDF_VALUE_DEPTH {
            Ok(())
        } else {
            Err(PdfError::UnreadableValidationStore)
        }
    }
}

/// Parse a value as exactly one indirect reference.
pub(crate) fn complete_object_reference(
    value: &[u8],
) -> Result<Option<PdfObjectReference>, PdfError> {
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    let reference = parser.reference();
    if reference.is_some() {
        parser.require_end()?;
    }
    Ok(reference)
}

/// Parse a DSS category as an array containing only indirect references.
pub(crate) fn complete_reference_array(value: &[u8]) -> Result<Vec<PdfObjectReference>, PdfError> {
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    if !parser.consume(b"[") {
        return Err(PdfError::UnreadableValidationStore);
    }
    PdfValueParser::check_depth(1)?;
    let mut references = Vec::new();
    loop {
        parser.skip_trivia();
        if parser.consume(b"]") {
            parser.require_end()?;
            return Ok(references);
        }
        let Some(reference) = parser.reference() else {
            return Err(PdfError::UnreadableValidationStore);
        };
        references.push(reference);
    }
}

/// Resolve a direct or indirect array of indirect references, as a
/// `/DSS` category, `/Fields` or `/Kids` carries.
pub(crate) fn validation_references(
    index: &PdfIndex<'_>,
    value: &[u8],
) -> Result<Vec<PdfObjectReference>, PdfError> {
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    if parser.starts_with(b"[") {
        return complete_reference_array(value);
    }
    let reference = complete_object_reference(value)?.ok_or(PdfError::UnreadableValidationStore)?;
    let array = index
        .object_body_reference(reference)
        .ok_or(PdfError::MissingObject(reference.number))?;
    complete_reference_array(&array)
}

/// Where the tokenizer is while walking an object body.
pub(crate) enum Scan {
    Regular,
    Comment,
    HexString,
    LiteralString { depth: u32, escaped: bool },
}

/// The offset recorded by the file's last `startxref`.
pub(crate) fn find_start_xref(pdf: &[u8]) -> Result<usize, PdfError> {
    let at = find_last(pdf, b"startxref").ok_or(PdfError::MissingStartXref)?;
    let tail = &pdf[at.saturating_add(b"startxref".len())..];
    let digits: Vec<u8> = tail
        .iter()
        .skip_while(|byte| PdfValueParser::is_whitespace(**byte))
        .take_while(|byte| byte.is_ascii_digit())
        .copied()
        .collect();
    if digits.is_empty() {
        return Err(PdfError::MissingStartXref);
    }
    let text = String::from_utf8_lossy(&digits);
    text.parse().map_err(|_ignored| PdfError::MissingStartXref)
}

/// Where one live object's bytes sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XrefLocation {
    /// Free, or an entry type this reader does not know: the number
    /// is claimed so older sections' copies stay shadowed, and a
    /// reference to it resolves to nothing.
    Free,
    /// At a byte offset in the file, written as `N G obj`.
    Direct {
        /// The offset of the object header.
        offset: usize,
    },
    /// Inside an object stream (ISO 32000-1 sec.7.5.7).
    Compressed {
        /// The object stream's own number.
        container: u32,
        /// The object's position among the stream's contents.
        position: u32,
    },
}

/// One object entry resolved from the xref chain.
#[derive(Debug, Clone, Copy)]
pub(crate) struct XrefEntry {
    pub(crate) number: u32,
    pub(crate) generation: u16,
    pub(crate) location: XrefLocation,
}

/// The xref view of the current PDF revision, whichever shape its
/// sections take.
pub(crate) struct PdfIndex<'a> {
    pub(super) pdf: &'a [u8],
    pub(super) trailer: Vec<u8>,
    pub(super) start_xref: usize,
    /// Whether the newest section is a cross-reference stream, which
    /// decides the shape of the section an update appends.
    pub(super) newest_is_stream: bool,
    pub(super) objects: Vec<XrefEntry>,
}

impl<'a> PdfIndex<'a> {
    /// Maximum number of cross-reference sections followed through
    /// `/Prev`; a longer chain is refused rather than read in part.
    pub(crate) const MAX_XREF_DEPTH: usize = 64;

    pub(crate) fn parse(pdf: &'a [u8]) -> Result<Self, PdfError> {
        let start_xref = find_start_xref(pdf)?;
        let mut next = Some(start_xref);
        let mut visited = Vec::new();
        let mut trailer = None;
        let mut newest_is_stream = false;
        let mut objects = Vec::new();

        for _ in 0..Self::MAX_XREF_DEPTH {
            let Some(offset) = next else { break };
            if visited.contains(&offset) {
                return Err(PdfError::MissingTrailer);
            }
            visited.push(offset);

            let section = parse_xref_section(pdf, offset)?;
            if trailer.is_none() {
                trailer = Some(section.trailer.clone());
                newest_is_stream = section.is_stream;
            }
            for entry in section.entries {
                // Newer xref sections win. Keep a newer free entry too:
                // it deletes the object and must suppress older copies.
                if !objects
                    .iter()
                    .any(|existing: &XrefEntry| existing.number == entry.number)
                {
                    objects.push(entry);
                }
            }
            next = trailer_offset(&section.trailer, b"Prev")?;
        }
        if next.is_some() {
            return Err(PdfError::MissingTrailer);
        }

        Ok(Self {
            pdf,
            trailer: trailer.ok_or(PdfError::MissingTrailer)?,
            start_xref,
            newest_is_stream,
            objects,
        })
    }

    pub(crate) fn trailer(&self) -> &[u8] {
        &self.trailer
    }

    pub(crate) const fn start_xref(&self) -> usize {
        self.start_xref
    }

    /// Whether an update must close with a cross-reference stream.
    pub(crate) const fn newest_is_stream(&self) -> bool {
        self.newest_is_stream
    }

    pub(crate) fn object_body(&self, number: u32) -> Option<Vec<u8>> {
        self.object_body_reference(PdfObjectReference {
            number,
            generation: 0,
        })
    }

    pub(crate) fn object_body_reference(&self, reference: PdfObjectReference) -> Option<Vec<u8>> {
        let entry = self.objects.iter().find(|entry| {
            entry.number == reference.number && entry.generation == reference.generation
        })?;
        match entry.location {
            XrefLocation::Free => None,
            XrefLocation::Direct { offset } => {
                object_body_at(self.pdf, reference.number, reference.generation, offset)
            }
            XrefLocation::Compressed {
                container,
                position,
            } => {
                let carrier = self
                    .objects
                    .iter()
                    .find(|entry| entry.number == container)?;
                let XrefLocation::Direct { offset } = carrier.location else {
                    return None;
                };
                xref_stream::compressed_body(self.pdf, offset, reference.number, position)
            }
        }
    }

    /// The dictionary of every live object that is one, or that opens
    /// a stream with one, in object-number order, each with the file
    /// offset of its `<<` when the object is not inside an object
    /// stream.
    ///
    /// Each object stream is decoded once however many objects it
    /// holds. A live object that is some other value, such as a number
    /// or an array, is left out.
    ///
    /// # Errors
    /// [`PdfError::MissingObject`] when a live entry does not lead to
    /// an object with its number and generation, or a dictionary there
    /// does not close: an unreadable object is never skipped, so a
    /// malformed signature dictionary cannot hide.
    pub(crate) fn object_dictionaries(&self) -> Result<Vec<ObjectDictionary>, PdfError> {
        let mut live: Vec<&XrefEntry> = self
            .objects
            .iter()
            .filter(|entry| entry.location != XrefLocation::Free)
            .collect();
        live.sort_unstable_by_key(|entry| (entry.number, entry.generation));
        let mut containers: HashMap<u32, Option<xref_stream::ObjectStream>> = HashMap::new();
        let mut dictionaries = Vec::new();
        for entry in live {
            let reference = PdfObjectReference {
                number: entry.number,
                generation: entry.generation,
            };
            let unreadable = PdfError::MissingObject(reference.number);
            let dictionary = match entry.location {
                XrefLocation::Free => None,
                XrefLocation::Direct { offset } => {
                    object_dictionary_at(self.pdf, reference, offset)
                        .ok_or(unreadable)?
                        .map(|(start, bytes)| (Some(start), bytes))
                }
                XrefLocation::Compressed {
                    container,
                    position,
                } => {
                    let body = containers
                        .entry(container)
                        .or_insert_with(|| {
                            let carrier = self
                                .objects
                                .iter()
                                .find(|entry| entry.number == container)?;
                            let XrefLocation::Direct { offset } = carrier.location else {
                                return None;
                            };
                            xref_stream::ObjectStream::at(self.pdf, offset)
                        })
                        .as_ref()
                        .and_then(|stream| stream.body(reference.number, position))
                        .ok_or(unreadable)?;
                    leading_dictionary(&body, 0)
                        .ok_or(unreadable)?
                        .map(|(_start, bytes)| (None, bytes))
                }
            };
            if let Some((file_offset, bytes)) = dictionary {
                dictionaries.push(ObjectDictionary { file_offset, bytes });
            }
        }
        Ok(dictionaries)
    }

    /// The decoded payload of the stream object `reference` names.
    ///
    /// A stream is always a direct object (ISO 32000-1 sec.7.3.8.1,
    /// sec.7.5.7), so an entry inside an object stream, a free entry
    /// or a missing one is `None`.
    ///
    /// # Errors
    /// [`PdfError`] when the object is not a stream or its filter is
    /// not one `xref_stream` decodes.
    pub(crate) fn stream_payload(
        &self,
        reference: PdfObjectReference,
    ) -> Result<Option<Vec<u8>>, PdfError> {
        let Some(entry) = self.objects.iter().find(|entry| {
            entry.number == reference.number && entry.generation == reference.generation
        }) else {
            return Ok(None);
        };
        let XrefLocation::Direct { offset } = entry.location else {
            return Ok(None);
        };
        xref_stream::stream_payload(self.pdf, offset, reference).map(Some)
    }
}

/// One live object's dictionary, as [`PdfIndex::object_dictionaries`]
/// lists it.
pub(crate) struct ObjectDictionary {
    /// Offset of its `<<` in the file; `None` inside an object stream,
    /// where the bytes are not the file's.
    pub(crate) file_offset: Option<usize>,
    /// The dictionary, from `<<` to `>>`.
    pub(crate) bytes: Vec<u8>,
}

pub(crate) struct XrefSection {
    pub(crate) trailer: Vec<u8>,
    pub(crate) entries: Vec<XrefEntry>,
    /// Whether the section is a cross-reference stream.
    pub(crate) is_stream: bool,
}

/// Cross-reference table keyword of an object in use
/// (ISO 32000-1 sec.7.5.4).
const XREF_IN_USE: &[u8] = b"n";

/// Cross-reference table keyword of a free entry.
const XREF_FREE: &[u8] = b"f";

/// The byte offset a trailer stores under `name`, `None` when absent.
///
/// The trailer must parse, and a present value must be one
/// non-negative integer: a chain link that cannot be read is an error,
/// never the end of the chain.
fn trailer_offset(trailer: &[u8], name: &[u8]) -> Result<Option<usize>, PdfError> {
    let parsed = PdfDictionary::parse(trailer).map_err(|_ignored| PdfError::MissingTrailer)?;
    let Some(entry) = parsed
        .entry(name)
        .map_err(|_ignored| PdfError::MissingTrailer)?
    else {
        return Ok(None);
    };
    let value = trailer
        .get(entry.value.clone())
        .ok_or(PdfError::MissingTrailer)?;
    parse_usize(value).map(Some).ok_or(PdfError::MissingTrailer)
}

pub(crate) fn parse_xref_section(pdf: &[u8], offset: usize) -> Result<XrefSection, PdfError> {
    let mut cursor = skip_pdf_whitespace(pdf, offset);
    let Some(rest) = pdf.get(cursor..) else {
        return Err(PdfError::MissingStartXref);
    };
    if !rest.starts_with(b"xref") {
        return xref_stream::parse_stream_section(pdf, cursor);
    }
    cursor = cursor.saturating_add(b"xref".len());

    let mut entries = Vec::new();
    loop {
        let token = read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?;
        if token == b"trailer" {
            let (trailer, _after) = dictionary_at(pdf, cursor).ok_or(PdfError::MissingTrailer)?;
            return hybrid_merged(pdf, trailer, entries);
        }

        let start = parse_u32(token).ok_or(PdfError::MissingTrailer)?;
        let count = parse_u32(read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?)
            .ok_or(PdfError::MissingTrailer)?;

        for index in 0..count {
            let object_offset =
                parse_usize(read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?)
                    .ok_or(PdfError::MissingTrailer)?;
            let generation =
                parse_u16(read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?)
                    .ok_or(PdfError::MissingTrailer)?;
            let flag = read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?;
            let number = start.checked_add(index).ok_or(PdfError::MissingTrailer)?;
            let location = if flag == XREF_IN_USE {
                XrefLocation::Direct {
                    offset: object_offset,
                }
            } else if flag == XREF_FREE {
                XrefLocation::Free
            } else {
                return Err(PdfError::MissingTrailer);
            };
            entries.push(XrefEntry {
                number,
                generation,
                location,
            });
        }
    }
}

/// A classic table section, merged with the cross-reference stream a
/// hybrid trailer names.
///
/// A hybrid revision keeps the authoritative copy of its entries in
/// the stream its `/XRefStm` key points at; the table is the fallback
/// for readers that predate streams (ISO 32000-1 sec.7.5.8.4). The
/// stream's entries go first, so they win the newest-copy merge.
pub(crate) fn hybrid_merged(
    pdf: &[u8],
    trailer: Vec<u8>,
    entries: Vec<XrefEntry>,
) -> Result<XrefSection, PdfError> {
    let Some(hybrid) = trailer_offset(&trailer, b"XRefStm")? else {
        return Ok(XrefSection {
            trailer,
            entries,
            is_stream: false,
        });
    };
    let stream = xref_stream::parse_stream_section(pdf, skip_pdf_whitespace(pdf, hybrid))?;
    let mut combined = stream.entries;
    combined.extend(entries);
    Ok(XrefSection {
        trailer,
        entries: combined,
        is_stream: false,
    })
}

pub(crate) fn skip_pdf_whitespace(pdf: &[u8], mut cursor: usize) -> usize {
    while pdf
        .get(cursor)
        .is_some_and(|byte| PdfValueParser::is_whitespace(*byte))
    {
        cursor = cursor.saturating_add(1);
    }
    cursor
}

pub(crate) fn read_pdf_token<'a>(pdf: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    *cursor = skip_pdf_whitespace(pdf, *cursor);
    let start = *cursor;
    while pdf
        .get(*cursor)
        .is_some_and(|byte| !PdfValueParser::is_whitespace(*byte))
    {
        *cursor = (*cursor).saturating_add(1);
    }
    (start < *cursor).then(|| &pdf[start..*cursor])
}

pub(crate) fn parse_usize(digits: &[u8]) -> Option<usize> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut out = 0_usize;
    for digit in digits {
        out = out
            .checked_mul(10)?
            .checked_add(usize::from(digit.saturating_sub(b'0')))?;
    }
    Some(out)
}

pub(crate) fn parse_u32(digits: &[u8]) -> Option<u32> {
    parse_usize(digits).and_then(|value| u32::try_from(value).ok())
}

pub(crate) fn parse_u16(digits: &[u8]) -> Option<u16> {
    parse_usize(digits).and_then(|value| u16::try_from(value).ok())
}

pub(crate) fn dictionary_at(pdf: &[u8], cursor: usize) -> Option<(Vec<u8>, usize)> {
    let start = skip_pdf_whitespace(pdf, cursor);
    if !pdf.get(start..)?.starts_with(b"<<") {
        return None;
    }

    let mut cursor = start;
    let mut depth = 0_u32;
    let mut state = Scan::Regular;
    while cursor < pdf.len() {
        let byte = pdf[cursor];
        match state {
            Scan::Regular => match byte {
                b'%' => {
                    state = Scan::Comment;
                    cursor = cursor.saturating_add(1);
                }
                b'(' => {
                    state = Scan::LiteralString {
                        depth: 1,
                        escaped: false,
                    };
                    cursor = cursor.saturating_add(1);
                }
                b'<' if pdf.get(cursor.saturating_add(1)) == Some(&b'<') => {
                    depth = depth.saturating_add(1);
                    cursor = cursor.saturating_add(2);
                }
                b'<' => {
                    state = Scan::HexString;
                    cursor = cursor.saturating_add(1);
                }
                b'>' if pdf.get(cursor.saturating_add(1)) == Some(&b'>') => {
                    depth = depth.checked_sub(1)?;
                    cursor = cursor.saturating_add(2);
                    if depth == 0 {
                        return Some((pdf[start..cursor].to_vec(), cursor));
                    }
                }
                _ => cursor = cursor.saturating_add(1),
            },
            Scan::Comment => {
                cursor = cursor.saturating_add(1);
                if byte == b'\r' || byte == b'\n' {
                    state = Scan::Regular;
                }
            }
            Scan::HexString => {
                cursor = cursor.saturating_add(1);
                if byte == b'>' {
                    state = Scan::Regular;
                }
            }
            Scan::LiteralString {
                mut depth,
                mut escaped,
            } => {
                cursor = cursor.saturating_add(1);
                if escaped {
                    escaped = false;
                    state = Scan::LiteralString { depth, escaped };
                    continue;
                }
                match byte {
                    b'\\' => {
                        escaped = true;
                        state = Scan::LiteralString { depth, escaped };
                    }
                    b'(' => {
                        depth = depth.saturating_add(1);
                        state = Scan::LiteralString { depth, escaped };
                    }
                    b')' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            state = Scan::Regular;
                        } else {
                            state = Scan::LiteralString { depth, escaped };
                        }
                    }
                    _ => state = Scan::LiteralString { depth, escaped },
                }
            }
        }
    }
    None
}

/// The value bytes stored under `key` (written with or without its
/// slash) in the dictionary opening `dictionary`, resolved through the
/// value grammar so a longer name or a string never matches.
pub(crate) fn dictionary_value<'d>(dictionary: &'d [u8], key: &[u8]) -> Option<&'d [u8]> {
    let name = key.strip_prefix(b"/").unwrap_or(key);
    let parsed = PdfDictionary::parse_leading(dictionary).ok()?;
    let entry = parsed.entry(name).ok()??;
    dictionary.get(entry.value.clone())
}

/// The indirect reference stored under `key`, generation included.
pub(crate) fn dictionary_reference(dictionary: &[u8], key: &[u8]) -> Option<PdfObjectReference> {
    complete_object_reference(dictionary_value(dictionary, key)?)
        .ok()
        .flatten()
}

/// The integer stored under `key`.
pub(crate) fn dictionary_integer(dictionary: &[u8], key: &[u8]) -> Option<u32> {
    dictionary_usize(dictionary, key).and_then(|value| u32::try_from(value).ok())
}

/// The non-negative integer stored directly under `key`; `None` when
/// absent, indirect or not an integer.
pub(crate) fn dictionary_usize(dictionary: &[u8], key: &[u8]) -> Option<usize> {
    parse_usize(dictionary_value(dictionary, key)?)
}

pub(crate) fn object_body_at(
    pdf: &[u8],
    number: u32,
    generation: u16,
    offset: usize,
) -> Option<Vec<u8>> {
    let mut cursor = offset;
    let actual_number = parse_u32(read_pdf_token(pdf, &mut cursor)?)?;
    let actual_generation = parse_u16(read_pdf_token(pdf, &mut cursor)?)?;
    let keyword = read_pdf_token(pdf, &mut cursor)?;
    if actual_number != number || actual_generation != generation || keyword != b"obj" {
        return None;
    }
    let end = find_first(pdf.get(cursor..)?, b"endobj")?;
    Some(pdf[cursor..cursor.saturating_add(end)].to_vec())
}

/// The dictionary opening the object `reference` at `offset`, without
/// reading any stream data after it.
///
/// `None` when the header is not `reference`'s or a dictionary there
/// does not close; `Some(None)` when the object is another value.
fn object_dictionary_at(
    pdf: &[u8],
    reference: PdfObjectReference,
    offset: usize,
) -> Option<Option<(usize, Vec<u8>)>> {
    let mut cursor = offset;
    let actual_number = parse_u32(read_pdf_token(pdf, &mut cursor)?)?;
    let actual_generation = parse_u16(read_pdf_token(pdf, &mut cursor)?)?;
    let keyword = read_pdf_token(pdf, &mut cursor)?;
    if actual_number != reference.number
        || actual_generation != reference.generation
        || keyword != b"obj"
    {
        return None;
    }
    leading_dictionary(pdf, cursor)
}

/// The dictionary at `cursor`, with the offset of its `<<`, when the
/// value there opens with `<<`.
///
/// `None` when it opens one that does not close; `Some(None)` when the
/// value is not a dictionary.
fn leading_dictionary(bytes: &[u8], cursor: usize) -> Option<Option<(usize, Vec<u8>)>> {
    let start = skip_pdf_whitespace(bytes, cursor);
    if !bytes.get(start..)?.starts_with(b"<<") {
        return Some(None);
    }
    dictionary_at(bytes, start).map(|(dictionary, _end)| Some((start, dictionary)))
}

/// First occurrence of `needle`.
pub(crate) fn find_first(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Last occurrence of `needle`.
pub(crate) fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}
