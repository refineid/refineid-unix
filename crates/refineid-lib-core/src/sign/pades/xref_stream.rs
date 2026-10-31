//! Cross-reference streams and the object streams they index.
//!
//! A PDF 1.5 writer closes a revision with a *cross-reference stream*
//! (ISO 32000-1 sec.7.5.8): the section's entries are binary rows in a
//! stream object whose dictionary doubles as the trailer. The same
//! writers move small objects -- typically the catalog and the page
//! tree -- into *object streams* (sec.7.5.7), so reading such a file
//! means decoding both. Rows and object streams are `FlateDecode`
//! compressed, often behind a PNG row predictor (sec.7.4.4.4).
//!
//! Writing follows reading: a document whose newest section is a
//! stream is extended with a stream, because its readers have already
//! committed to following them. The rows this writer emits are left
//! unfiltered -- a handful of entries buys nothing from compression,
//! and unfiltered rows keep the update inspectable.

use super::PdfError;
use super::index::{
    MAX_XREF_ENTRIES, PdfDictionary, PdfObjectReference, PdfValueParser, XrefEntry, XrefLocation,
    XrefSection, dictionary_at, dictionary_usize, dictionary_value, find_first, parse_u16,
    parse_u32, parse_usize, read_pdf_token, skip_pdf_whitespace,
};

/// Bound on any one decoded stream, so a hostile document cannot make
/// this reader allocate without limit.
const DECODED_LIMIT: usize = 1 << 26;

/// Widest predictor row this reader accepts, in samples; ISO 32000-1
/// sec.7.4.4.4 leaves `/Columns` open, and a cross-reference row is at
/// most [`ENTRY_FIELDS`] fields of [`MAX_FIELD_WIDTH`] bytes.
const MAX_PREDICTOR_COLUMNS: usize = 256;

/// Widest `/W` field this reader accepts, in bytes: a 64-bit offset.
/// The row length, the sum of the three widths, is then at most
/// [`ENTRY_FIELDS`] times this.
const MAX_FIELD_WIDTH: usize = size_of::<u64>();

/// Most `/Index` pairs this reader accepts, an implementation limit:
/// one subsection per object of a revision that changes 65 536
/// non-adjacent objects.
const MAX_INDEX_PAIRS: usize = 1 << 16;

/// Numbers in one `/Index` pair: the first object number and the count.
const INDEX_PAIR: usize = 2;

/// The `/Columns` value when the key is absent (ISO 32000-1 Table 8).
const DEFAULT_COLUMNS: usize = 1;

/// The predictor value meaning none was applied.
const NO_PREDICTOR: usize = 1;

/// The first PNG row predictor; lower values other than none are the
/// TIFF predictor, which this reader does not decode.
const PNG_PREDICTOR_FLOOR: usize = 10;

/// PNG row filter: the row as written.
const PNG_NONE: u8 = 0;

/// PNG row filter: each byte relative to its left neighbour.
const PNG_SUB: u8 = 1;

/// PNG row filter: each byte relative to the byte above.
const PNG_UP: u8 = 2;

/// PNG row filter: each byte relative to the mean of left and above.
const PNG_AVERAGE: u8 = 3;

/// PNG row filter: each byte relative to the Paeth prediction.
const PNG_PAETH: u8 = 4;

/// The sample shape this reader decodes: one colour of eight bits,
/// which is what cross-reference streams use.
const SUPPORTED_COLORS: usize = 1;

/// Bits per component in the supported shape.
const SUPPORTED_BITS: usize = 8;

/// Fields in one cross-reference stream entry: `/W` is three wide
/// (ISO 32000-1 sec.7.5.8.2).
const ENTRY_FIELDS: usize = 3;

/// Radix of one big-endian field byte.
const BYTE_RADIX: usize = 1 << u8::BITS;

/// Type code of an entry at a byte offset in the file
/// (ISO 32000-1 Table 18; type 0 is free).
const TYPE_DIRECT: usize = 1;

/// Type code of an entry inside an object stream.
const TYPE_COMPRESSED: usize = 2;

/// Tokens per pair in an object stream's leading table: an object
/// number and its offset relative to `/First`.
const PAIR_TOKENS: usize = 2;

/// Field widths this writer emits: one type byte, a four-byte offset,
/// a two-byte generation.
const WRITTEN_WIDTHS: [usize; ENTRY_FIELDS] = [1, 4, 2];

/// One stream object: its dictionary and its decoded payload.
struct StreamObject {
    /// The stream dictionary, as written.
    dictionary: Vec<u8>,
    /// The payload with its filter and predictor undone.
    payload: Vec<u8>,
}

/// One cross-reference stream section at `offset`.
pub(super) fn parse_stream_section(pdf: &[u8], offset: usize) -> Result<XrefSection, PdfError> {
    let object = parse_stream_object(pdf, offset)?;
    if find_first(&object.dictionary, b"/XRef").is_none() {
        return Err(PdfError::MissingTrailer);
    }
    let widths: [usize; ENTRY_FIELDS] = integer_array(&object.dictionary, b"/W", ENTRY_FIELDS)?
        .try_into()
        .map_err(|_ignored| PdfError::MissingTrailer)?;
    let size = dictionary_usize(&object.dictionary, b"/Size").ok_or(PdfError::MissingTrailer)?;
    if size > MAX_XREF_ENTRIES {
        return Err(PdfError::MissingTrailer);
    }
    let mut subsections = integer_array(
        &object.dictionary,
        b"/Index",
        MAX_INDEX_PAIRS.saturating_mul(INDEX_PAIR),
    )?;
    if subsections.is_empty() {
        subsections = vec![0, size];
    }
    let entries = stream_entries(&object.payload, &widths, &subsections)?;
    Ok(XrefSection {
        trailer: object.dictionary,
        entries,
        is_stream: true,
    })
}

/// One compressed object's bytes: its slice of the object stream at
/// `container_offset` (ISO 32000-1 sec.7.5.7).
pub(super) fn compressed_body(
    pdf: &[u8],
    container_offset: usize,
    number: u32,
    position: u32,
) -> Option<Vec<u8>> {
    ObjectStream::at(pdf, container_offset)?.body(number, position)
}

/// One object stream, decoded once so each object it holds can be
/// sliced out of it (ISO 32000-1 sec.7.5.7).
pub(super) struct ObjectStream {
    /// Offset of the first object, past the leading number table.
    first: usize,
    /// How many objects the stream holds.
    count: usize,
    /// The decoded payload.
    payload: Vec<u8>,
}

impl ObjectStream {
    /// The object stream at `container_offset`, `None` when it does
    /// not parse.
    pub(super) fn at(pdf: &[u8], container_offset: usize) -> Option<Self> {
        let object = parse_stream_object(pdf, container_offset).ok()?;
        let first = dictionary_usize(&object.dictionary, b"/First")?;
        let count = dictionary_usize(&object.dictionary, b"/N")?;
        if first > object.payload.len() {
            return None;
        }
        Some(Self {
            first,
            count,
            payload: object.payload,
        })
    }

    /// The bytes of object `number` at `position` in the stream,
    /// `None` when the table does not name it there.
    pub(super) fn body(&self, number: u32, position: u32) -> Option<Vec<u8>> {
        let first = self.first;
        let count = self.count;
        let position = usize::try_from(position).ok()?;
        if position >= count {
            return None;
        }
        let header = self.payload.get(..first)?;
        let tokens: Vec<&[u8]> = header
            .split(|byte| PdfValueParser::is_whitespace(*byte))
            .filter(|token| !token.is_empty())
            .collect();
        let declared = parse_u32(tokens.get(position.saturating_mul(PAIR_TOKENS)).copied()?)?;
        if declared != number {
            return None;
        }
        let offset_token = tokens
            .get(position.saturating_mul(PAIR_TOKENS).saturating_add(1))
            .copied()?;
        let start = first.saturating_add(parse_usize(offset_token)?);
        let next = position.saturating_add(1);
        let end = if next < count {
            let token = tokens
                .get(next.saturating_mul(PAIR_TOKENS).saturating_add(1))
                .copied()?;
            first.saturating_add(parse_usize(token)?)
        } else {
            self.payload.len()
        };
        self.payload.get(start..end).map(<[u8]>::to_vec)
    }
}

/// Close the revision with a cross-reference stream: one subsection
/// per object, unfiltered rows, the stream object taking the number
/// just past the revision's other additions.
pub(super) fn push_stream_close(
    update: &mut Vec<u8>,
    xref_at: usize,
    offsets: &[(u32, usize)],
    size: u32,
    catalog_number: u32,
    previous_xref: usize,
    carried: &str,
) -> Result<(), PdfError> {
    let stream_number = size;
    let mut entries: Vec<(u32, usize)> = offsets.to_vec();
    entries.push((stream_number, xref_at));
    entries.sort_unstable_by_key(|(number, _)| *number);
    let mut index = String::new();
    let mut rows: Vec<u8> = Vec::new();
    for (number, offset) in &entries {
        let narrow = u32::try_from(*offset).map_err(|_ignored| PdfError::MissingStartXref)?;
        let _ignored = core::fmt::Write::write_fmt(&mut index, format_args!("{number} 1 "));
        rows.push(u8::try_from(TYPE_DIRECT).unwrap_or(1));
        rows.extend_from_slice(&narrow.to_be_bytes());
        rows.extend_from_slice(&0_u16.to_be_bytes());
    }
    let head = format!(
        "{stream_number} 0 obj\n<< /Type /XRef /Size {} /Root {catalog_number} 0 R \
         /Prev {previous_xref}{carried} /Index [ {index}] /W [{} {} {}] /Length {} \
         >>\nstream\n",
        stream_number.saturating_add(1),
        WRITTEN_WIDTHS[0],
        WRITTEN_WIDTHS[1],
        WRITTEN_WIDTHS[2],
        rows.len()
    );
    update.extend_from_slice(head.as_bytes());
    update.extend_from_slice(&rows);
    update.extend_from_slice(
        format!("\nendstream\nendobj\nstartxref\n{xref_at}\n%%EOF\n").as_bytes(),
    );
    Ok(())
}

/// The decoded payload of the stream object `reference` at `offset`.
///
/// # Errors
/// [`PdfError::MissingTrailer`] when the object at `offset` is not
/// `reference` or not a stream, and
/// [`PdfError::UnsupportedCrossReferenceStream`] for a filter other
/// than `FlateDecode`.
pub(super) fn stream_payload(
    pdf: &[u8],
    offset: usize,
    reference: PdfObjectReference,
) -> Result<Vec<u8>, PdfError> {
    let mut cursor = skip_pdf_whitespace(pdf, offset);
    let number = read_pdf_token(pdf, &mut cursor).and_then(parse_u32);
    let generation = read_pdf_token(pdf, &mut cursor).and_then(parse_u16);
    if number != Some(reference.number) || generation != Some(reference.generation) {
        return Err(PdfError::MissingTrailer);
    }
    parse_stream_object(pdf, offset).map(|object| object.payload)
}

/// The stream object at `offset`, its payload decoded.
fn parse_stream_object(pdf: &[u8], offset: usize) -> Result<StreamObject, PdfError> {
    let mut cursor = skip_pdf_whitespace(pdf, offset);
    let _number = parse_u32(read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?)
        .ok_or(PdfError::MissingTrailer)?;
    let _generation = parse_u16(read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?)
        .ok_or(PdfError::MissingTrailer)?;
    if read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)? != b"obj" {
        return Err(PdfError::MissingTrailer);
    }
    let (dictionary, after) = dictionary_at(pdf, cursor).ok_or(PdfError::MissingTrailer)?;
    let raw = raw_payload(pdf, after, &dictionary)?;
    let payload = decoded(&raw, &dictionary)?;
    Ok(StreamObject {
        dictionary,
        payload,
    })
}

/// The raw payload bytes between `stream` and `endstream`.
///
/// A direct `/Length` names the span exactly; without one the payload
/// runs to the `endstream` keyword, less the line ending the format
/// puts before it.
fn raw_payload(pdf: &[u8], after: usize, dictionary: &[u8]) -> Result<Vec<u8>, PdfError> {
    let keyword = find_first(pdf.get(after..).ok_or(PdfError::MissingTrailer)?, b"stream")
        .ok_or(PdfError::MissingTrailer)?;
    // The keyword is followed by CRLF or LF (ISO 32000-1 sec.7.3.8.1).
    let mut start = after
        .saturating_add(keyword)
        .saturating_add(b"stream".len());
    if pdf.get(start) == Some(&b'\r') {
        start = start.saturating_add(1);
    }
    if pdf.get(start) == Some(&b'\n') {
        start = start.saturating_add(1);
    }
    if let Some(length) = direct_length(dictionary)
        && let Some(payload) = pdf.get(start..start.saturating_add(length))
    {
        return Ok(payload.to_vec());
    }
    let tail = pdf.get(start..).ok_or(PdfError::MissingTrailer)?;
    let keyword_at = find_first(tail, b"endstream").ok_or(PdfError::MissingTrailer)?;
    let mut end = keyword_at;
    if end > 0 && tail.get(end.saturating_sub(1)) == Some(&b'\n') {
        end = end.saturating_sub(1);
    }
    if end > 0 && tail.get(end.saturating_sub(1)) == Some(&b'\r') {
        end = end.saturating_sub(1);
    }
    Ok(tail[..end].to_vec())
}

/// The direct `/Length` value, or `None` when absent or indirect.
fn direct_length(dictionary: &[u8]) -> Option<usize> {
    let parsed = PdfDictionary::parse(dictionary).ok()?;
    let entry = parsed.entry(b"Length").ok()??;
    parse_usize(trim(&dictionary[entry.value.clone()]))
}

/// The payload with its filter chain and predictor undone.
fn decoded(raw: &[u8], dictionary: &[u8]) -> Result<Vec<u8>, PdfError> {
    let inflated = if flate_only(dictionary)? {
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(raw, DECODED_LIMIT)
            .map_err(|_ignored| PdfError::MissingTrailer)?
    } else {
        raw.to_vec()
    };
    unpredicted(inflated, dictionary)
}

/// Whether the filter chain is exactly `FlateDecode`; absent means
/// the payload is raw, anything else is refused.
fn flate_only(dictionary: &[u8]) -> Result<bool, PdfError> {
    let parsed = PdfDictionary::parse(dictionary).map_err(|_ignored| PdfError::MissingTrailer)?;
    let Some(entry) = parsed
        .entry(b"Filter")
        .map_err(|_ignored| PdfError::MissingTrailer)?
    else {
        return Ok(false);
    };
    let mut name = trim(&dictionary[entry.value.clone()]);
    if let Some(inner) = name
        .strip_prefix(b"[")
        .and_then(|inner| inner.strip_suffix(b"]"))
    {
        name = trim(inner);
    }
    if name == b"/FlateDecode" {
        Ok(true)
    } else {
        Err(PdfError::UnsupportedCrossReferenceStream)
    }
}

/// The payload with the predictor `/DecodeParms` names undone
/// (ISO 32000-1 sec.7.4.4.4).
fn unpredicted(data: Vec<u8>, dictionary: &[u8]) -> Result<Vec<u8>, PdfError> {
    let Some(parameters) = decode_parameters(dictionary)? else {
        return Ok(data);
    };
    let predictor = dictionary_usize(&parameters, b"/Predictor").unwrap_or(NO_PREDICTOR);
    if predictor == NO_PREDICTOR {
        return Ok(data);
    }
    if predictor < PNG_PREDICTOR_FLOOR
        || dictionary_usize(&parameters, b"/Colors").unwrap_or(SUPPORTED_COLORS) != SUPPORTED_COLORS
        || dictionary_usize(&parameters, b"/BitsPerComponent").unwrap_or(SUPPORTED_BITS)
            != SUPPORTED_BITS
    {
        return Err(PdfError::UnsupportedCrossReferenceStream);
    }
    let columns = match dictionary_value(&parameters, b"/Columns") {
        None => DEFAULT_COLUMNS,
        Some(value) => parse_usize(trim(value)).ok_or(PdfError::UnsupportedCrossReferenceStream)?,
    };
    if columns == 0 || columns > MAX_PREDICTOR_COLUMNS {
        return Err(PdfError::UnsupportedCrossReferenceStream);
    }
    png_unfiltered(&data, columns)
}

/// The direct `/DecodeParms` dictionary, under either spelling.
fn decode_parameters(dictionary: &[u8]) -> Result<Option<Vec<u8>>, PdfError> {
    let parsed = PdfDictionary::parse(dictionary).map_err(|_ignored| PdfError::MissingTrailer)?;
    let entry = match parsed
        .entry(b"DecodeParms")
        .map_err(|_ignored| PdfError::MissingTrailer)?
    {
        Some(entry) => Some(entry),
        None => parsed
            .entry(b"DP")
            .map_err(|_ignored| PdfError::MissingTrailer)?,
    };
    let Some(entry) = entry else { return Ok(None) };
    let value = trim(&dictionary[entry.value.clone()]);
    if value.starts_with(b"<<") {
        return Ok(Some(value.to_vec()));
    }
    // An indirect or array-shaped parameter set is not a shape this
    // reader follows.
    Err(PdfError::UnsupportedCrossReferenceStream)
}

/// The rows with their per-row PNG filters undone, one-byte samples.
fn png_unfiltered(data: &[u8], columns: usize) -> Result<Vec<u8>, PdfError> {
    let stride = columns.saturating_add(1);
    if columns == 0 || !data.len().is_multiple_of(stride) {
        return Err(PdfError::MissingTrailer);
    }
    let mut out = Vec::with_capacity(data.len().saturating_sub(data.len() / stride));
    let mut above = vec![0_u8; columns];
    for row in data.chunks_exact(stride) {
        let filter = row[0];
        let mut decoded = vec![0_u8; columns];
        for column in 0..columns {
            let raw = row[column.saturating_add(1)];
            let left = if column > 0 { decoded[column - 1] } else { 0 };
            let upper = above[column];
            let upper_left = if column > 0 { above[column - 1] } else { 0 };
            let prediction = match filter {
                PNG_NONE => 0,
                PNG_SUB => left,
                PNG_UP => upper,
                PNG_AVERAGE => average(left, upper),
                PNG_PAETH => paeth(left, upper, upper_left),
                _ => return Err(PdfError::MissingTrailer),
            };
            decoded[column] = raw.wrapping_add(prediction);
        }
        out.extend_from_slice(&decoded);
        above = decoded;
    }
    Ok(out)
}

/// The mean of the left and upper neighbours, rounded down.
fn average(left: u8, upper: u8) -> u8 {
    let sum = u16::from(left) + u16::from(upper);
    u8::try_from(sum / 2).unwrap_or(u8::MAX)
}

/// The Paeth prediction: whichever neighbour is closest to the
/// initial estimate `left + upper - upper_left`.
fn paeth(left: u8, upper: u8, upper_left: u8) -> u8 {
    let estimate = i32::from(left) + i32::from(upper) - i32::from(upper_left);
    let distance_left = (estimate - i32::from(left)).abs();
    let distance_upper = (estimate - i32::from(upper)).abs();
    let distance_upper_left = (estimate - i32::from(upper_left)).abs();
    if distance_left <= distance_upper && distance_left <= distance_upper_left {
        left
    } else if distance_upper <= distance_upper_left {
        upper
    } else {
        upper_left
    }
}

/// The decoded entry rows as section entries (ISO 32000-1 sec.7.5.8.3).
fn stream_entries(
    payload: &[u8],
    widths: &[usize; ENTRY_FIELDS],
    subsections: &[usize],
) -> Result<Vec<XrefEntry>, PdfError> {
    if widths.iter().any(|width| *width > MAX_FIELD_WIDTH) {
        return Err(PdfError::MissingTrailer);
    }
    let row_length = widths.iter().sum::<usize>();
    let (pairs, odd) = subsections.as_chunks::<INDEX_PAIR>();
    if row_length == 0 || !odd.is_empty() {
        return Err(PdfError::MissingTrailer);
    }
    // Every declared entry is a number below the ceiling and a full row
    // of the payload, and the pairs together declare no more entries
    // than the ceiling; all hold before anything is allocated.
    let mut declared = 0_usize;
    for [first, count] in pairs {
        let end = first.checked_add(*count).ok_or(PdfError::MissingTrailer)?;
        declared = declared
            .checked_add(*count)
            .ok_or(PdfError::MissingTrailer)?;
        if end > MAX_XREF_ENTRIES || declared > MAX_XREF_ENTRIES {
            return Err(PdfError::MissingTrailer);
        }
    }
    if declared
        .checked_mul(row_length)
        .is_none_or(|needed| needed > payload.len())
    {
        return Err(PdfError::MissingTrailer);
    }
    let mut entries = Vec::with_capacity(declared);
    let mut cursor = 0_usize;
    for [first, count] in pairs {
        let first = *first;
        for entry in 0..*count {
            let row = payload
                .get(cursor..cursor.saturating_add(row_length))
                .ok_or(PdfError::MissingTrailer)?;
            cursor = cursor.saturating_add(row_length);
            let number = u32::try_from(first.saturating_add(entry))
                .map_err(|_ignored| PdfError::MissingTrailer)?;
            entries.push(entry_from_row(number, row, widths)?);
        }
    }
    Ok(entries)
}

/// One entry from one row's big-endian fields.
///
/// A zero-width type field defaults to a direct entry; other absent
/// fields default to zero. Free, and any type this reader does not
/// know, claims the number with no location -- a reference to such an
/// object is a reference to null.
fn entry_from_row(
    number: u32,
    row: &[u8],
    widths: &[usize; ENTRY_FIELDS],
) -> Result<XrefEntry, PdfError> {
    let mut fields = [0_usize; ENTRY_FIELDS];
    let mut at = 0_usize;
    for (position, width) in widths.iter().enumerate() {
        let mut value = 0_usize;
        for _ in 0..*width {
            let byte = row.get(at).copied().ok_or(PdfError::MissingTrailer)?;
            value = value
                .checked_mul(BYTE_RADIX)
                .and_then(|wide| wide.checked_add(usize::from(byte)))
                .ok_or(PdfError::MissingTrailer)?;
            at = at.saturating_add(1);
        }
        if position == 0 && *width == 0 {
            value = TYPE_DIRECT;
        }
        fields[position] = value;
    }
    let location = match fields[0] {
        TYPE_DIRECT => XrefLocation::Direct { offset: fields[1] },
        TYPE_COMPRESSED => XrefLocation::Compressed {
            container: u32::try_from(fields[1]).map_err(|_ignored| PdfError::MissingTrailer)?,
            position: u32::try_from(fields[2]).map_err(|_ignored| PdfError::MissingTrailer)?,
        },
        _ => XrefLocation::Free,
    };
    Ok(XrefEntry {
        number,
        generation: 0,
        location,
    })
}

/// The direct integer array under `key`, empty when absent or
/// malformed.
///
/// # Errors
/// [`PdfError::MissingTrailer`] once the array holds more than
/// `limit` numbers; collecting stops there.
fn integer_array(dictionary: &[u8], key: &[u8], limit: usize) -> Result<Vec<usize>, PdfError> {
    let Some(value) = dictionary_value(dictionary, key) else {
        return Ok(Vec::new());
    };
    let Some(body) = trim(value)
        .strip_prefix(b"[")
        .and_then(|inner| inner.strip_suffix(b"]"))
    else {
        return Ok(Vec::new());
    };
    let mut values = Vec::new();
    for token in body
        .split(|byte| PdfValueParser::is_whitespace(*byte))
        .filter(|token| !token.is_empty())
    {
        if values.len() == limit {
            return Err(PdfError::MissingTrailer);
        }
        let Some(value) = parse_usize(token) else {
            return Ok(Vec::new());
        };
        values.push(value);
    }
    Ok(values)
}

/// `bytes` without leading and trailing PDF whitespace.
fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !PdfValueParser::is_whitespace(*byte))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !PdfValueParser::is_whitespace(*byte))
        .map_or(start, |found| found.saturating_add(1));
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::{
        ENTRY_FIELDS, INDEX_PAIR, MAX_FIELD_WIDTH, MAX_INDEX_PAIRS, MAX_PREDICTOR_COLUMNS,
        MAX_XREF_ENTRIES, PNG_NONE, PdfError, TYPE_DIRECT, XrefLocation, parse_stream_section,
        png_unfiltered,
    };

    /// zlib compression level for test payloads; any level decodes.
    const LEVEL: u8 = 6;

    /// Field widths of the test rows: type, two offset bytes, two
    /// generation bytes.
    const WIDTHS: &str = "/W [1 2 2]";

    /// Bytes in one row under [`WIDTHS`].
    const ROW: usize = 5;

    /// The PNG Up predictor as `/DecodeParms` names it.
    const PNG_UP_PREDICTOR: usize = 12;

    /// One cross-reference stream object at offset zero.
    fn section(keys: &str, payload: &[u8]) -> Vec<u8> {
        let mut pdf = format!(
            "1 0 obj\n<< /Type /XRef {keys} /Length {} >>\nstream\n",
            payload.len()
        )
        .into_bytes();
        pdf.extend_from_slice(payload);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        pdf
    }

    /// An empty payload, `FlateDecode` compressed.
    fn empty_flate() -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec_zlib(&[], LEVEL)
    }

    /// `rows` free rows of [`ROW`] bytes.
    fn free_rows(rows: usize) -> Vec<u8> {
        vec![0; rows.saturating_mul(ROW)]
    }

    /// The entry count of the section, or why it was refused.
    fn parsed(keys: &str, payload: &[u8]) -> Result<usize, PdfError> {
        parse_stream_section(&section(keys, payload), 0).map(|section| section.entries.len())
    }

    /// `/DecodeParms` naming the PNG Up predictor over `columns`.
    fn predicted(columns: &str) -> String {
        format!(
            "/Filter /FlateDecode \
             /DecodeParms << /Predictor {PNG_UP_PREDICTOR} /Columns {columns} >>"
        )
    }

    #[test]
    fn columns_over_the_ceiling_are_refused_before_allocation() {
        for columns in [
            MAX_PREDICTOR_COLUMNS + 1,
            isize::MAX.unsigned_abs(),
            usize::MAX,
        ] {
            let keys = format!("/Size 1 {WIDTHS} {}", predicted(&columns.to_string()));
            assert_eq!(
                parsed(&keys, &empty_flate()),
                Err(PdfError::UnsupportedCrossReferenceStream)
            );
        }
    }

    #[test]
    fn the_widest_accepted_columns_still_decode() {
        let keys = format!(
            "/Size 0 {WIDTHS} {}",
            predicted(&MAX_PREDICTOR_COLUMNS.to_string())
        );
        assert_eq!(parsed(&keys, &empty_flate()), Ok(0));
        let mut row = vec![PNG_NONE];
        row.extend((0..MAX_PREDICTOR_COLUMNS).map(|column| column.to_le_bytes()[0]));
        assert_eq!(
            png_unfiltered(&row, MAX_PREDICTOR_COLUMNS).as_deref(),
            Ok(&row[1..])
        );
    }

    #[test]
    fn zero_columns_are_refused() {
        let keys = format!("/Size 1 {WIDTHS} {}", predicted("0"));
        assert_eq!(
            parsed(&keys, &empty_flate()),
            Err(PdfError::UnsupportedCrossReferenceStream)
        );
        assert_eq!(png_unfiltered(&[], 0), Err(PdfError::MissingTrailer));
    }

    #[test]
    fn malformed_columns_are_refused() {
        for columns in ["-1", "1.5", "/One", "1 0 R"] {
            let keys = format!("/Size 1 {WIDTHS} {}", predicted(columns));
            assert_eq!(
                parsed(&keys, &empty_flate()),
                Err(PdfError::UnsupportedCrossReferenceStream)
            );
        }
    }

    #[test]
    fn absent_columns_default_to_one() {
        // One one-byte row behind its filter byte decodes only when the
        // row is one column wide.
        let rows = miniz_oxide::deflate::compress_to_vec_zlib(&[PNG_NONE, u8::MIN], LEVEL);
        let keys = format!(
            "/Size 1 /W [0 0 1] /Filter /FlateDecode \
             /DecodeParms << /Predictor {PNG_UP_PREDICTOR} >>"
        );
        assert_eq!(parsed(&keys, &rows), Ok(1));
    }

    #[test]
    fn a_fourth_width_is_refused() {
        let widths = ["1"; ENTRY_FIELDS + 1].join(" ");
        let keys = format!("/Size 1 /W [{widths}]");
        assert_eq!(parsed(&keys, &free_rows(1)), Err(PdfError::MissingTrailer));
    }

    #[test]
    fn an_index_over_the_pair_ceiling_is_refused() {
        let numbers = MAX_INDEX_PAIRS.saturating_mul(INDEX_PAIR);
        let over = vec!["0"; numbers + INDEX_PAIR].join(" ");
        let keys = format!("/Size 1 /Index [{over}] {WIDTHS}");
        assert_eq!(parsed(&keys, &free_rows(1)), Err(PdfError::MissingTrailer));
        // At the ceiling the pairs are read; empty pairs declare nothing.
        let mut at = vec!["0"; numbers - INDEX_PAIR];
        at.extend(["0", "1"]);
        let keys = format!("/Size 1 /Index [{}] {WIDTHS}", at.join(" "));
        assert_eq!(parsed(&keys, &free_rows(1)), Ok(1));
    }

    #[test]
    fn a_width_over_the_ceiling_is_refused() {
        let keys = format!("/Size 1 /W [1 {} 2]", MAX_FIELD_WIDTH + 1);
        assert_eq!(parsed(&keys, &free_rows(1)), Err(PdfError::MissingTrailer));
    }

    #[test]
    fn widths_whose_sum_overflows_are_refused() {
        let keys = format!("/Size 1 /W [{} {} 1]", usize::MAX, usize::MAX);
        assert_eq!(parsed(&keys, &free_rows(1)), Err(PdfError::MissingTrailer));
    }

    #[test]
    fn malformed_index_and_widths_are_refused() {
        let keys = format!("/Size 1 /Index [0 1 2] {WIDTHS}");
        assert_eq!(parsed(&keys, &free_rows(1)), Err(PdfError::MissingTrailer));
        for widths in ["/W [1 4]", "/W [1 2 2 1]", "/W []", "/W [0 0 0]"] {
            let keys = format!("/Size 1 {widths}");
            assert_eq!(parsed(&keys, &free_rows(1)), Err(PdfError::MissingTrailer));
        }
    }

    #[test]
    fn a_size_over_the_ceiling_is_refused() {
        let keys = format!("/Size {} {WIDTHS}", MAX_XREF_ENTRIES + 1);
        assert_eq!(parsed(&keys, &free_rows(1)), Err(PdfError::MissingTrailer));
        let keys = format!("/Size {MAX_XREF_ENTRIES} /Index [0 1] {WIDTHS}");
        assert_eq!(parsed(&keys, &free_rows(1)), Ok(1));
    }

    #[test]
    fn index_pairs_over_the_ceiling_together_are_refused() {
        let keys = format!("/Size 1 /Index [0 1 0 {MAX_XREF_ENTRIES}] {WIDTHS}");
        assert_eq!(parsed(&keys, &free_rows(1)), Err(PdfError::MissingTrailer));
        let keys = format!("/Size 1 /Index [0 1 0 1] {WIDTHS}");
        assert_eq!(parsed(&keys, &free_rows(2)), Ok(2));
    }

    #[test]
    fn an_index_past_the_object_ceiling_is_refused() {
        let keys = format!("/Size 1 /Index [{MAX_XREF_ENTRIES} 1] {WIDTHS}");
        assert_eq!(parsed(&keys, &free_rows(1)), Err(PdfError::MissingTrailer));
        let keys = format!("/Size 1 /Index [{} 1] {WIDTHS}", MAX_XREF_ENTRIES - 1);
        assert_eq!(parsed(&keys, &free_rows(1)), Ok(1));
    }

    #[test]
    fn index_counts_whose_sum_overflows_are_refused() {
        let keys = format!(
            "/Size 1 /Index [0 {} 0 {}] {WIDTHS}",
            usize::MAX,
            usize::MAX
        );
        assert_eq!(parsed(&keys, &free_rows(1)), Err(PdfError::MissingTrailer));
        let keys = format!("/Size 1 /Index [{} 1] {WIDTHS}", usize::MAX);
        assert_eq!(parsed(&keys, &free_rows(1)), Err(PdfError::MissingTrailer));
    }

    #[test]
    fn declared_entries_beyond_the_payload_are_refused() {
        let declared = 4;
        let keys = format!("/Size {declared} /Index [0 {declared}] {WIDTHS}");
        assert_eq!(
            parsed(&keys, &free_rows(declared - 1)),
            Err(PdfError::MissingTrailer)
        );
        assert_eq!(parsed(&keys, &free_rows(declared)), Ok(declared));
    }

    #[test]
    fn a_sixty_four_bit_offset_field_is_read() {
        let offset: u64 = 1 << u8::BITS;
        let mut row = vec![u8::try_from(TYPE_DIRECT).expect("a type code is one byte")];
        row.extend(offset.to_be_bytes());
        row.extend(u16::MIN.to_be_bytes());
        let keys = format!("/Size 1 /W [1 {MAX_FIELD_WIDTH} 2]");
        let section = parse_stream_section(&section(&keys, &row), 0).expect("the row is read");
        assert!(matches!(
            section.entries.as_slice(),
            [entry] if entry.location == XrefLocation::Direct {
                offset: usize::try_from(offset).expect("the offset fits"),
            }
        ));
    }
}
