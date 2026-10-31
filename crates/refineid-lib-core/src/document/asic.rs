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

//! Reading an `ASiC-E` or `BDOC` container: the ZIP archive
//! [`crate::sign::asic`] writes, and the ones `DigiDoc` writes.
//!
//! The archive is read the way an extractor reads it. The end of
//! central directory record names the central directory, the central
//! directory names every entry, and each local header must agree with
//! its record. Whatever could make two readers see different files is
//! refused: bytes after the end record, a central directory that does
//! not end at it, local entries that do not tile the archive exactly,
//! a name that is not a plain relative path or repeats another after
//! case folding, data whose CRC-32 is not the declared one, an entry
//! that is a symbolic link, and ZIP64, multi-volume, encrypted or
//! unknown-method entries. Decompressed sizes are bounded.
//!
//! The entries are then sorted by role: the data files, the `XAdES`
//! signature files, and each `CAdES` signature with the `ASiCManifest`
//! that names it.
//!
//! # Conformance
//!
//! - `ETSI EN 319 162-1` V1.1.1 clause 4.4 and annex A.1 to A.5: the
//!   `mimetype` entry, `META-INF/*signatures*.xml` for `XAdES`,
//!   `META-INF/*signature*.p7s` with `META-INF/*ASiCManifest*.xml` for
//!   `CAdES`, data files outside `META-INF/`.
//! - `ISO/IEC 21320-1` and PKWARE `APPNOTE.TXT` 6.3: stored (0) or
//!   deflated (8) entries, single volume, no encryption; sec.4.3.9
//!   the data descriptor, sec.4.3.12 the central directory record,
//!   sec.4.3.16 the end of central directory record.

use crate::document::DocumentFile;
use crate::document::xades::{DigestMethod, decode_base64};
use crate::document::xml::{ElementRef, XmlDocument};
use crate::sign::asic::NAMESPACE_ASIC;
use crate::sign::xades::NAMESPACE_DSIG;

/// The entry naming the container's media type (EN 319 162-1 A.1).
const MIMETYPE_ENTRY: &str = "mimetype";

/// Media type of an `ASiC-E` container (EN 319 162-1 annex A.1); `BDOC
/// 2.1` carries the same.
const MIMETYPE_ASICE: &str = "application/vnd.etsi.asic-e+zip";

/// Media type of a `BDOC 1.0` container.
const MIMETYPE_BDOC: &str = "application/vnd.bdoc-1.0";

/// The folder holding signatures and manifests (EN 319 162-1 A.4).
const META_INF: &str = "META-INF/";

/// What an `XAdES` signature file's name contains (EN 319 162-1
/// clause 4.4.3.2).
const XADES_NAME_PART: &str = "signatures";

/// What a `CAdES` signature file's name contains (EN 319 162-1 clause
/// 4.4.3.1).
const CADES_NAME_PART: &str = "signature";

/// What an `ASiCManifest` file's name contains (EN 319 162-1 annex A.5).
const MANIFEST_NAME_PART: &str = "ASiCManifest";

/// Extension of an XML file.
const EXTENSION_XML: &str = ".xml";

/// Extension of a detached `CMS` signature.
const EXTENSION_P7S: &str = ".p7s";

/// Root element of an `ASiCManifest` (EN 319 162-1 annex A.5).
const ELEMENT_MANIFEST: &str = "ASiCManifest";

/// The element naming the signature a manifest is signed by.
const ELEMENT_SIG_REFERENCE: &str = "SigReference";

/// The element naming one data file and its digest (EN 319 162-1
/// annex A.5).
const ELEMENT_DATA_OBJECT_REFERENCE: &str = "DataObjectReference";

/// The `ds:DigestMethod` inside a `DataObjectReference`.
const ELEMENT_DIGEST_METHOD: &str = "DigestMethod";

/// The `ds:DigestValue` inside a `DataObjectReference`.
const ELEMENT_DIGEST_VALUE: &str = "DigestValue";

/// The attribute carrying a reference's target.
const ATTRIBUTE_URI: &str = "URI";

/// The attribute naming a digest algorithm.
const ATTRIBUTE_ALGORITHM: &str = "Algorithm";

/// Local file header signature (APPNOTE 4.3.7).
const SIGNATURE_LOCAL_HEADER: u32 = 0x0403_4B50;

/// Central directory record signature (APPNOTE 4.3.12).
const SIGNATURE_CENTRAL_HEADER: u32 = 0x0201_4B50;

/// End of central directory record signature (APPNOTE 4.3.16).
const SIGNATURE_END_OF_DIRECTORY: u32 = 0x0605_4B50;

/// Data descriptor signature, which may precede one (APPNOTE 4.3.9.3).
const SIGNATURE_DATA_DESCRIPTOR: u32 = 0x0807_4B50;

/// ZIP64 end of central directory locator signature (APPNOTE 4.3.15).
const SIGNATURE_ZIP64_LOCATOR: u32 = 0x0706_4B50;

/// Length of the ZIP64 end of central directory locator (APPNOTE 4.3.15).
const ZIP64_LOCATOR_LEN: usize = 20;

/// General-purpose bit 0: the entry is encrypted (APPNOTE 4.4.4).
const FLAG_ENCRYPTED: u16 = 0x0001;

/// General-purpose bit 3: CRC and sizes follow the data in a data
/// descriptor (APPNOTE 4.4.4).
const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;

/// General-purpose bit 6: strong encryption (APPNOTE 4.4.4).
const FLAG_STRONG_ENCRYPTION: u16 = 0x0040;

/// Compression method 0: stored (APPNOTE 4.4.5).
const METHOD_STORED: u16 = 0;

/// Compression method 8: deflated (APPNOTE 4.4.5).
const METHOD_DEFLATED: u16 = 8;

/// Fixed part of the end of central directory record, signature
/// included (APPNOTE 4.3.16).
const END_OF_DIRECTORY_LEN: usize = 22;

/// Longest archive comment: its length field is 16 bits.
const MAX_ARCHIVE_COMMENT_LEN: usize = 0xFFFF;

/// A 16-bit field holding this value defers to a ZIP64 record
/// (APPNOTE 4.4.1.4).
const ZIP64_MARKER_U16: u16 = u16::MAX;

/// A 32-bit field holding this value defers to a ZIP64 record.
const ZIP64_MARKER_U32: u32 = u32::MAX;

/// The only disk number a single-volume archive carries.
const SINGLE_DISK: u16 = 0;

/// Extra field header id of the ZIP64 extended information (APPNOTE
/// 4.5.3).
const EXTRA_ZIP64: u16 = 0x0001;

/// Extra field header id of the Info-ZIP Unicode Path (APPNOTE 4.6.9),
/// which would give an extractor another name.
const EXTRA_UNICODE_PATH: u16 = 0x7075;

/// Shift to the host-dependent upper half of the external attributes,
/// where a Unix archiver stores the file mode (APPNOTE 4.4.15).
const UNIX_MODE_SHIFT: u32 = 16;

/// `S_IFMT`: the file-type bits of a Unix mode (POSIX `<sys/stat.h>`).
const UNIX_FILE_TYPE_MASK: u32 = 0o170_000;

/// `S_IFLNK`: the symbolic-link file type.
const UNIX_SYMBOLIC_LINK: u32 = 0o120_000;

/// Path separator inside an archive (APPNOTE 4.4.17.1).
const ENTRY_SEPARATOR: char = '/';

/// The separator an archive name must not use (APPNOTE 4.4.17.1).
const FORBIDDEN_SEPARATOR: char = '\\';

/// Most entries a container may carry.
const MAX_ENTRIES: usize = 4096;

/// Most decompressed bytes in the whole container: 512 MiB.
const MAX_TOTAL_BYTES: usize = 0x2000_0000;

/// Octets of a little-endian `u16`.
const U16_LEN: usize = 2;

/// Octets of a little-endian `u32`.
const U32_LEN: usize = 4;

/// Why a container yielded no entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsicReadError {
    /// The file does not start as a ZIP archive does.
    NotAZip,
    /// The archive structure is inconsistent.
    Malformed(&'static str),
    /// A ZIP feature outside the `ASiC` profile.
    Unsupported(&'static str),
}

impl core::fmt::Display for AsicReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAZip => f.write_str("not a ZIP archive"),
            Self::Malformed(what) => write!(f, "malformed container: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported container: {what}"),
        }
    }
}

impl core::error::Error for AsicReadError {}

/// The container's media type, from its `mimetype` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mimetype {
    /// `application/vnd.etsi.asic-e+zip`: `ASiC-E`, and `BDOC 2.1`.
    AsicE,
    /// `application/vnd.bdoc-1.0`.
    Bdoc,
    /// No `mimetype` entry, or one naming another type.
    Other,
}

/// One file inside the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The entry name: a plain relative path from the container root.
    pub name: String,
    /// The decompressed content, CRC-checked.
    pub content: Vec<u8>,
}

/// A `CAdES` signature file with the manifest it signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CadesEntry {
    /// `META-INF/*signature*.p7s`.
    pub signature: Entry,
    /// The `META-INF/*ASiCManifest*.xml` whose `SigReference` names the
    /// signature; `None` when no manifest names it.
    pub manifest: Option<Entry>,
}

/// A read container, its entries sorted by role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsicContainer {
    /// From the `mimetype` entry.
    mimetype: Mimetype,
    /// Entries outside `META-INF/`, `mimetype` excluded.
    data_files: Vec<Entry>,
    /// `META-INF/*signatures*.xml`.
    xades_signature_files: Vec<Entry>,
    /// `META-INF/*signature*.p7s` with their manifests.
    cades_signatures: Vec<CadesEntry>,
}

impl AsicContainer {
    /// Read the container in `file`.
    ///
    /// # Errors
    /// [`AsicReadError::NotAZip`] when the file does not start with a
    /// local file header; otherwise the structural refusals the module
    /// documentation lists.
    pub fn parse(file: &DocumentFile) -> Result<Self, AsicReadError> {
        let entries = read_zip(file.as_bytes())?;
        Ok(Self::sort(entries))
    }

    /// Sort entries by role.
    fn sort(entries: Vec<Entry>) -> Self {
        let mut mimetype = Mimetype::Other;
        let mut data_files = Vec::new();
        let mut xades_signature_files = Vec::new();
        let mut cades_files = Vec::new();
        let mut manifests = Vec::new();
        for entry in entries {
            if entry.name == MIMETYPE_ENTRY {
                mimetype = match entry.content.as_slice() {
                    content if content == MIMETYPE_ASICE.as_bytes() => Mimetype::AsicE,
                    content if content == MIMETYPE_BDOC.as_bytes() => Mimetype::Bdoc,
                    _ => Mimetype::Other,
                };
                continue;
            }
            let Some(inside) = entry.name.strip_prefix(META_INF) else {
                data_files.push(entry);
                continue;
            };
            // Signature files sit directly in META-INF, not below it.
            if inside.contains(ENTRY_SEPARATOR) {
                continue;
            }
            if inside.contains(XADES_NAME_PART) && inside.ends_with(EXTENSION_XML) {
                xades_signature_files.push(entry);
            } else if inside.contains(CADES_NAME_PART) && inside.ends_with(EXTENSION_P7S) {
                cades_files.push(entry);
            } else if inside.contains(MANIFEST_NAME_PART) && inside.ends_with(EXTENSION_XML) {
                manifests.push(entry);
            }
        }
        let cades_signatures = cades_files
            .into_iter()
            .map(|signature| {
                let manifest = manifests
                    .iter()
                    .find(|manifest| manifest_names(manifest, &signature.name))
                    .cloned();
                CadesEntry {
                    signature,
                    manifest,
                }
            })
            .collect();
        Self {
            mimetype,
            data_files,
            xades_signature_files,
            cades_signatures,
        }
    }

    /// The media type the `mimetype` entry names.
    #[must_use]
    pub const fn mimetype(&self) -> Mimetype {
        self.mimetype
    }

    /// Every entry outside `META-INF/` other than `mimetype`, in
    /// archive order.
    #[must_use]
    pub fn data_files(&self) -> &[Entry] {
        &self.data_files
    }

    /// `META-INF/*signatures*.xml`, in archive order.
    #[must_use]
    pub fn xades_signature_files(&self) -> &[Entry] {
        &self.xades_signature_files
    }

    /// `META-INF/*signature*.p7s` with the manifests naming them, in
    /// archive order.
    #[must_use]
    pub fn cades_signatures(&self) -> &[CadesEntry] {
        &self.cades_signatures
    }

    /// The data file of this name.
    #[must_use]
    pub fn data_file(&self, name: &str) -> Option<&Entry> {
        self.data_files.iter().find(|entry| entry.name == name)
    }

    /// Whether the `ASiCManifest` paired with `entry` binds exactly
    /// this container's data files to its signature (EN 319 162-1
    /// annex A.5 and A.6): it parses, its one `SigReference` names
    /// `entry.signature`, every `DataObjectReference` names a data file
    /// whose digest under a `SHA-256`, `SHA-384` or `SHA-512`
    /// `DigestMethod` equals its `DigestValue`, and every data file is
    /// referenced. A missing manifest, an unknown digest method, a
    /// missing file or an unreferenced data file gives false.
    ///
    /// The signature over the manifest bytes is judged by
    /// [`crate::document::cades`].
    #[must_use]
    pub fn manifest_intact(&self, entry: &CadesEntry) -> bool {
        let Some(manifest) = &entry.manifest else {
            return false;
        };
        let Ok(document) = XmlDocument::parse(manifest.content.clone()) else {
            return false;
        };
        let root = document.root();
        if !root.is(NAMESPACE_ASIC, ELEMENT_MANIFEST) {
            return false;
        }
        let mut sig_references = root.children_named(NAMESPACE_ASIC, ELEMENT_SIG_REFERENCE);
        let names_signature = match (sig_references.next(), sig_references.next()) {
            (Some(reference), None) => reference
                .attribute(ATTRIBUTE_URI)
                .and_then(percent_decode)
                .is_some_and(|uri| uri == entry.signature.name),
            _ => false,
        };
        let mut referenced: Vec<&str> = Vec::new();
        for reference in root.children_named(NAMESPACE_ASIC, ELEMENT_DATA_OBJECT_REFERENCE) {
            let Some(file) = reference
                .attribute(ATTRIBUTE_URI)
                .and_then(percent_decode)
                .and_then(|name| self.data_file(&name))
            else {
                return false;
            };
            let Some(method) = reference
                .child(NAMESPACE_DSIG, ELEMENT_DIGEST_METHOD)
                .and_then(|method| method.attribute(ATTRIBUTE_ALGORITHM))
                .and_then(DigestMethod::from_uri)
            else {
                return false;
            };
            let Some(value) = reference
                .child(NAMESPACE_DSIG, ELEMENT_DIGEST_VALUE)
                .and_then(|value| decode_base64(&value.text()))
            else {
                return false;
            };
            if method.digest(&file.content) != value {
                return false;
            }
            referenced.push(&file.name);
        }
        names_signature
            && self
                .data_files
                .iter()
                .all(|file| referenced.contains(&file.name.as_str()))
    }
}

/// Whether `manifest` is an `ASiCManifest` whose `SigReference` names
/// the entry `signature_name`. A manifest that does not parse names
/// nothing.
fn manifest_names(manifest: &Entry, signature_name: &str) -> bool {
    let Ok(document) = XmlDocument::parse(manifest.content.clone()) else {
        return false;
    };
    let root: ElementRef<'_> = document.root();
    if !root.is(NAMESPACE_ASIC, ELEMENT_MANIFEST) {
        return false;
    }
    root.children_named(NAMESPACE_ASIC, ELEMENT_SIG_REFERENCE)
        .filter_map(|reference| reference.attribute(ATTRIBUTE_URI))
        .filter_map(percent_decode)
        .any(|uri| uri == signature_name)
}

/// Decode `%XX` escapes in a reference URI (RFC 3986 sec.2.1) into the
/// UTF-8 entry name they spell. `None` for a malformed escape or a
/// result that is not UTF-8.
pub(crate) fn percent_decode(uri: &str) -> Option<String> {
    /// Radix of a percent escape's two digits.
    const RADIX_HEX: u32 = 16;
    /// Digits in one escape.
    const ESCAPE_DIGITS: usize = 2;
    let mut out = Vec::with_capacity(uri.len());
    let mut bytes = uri.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let digits: Vec<u8> = bytes.by_ref().take(ESCAPE_DIGITS).collect();
            let text = core::str::from_utf8(&digits).ok()?;
            if text.len() != ESCAPE_DIGITS || !text.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(text, RADIX_HEX).ok()?);
        } else {
            out.push(byte);
        }
    }
    String::from_utf8(out).ok()
}

/// Where the central directory sits, from the end record.
struct EndOfDirectory {
    /// Offset of the end record: where the central directory must end.
    offset: usize,
    /// Number of central directory records.
    count: usize,
    /// Offset of the first central directory record.
    central_offset: usize,
}

/// One central directory record.
struct CentralRecord {
    /// General-purpose flags.
    flags: u16,
    /// Compression method.
    method: u16,
    /// CRC-32 of the uncompressed data.
    crc: u32,
    /// Stored length.
    compressed_len: usize,
    /// Decompressed length.
    uncompressed_len: usize,
    /// Entry name as stored.
    name: Vec<u8>,
    /// Offset of the local file header.
    local_offset: usize,
}

/// The archive extent one local entry occupies.
struct LocalExtent {
    /// The local header's offset.
    start: usize,
    /// One past the data, or the data descriptor.
    end: usize,
}

/// Read every entry the central directory lists.
fn read_zip(bytes: &[u8]) -> Result<Vec<Entry>, AsicReadError> {
    if Cursor::new(bytes).u32() != Some(SIGNATURE_LOCAL_HEADER) {
        return Err(AsicReadError::NotAZip);
    }
    let end = find_end_of_directory(bytes)?;
    let records = read_central_directory(bytes, &end)?;
    let mut entries = Vec::with_capacity(records.len());
    let mut extents = Vec::with_capacity(records.len());
    let mut folded_names: Vec<String> = Vec::with_capacity(records.len());
    let mut total = 0_usize;
    for record in &records {
        total = total
            .checked_add(record.uncompressed_len)
            .filter(|declared| *declared <= MAX_TOTAL_BYTES)
            .ok_or(AsicReadError::Unsupported(
                "container exceeds the decompressed-size bound",
            ))?;
        let (entry, extent) = read_local_entry(bytes, record)?;
        extents.push(extent);
        let Some(entry) = entry else {
            continue;
        };
        let folded = entry.name.to_lowercase();
        if folded_names.contains(&folded) {
            return Err(AsicReadError::Malformed("duplicate entry name"));
        }
        folded_names.push(folded);
        entries.push(entry);
    }
    require_exact_tiling(extents, end.central_offset)?;
    Ok(entries)
}

/// Locate the end of central directory record, which must end exactly
/// at the end of the file, and check the geometry it declares.
///
/// An archive comment may itself contain the signature bytes, so a
/// candidate whose comment does not reach the end of the file is
/// skipped rather than refused.
fn find_end_of_directory(bytes: &[u8]) -> Result<EndOfDirectory, AsicReadError> {
    /// No candidate record ends the file.
    const MISSING: AsicReadError =
        AsicReadError::Malformed("no end of central directory record ends the file");
    /// A candidate record is cut short.
    const TRUNCATED: AsicReadError =
        AsicReadError::Malformed("truncated end of central directory record");
    let latest = bytes
        .len()
        .checked_sub(END_OF_DIRECTORY_LEN)
        .ok_or(MISSING)?;
    let earliest = latest.saturating_sub(MAX_ARCHIVE_COMMENT_LEN);
    for offset in (earliest..=latest).rev() {
        let mut cursor = Cursor::at(bytes, offset);
        if cursor.u32() != Some(SIGNATURE_END_OF_DIRECTORY) {
            continue;
        }
        let disk = cursor.u16().ok_or(TRUNCATED)?;
        let directory_disk = cursor.u16().ok_or(TRUNCATED)?;
        let count_on_disk = cursor.u16().ok_or(TRUNCATED)?;
        let count = cursor.u16().ok_or(TRUNCATED)?;
        let central_size = cursor.u32().ok_or(TRUNCATED)?;
        let central_offset = cursor.u32().ok_or(TRUNCATED)?;
        let comment_len = cursor.u16().ok_or(TRUNCATED)?;
        if cursor.position().checked_add(usize::from(comment_len)) != Some(bytes.len()) {
            continue;
        }
        if count_on_disk == ZIP64_MARKER_U16
            || count == ZIP64_MARKER_U16
            || central_size == ZIP64_MARKER_U32
            || central_offset == ZIP64_MARKER_U32
            || offset
                .checked_sub(ZIP64_LOCATOR_LEN)
                .is_some_and(|at| Cursor::at(bytes, at).u32() == Some(SIGNATURE_ZIP64_LOCATOR))
        {
            return Err(AsicReadError::Unsupported("ZIP64"));
        }
        if disk != SINGLE_DISK || directory_disk != SINGLE_DISK {
            return Err(AsicReadError::Unsupported("multi-volume archive"));
        }
        if count_on_disk != count {
            return Err(AsicReadError::Malformed("entry counts disagree"));
        }
        let central_offset = usize::try_from(central_offset).map_err(|_ignored| TRUNCATED)?;
        let central_size = usize::try_from(central_size).map_err(|_ignored| TRUNCATED)?;
        if central_offset.checked_add(central_size) != Some(offset) {
            return Err(AsicReadError::Malformed(
                "central directory does not end at the end record",
            ));
        }
        return Ok(EndOfDirectory {
            offset,
            count: usize::from(count),
            central_offset,
        });
    }
    Err(MISSING)
}

/// Read exactly the declared number of central directory records,
/// which must fill the central directory to the byte.
fn read_central_directory(
    bytes: &[u8],
    end: &EndOfDirectory,
) -> Result<Vec<CentralRecord>, AsicReadError> {
    if end.count > MAX_ENTRIES {
        return Err(AsicReadError::Unsupported("too many entries"));
    }
    let mut cursor = Cursor::at(bytes, end.central_offset);
    let mut records = Vec::with_capacity(end.count);
    for _ in 0..end.count {
        if cursor.u32() != Some(SIGNATURE_CENTRAL_HEADER) {
            return Err(AsicReadError::Malformed(
                "central directory record without its signature",
            ));
        }
        records.push(CentralRecord::read(&mut cursor)?);
    }
    if cursor.position() != end.offset {
        return Err(AsicReadError::Malformed(
            "central directory does not end at the end record",
        ));
    }
    Ok(records)
}

impl CentralRecord {
    /// Read one record past its signature (APPNOTE 4.3.12).
    fn read(cursor: &mut Cursor<'_>) -> Result<Self, AsicReadError> {
        /// The record is cut short.
        const TRUNCATED: AsicReadError =
            AsicReadError::Malformed("truncated central directory record");
        let _version_made_by = cursor.u16().ok_or(TRUNCATED)?;
        let _version_needed = cursor.u16().ok_or(TRUNCATED)?;
        let flags = cursor.u16().ok_or(TRUNCATED)?;
        let method = cursor.u16().ok_or(TRUNCATED)?;
        let _modification_time = cursor.u16().ok_or(TRUNCATED)?;
        let _modification_date = cursor.u16().ok_or(TRUNCATED)?;
        let crc = cursor.u32().ok_or(TRUNCATED)?;
        let compressed = cursor.u32().ok_or(TRUNCATED)?;
        let uncompressed = cursor.u32().ok_or(TRUNCATED)?;
        let name_len = cursor.u16().ok_or(TRUNCATED)?;
        let extra_len = cursor.u16().ok_or(TRUNCATED)?;
        let comment_len = cursor.u16().ok_or(TRUNCATED)?;
        let disk = cursor.u16().ok_or(TRUNCATED)?;
        let _internal_attributes = cursor.u16().ok_or(TRUNCATED)?;
        let external_attributes = cursor.u32().ok_or(TRUNCATED)?;
        let local_offset = cursor.u32().ok_or(TRUNCATED)?;
        let name = cursor
            .take(usize::from(name_len))
            .ok_or(TRUNCATED)?
            .to_vec();
        let extra = cursor.take(usize::from(extra_len)).ok_or(TRUNCATED)?;
        cursor.take(usize::from(comment_len)).ok_or(TRUNCATED)?;
        if compressed == ZIP64_MARKER_U32
            || uncompressed == ZIP64_MARKER_U32
            || local_offset == ZIP64_MARKER_U32
        {
            return Err(AsicReadError::Unsupported("ZIP64"));
        }
        if disk != SINGLE_DISK {
            return Err(AsicReadError::Unsupported("multi-volume archive"));
        }
        if (external_attributes >> UNIX_MODE_SHIFT) & UNIX_FILE_TYPE_MASK == UNIX_SYMBOLIC_LINK {
            return Err(AsicReadError::Unsupported("symbolic link entry"));
        }
        require_plain_extra_field(extra)?;
        Ok(Self {
            flags,
            method,
            crc,
            compressed_len: usize::try_from(compressed).map_err(|_ignored| TRUNCATED)?,
            uncompressed_len: usize::try_from(uncompressed).map_err(|_ignored| TRUNCATED)?,
            name,
            local_offset: usize::try_from(local_offset).map_err(|_ignored| TRUNCATED)?,
        })
    }
}

/// Walk an extra field as the (id, size, data) records APPNOTE 4.5.1
/// defines, refusing a malformed one and any that would give an
/// extractor another name or size.
fn require_plain_extra_field(extra: &[u8]) -> Result<(), AsicReadError> {
    /// The extra field is not a sequence of records.
    const MALFORMED: AsicReadError = AsicReadError::Malformed("malformed extra field");
    let mut cursor = Cursor::new(extra);
    while cursor.position() < extra.len() {
        let id = cursor.u16().ok_or(MALFORMED)?;
        let size = cursor.u16().ok_or(MALFORMED)?;
        cursor.take(usize::from(size)).ok_or(MALFORMED)?;
        match id {
            EXTRA_ZIP64 => return Err(AsicReadError::Unsupported("ZIP64")),
            EXTRA_UNICODE_PATH => {
                return Err(AsicReadError::Unsupported("Unicode Path extra field"));
            }
            _ => {}
        }
    }
    Ok(())
}

/// The entry name as a plain relative path: UTF-8, not absolute, no
/// backslash or control character, every component non-empty and
/// neither `.` nor `..`. `Ok(None)` for a directory entry, which an
/// archiver may list and which carries no file.
fn plain_entry_name(name: &[u8]) -> Result<Option<String>, AsicReadError> {
    let name = String::from_utf8(name.to_vec())
        .map_err(|_ignored| AsicReadError::Malformed("entry name is not UTF-8"))?;
    if name.is_empty() {
        return Err(AsicReadError::Malformed("empty entry name"));
    }
    if name.starts_with(ENTRY_SEPARATOR) {
        return Err(AsicReadError::Malformed("absolute entry name"));
    }
    if name.contains(FORBIDDEN_SEPARATOR) {
        return Err(AsicReadError::Malformed("backslash in an entry name"));
    }
    if name.chars().any(char::is_control) {
        return Err(AsicReadError::Malformed(
            "control character in an entry name",
        ));
    }
    let (path, directory) = match name.strip_suffix(ENTRY_SEPARATOR) {
        Some(path) => (path, true),
        None => (name.as_str(), false),
    };
    for component in path.split(ENTRY_SEPARATOR) {
        if component.is_empty() || component == "." || component == ".." {
            return Err(AsicReadError::Malformed("entry name is not a plain path"));
        }
    }
    Ok((!directory).then_some(name))
}

/// The local header fields a reader compares with the central record
/// (APPNOTE 4.3.7).
struct LocalHeader {
    /// General-purpose flags.
    flags: u16,
    /// Compression method.
    method: u16,
    /// CRC-32, zero when a data descriptor carries it.
    crc: u32,
    /// Stored length, zero when a data descriptor carries it.
    compressed_len: usize,
    /// Decompressed length, zero when a data descriptor carries it.
    uncompressed_len: usize,
    /// Name length.
    name_len: usize,
    /// Extra field length.
    extra_len: usize,
}

impl LocalHeader {
    /// Read one header past its signature.
    fn read(cursor: &mut Cursor<'_>) -> Option<Self> {
        let _version_needed = cursor.u16()?;
        let flags = cursor.u16()?;
        let method = cursor.u16()?;
        let _modification_time = cursor.u16()?;
        let _modification_date = cursor.u16()?;
        let crc = cursor.u32()?;
        let compressed = cursor.u32()?;
        let uncompressed = cursor.u32()?;
        let name_len = cursor.u16()?;
        let extra_len = cursor.u16()?;
        Some(Self {
            flags,
            method,
            crc,
            compressed_len: usize::try_from(compressed).ok()?,
            uncompressed_len: usize::try_from(uncompressed).ok()?,
            name_len: usize::from(name_len),
            extra_len: usize::from(extra_len),
        })
    }
}

/// Read the local entry a central record points at, requiring the two
/// to agree on everything that decides what the entry is. `None` for a
/// directory entry.
fn read_local_entry(
    bytes: &[u8],
    record: &CentralRecord,
) -> Result<(Option<Entry>, LocalExtent), AsicReadError> {
    let mut cursor = Cursor::at(bytes, record.local_offset);
    if cursor.u32() != Some(SIGNATURE_LOCAL_HEADER) {
        return Err(AsicReadError::Malformed(
            "central directory names an offset that is not a local header",
        ));
    }
    let header =
        LocalHeader::read(&mut cursor).ok_or(AsicReadError::Malformed("truncated local header"))?;
    let name_bytes = cursor
        .take(header.name_len)
        .ok_or(AsicReadError::Malformed("truncated entry name"))?;
    let extra = cursor
        .take(header.extra_len)
        .ok_or(AsicReadError::Malformed("truncated extra field"))?;
    if header.flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) != 0 {
        return Err(AsicReadError::Unsupported("encrypted entry"));
    }
    let descriptor = header.flags & FLAG_DATA_DESCRIPTOR != 0;
    // With a data descriptor the local header may carry zeros where the
    // CRC and sizes go; the central record and the descriptor carry
    // them (APPNOTE 4.4.4 bit 3).
    let sizes_agree = if descriptor {
        (header.crc == 0 || header.crc == record.crc)
            && (header.compressed_len == 0 || header.compressed_len == record.compressed_len)
            && (header.uncompressed_len == 0 || header.uncompressed_len == record.uncompressed_len)
    } else {
        header.crc == record.crc
            && header.compressed_len == record.compressed_len
            && header.uncompressed_len == record.uncompressed_len
    };
    if header.flags != record.flags
        || header.method != record.method
        || !sizes_agree
        || name_bytes != record.name.as_slice()
    {
        return Err(AsicReadError::Malformed(
            "central directory and local header disagree",
        ));
    }
    require_plain_extra_field(extra)?;
    let stored = cursor
        .take(record.compressed_len)
        .ok_or(AsicReadError::Malformed("truncated entry data"))?;
    if descriptor {
        read_data_descriptor(&mut cursor, record)?;
    }
    let extent = LocalExtent {
        start: record.local_offset,
        end: cursor.position(),
    };
    let Some(name) = plain_entry_name(&record.name)? else {
        if record.uncompressed_len != 0 {
            return Err(AsicReadError::Malformed("directory entry with content"));
        }
        return Ok((None, extent));
    };
    let content = match header.method {
        METHOD_STORED => stored.to_vec(),
        METHOD_DEFLATED => {
            miniz_oxide::inflate::decompress_to_vec_with_limit(stored, record.uncompressed_len)
                .map_err(|_ignored| AsicReadError::Malformed("deflated data does not inflate"))?
        }
        _ => return Err(AsicReadError::Unsupported("compression method")),
    };
    if content.len() != record.uncompressed_len {
        return Err(AsicReadError::Malformed(
            "entry size does not match its header",
        ));
    }
    if crc32(&content) != record.crc {
        return Err(AsicReadError::Malformed(
            "entry data does not match its CRC-32",
        ));
    }
    Ok((Some(Entry { name, content }), extent))
}

/// Read the data descriptor after an entry's data (APPNOTE 4.3.9): an
/// optional signature, the CRC-32 and both sizes, which must equal the
/// central record's.
fn read_data_descriptor(
    cursor: &mut Cursor<'_>,
    record: &CentralRecord,
) -> Result<(), AsicReadError> {
    /// The descriptor is cut short or disagrees with the record.
    const DISAGREES: AsicReadError =
        AsicReadError::Malformed("data descriptor disagrees with the central directory");
    let mut probe = Cursor::at(cursor.bytes, cursor.position());
    if probe.u32() == Some(SIGNATURE_DATA_DESCRIPTOR) {
        cursor.u32().ok_or(DISAGREES)?;
    }
    let crc = cursor.u32().ok_or(DISAGREES)?;
    let compressed = cursor.u32().ok_or(DISAGREES)?;
    let uncompressed = cursor.u32().ok_or(DISAGREES)?;
    if crc != record.crc
        || usize::try_from(compressed).ok() != Some(record.compressed_len)
        || usize::try_from(uncompressed).ok() != Some(record.uncompressed_len)
    {
        return Err(DISAGREES);
    }
    Ok(())
}

/// The listed local entries must cover the bytes before the central
/// directory exactly, so nothing hides between or beside them.
fn require_exact_tiling(
    mut extents: Vec<LocalExtent>,
    central_offset: usize,
) -> Result<(), AsicReadError> {
    /// Bytes outside every listed entry.
    const GAP: AsicReadError =
        AsicReadError::Malformed("local entries do not tile the archive exactly");
    extents.sort_unstable_by_key(|extent| extent.start);
    let mut expected = 0_usize;
    for extent in &extents {
        if extent.start != expected {
            return Err(GAP);
        }
        expected = extent.end;
    }
    if expected != central_offset {
        return Err(GAP);
    }
    Ok(())
}

/// CRC-32 as ZIP defines it (APPNOTE 4.4.7: the IEEE 802.3 polynomial,
/// reflected, initial and final value all ones).
fn crc32(data: &[u8]) -> u32 {
    /// Reflected IEEE 802.3 polynomial.
    const POLYNOMIAL: u32 = 0xEDB8_8320;
    /// Bits per input byte.
    const BITS: usize = 8;
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..BITS {
            let carry = crc & 1;
            crc >>= 1;
            if carry != 0 {
                crc ^= POLYNOMIAL;
            }
        }
    }
    !crc
}

/// Byte cursor that fails closed instead of slicing out of range.
struct Cursor<'a> {
    /// The whole input.
    bytes: &'a [u8],
    /// The next unread offset.
    position: usize,
}

impl<'a> Cursor<'a> {
    /// A cursor at the start of `bytes`.
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// A cursor at `position`; reads past the end fail.
    const fn at(bytes: &'a [u8], position: usize) -> Self {
        Self { bytes, position }
    }

    /// The next unread offset.
    const fn position(&self) -> usize {
        self.position
    }

    /// The next `len` bytes.
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(len)?;
        let slice = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(slice)
    }

    /// A little-endian `u16`.
    fn u16(&mut self) -> Option<u16> {
        let pair: [u8; U16_LEN] = self.take(U16_LEN)?.try_into().ok()?;
        Some(u16::from_le_bytes(pair))
    }

    /// A little-endian `u32`.
    fn u32(&mut self) -> Option<u32> {
        let quad: [u8; U32_LEN] = self.take(U32_LEN)?.try_into().ok()?;
        Some(u32::from_le_bytes(quad))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AsicContainer, AsicReadError, FLAG_DATA_DESCRIPTOR, METHOD_DEFLATED, METHOD_STORED,
        MIMETYPE_ASICE, MIMETYPE_ENTRY, Mimetype, SIGNATURE_CENTRAL_HEADER,
        SIGNATURE_DATA_DESCRIPTOR, SIGNATURE_END_OF_DIRECTORY, SIGNATURE_LOCAL_HEADER, crc32,
        percent_decode,
    };
    use crate::document::DocumentFile;
    use crate::sign::asic::DataObject;
    use crate::sign::cades::DigestAlgorithm;

    /// `deflate` level for the hand-built archives: the default.
    const DEFLATE_LEVEL: u8 = 6;

    /// Version needed to extract: 2.0, stored or deflated.
    const VERSION_NEEDED: u16 = 20;

    /// One entry for the hand-built archives.
    struct RawEntry<'a> {
        name: &'a str,
        content: &'a [u8],
        method: u16,
        descriptor: bool,
    }

    /// A minimal ZIP writer for the cases our container writer does
    /// not produce: deflated entries and data descriptors.
    fn zip(entries: &[RawEntry<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut directory = Vec::new();
        for entry in entries {
            let offset = u32::try_from(out.len()).expect("fits");
            let stored = if entry.method == METHOD_DEFLATED {
                miniz_oxide::deflate::compress_to_vec(entry.content, DEFLATE_LEVEL)
            } else {
                entry.content.to_vec()
            };
            let crc = crc32(entry.content);
            let compressed = u32::try_from(stored.len()).expect("fits");
            let size = u32::try_from(entry.content.len()).expect("fits");
            let name_len = u16::try_from(entry.name.len()).expect("fits");
            let flags = if entry.descriptor {
                FLAG_DATA_DESCRIPTOR
            } else {
                0
            };
            let zero_u16 = 0_u16.to_le_bytes();
            let zero_u32 = 0_u32.to_le_bytes();

            out.extend_from_slice(&SIGNATURE_LOCAL_HEADER.to_le_bytes());
            out.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&entry.method.to_le_bytes());
            out.extend_from_slice(&zero_u16);
            out.extend_from_slice(&zero_u16);
            if entry.descriptor {
                out.extend_from_slice(&zero_u32);
                out.extend_from_slice(&zero_u32);
                out.extend_from_slice(&zero_u32);
            } else {
                out.extend_from_slice(&crc.to_le_bytes());
                out.extend_from_slice(&compressed.to_le_bytes());
                out.extend_from_slice(&size.to_le_bytes());
            }
            out.extend_from_slice(&name_len.to_le_bytes());
            out.extend_from_slice(&zero_u16);
            out.extend_from_slice(entry.name.as_bytes());
            out.extend_from_slice(&stored);
            if entry.descriptor {
                out.extend_from_slice(&SIGNATURE_DATA_DESCRIPTOR.to_le_bytes());
                out.extend_from_slice(&crc.to_le_bytes());
                out.extend_from_slice(&compressed.to_le_bytes());
                out.extend_from_slice(&size.to_le_bytes());
            }

            directory.extend_from_slice(&SIGNATURE_CENTRAL_HEADER.to_le_bytes());
            directory.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
            directory.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
            directory.extend_from_slice(&flags.to_le_bytes());
            directory.extend_from_slice(&entry.method.to_le_bytes());
            directory.extend_from_slice(&zero_u16);
            directory.extend_from_slice(&zero_u16);
            directory.extend_from_slice(&crc.to_le_bytes());
            directory.extend_from_slice(&compressed.to_le_bytes());
            directory.extend_from_slice(&size.to_le_bytes());
            directory.extend_from_slice(&name_len.to_le_bytes());
            // Extra, comment, disk, internal attributes.
            for _ in 0..4 {
                directory.extend_from_slice(&zero_u16);
            }
            directory.extend_from_slice(&zero_u32);
            directory.extend_from_slice(&offset.to_le_bytes());
            directory.extend_from_slice(entry.name.as_bytes());
        }
        let count = u16::try_from(entries.len()).expect("fits");
        let directory_at = u32::try_from(out.len()).expect("fits");
        let directory_len = u32::try_from(directory.len()).expect("fits");
        out.extend_from_slice(&directory);
        out.extend_from_slice(&SIGNATURE_END_OF_DIRECTORY.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&directory_len.to_le_bytes());
        out.extend_from_slice(&directory_at.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out
    }

    fn parse(bytes: Vec<u8>) -> Result<AsicContainer, AsicReadError> {
        AsicContainer::parse(&DocumentFile::from_file(bytes))
    }

    const TEXT: &[u8] = b"a declaration of a means of cryptology, repeated, repeated, repeated";

    #[test]
    fn stored_deflated_and_descriptor_entries_read_back() {
        let archive = zip(&[
            RawEntry {
                name: MIMETYPE_ENTRY,
                content: MIMETYPE_ASICE.as_bytes(),
                method: METHOD_STORED,
                descriptor: false,
            },
            RawEntry {
                name: "stored.txt",
                content: TEXT,
                method: METHOD_STORED,
                descriptor: false,
            },
            RawEntry {
                name: "deflated.txt",
                content: TEXT,
                method: METHOD_DEFLATED,
                descriptor: false,
            },
            RawEntry {
                name: "streamed.txt",
                content: TEXT,
                method: METHOD_DEFLATED,
                descriptor: true,
            },
            RawEntry {
                name: "META-INF/",
                content: b"",
                method: METHOD_STORED,
                descriptor: false,
            },
            RawEntry {
                name: "META-INF/signatures0.xml",
                content: b"<x/>",
                method: METHOD_DEFLATED,
                descriptor: false,
            },
        ]);
        let container = parse(archive).expect("reads");
        assert_eq!(container.mimetype(), Mimetype::AsicE);
        let names: Vec<_> = container
            .data_files()
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, ["stored.txt", "deflated.txt", "streamed.txt"]);
        assert!(
            container
                .data_files()
                .iter()
                .all(|entry| entry.content == TEXT)
        );
        assert_eq!(container.xades_signature_files().len(), 1);
        assert!(container.cades_signatures().is_empty());
    }

    #[test]
    fn a_crc_mismatch_is_refused() {
        let mut archive = zip(&[RawEntry {
            name: "a.txt",
            content: TEXT,
            method: METHOD_STORED,
            descriptor: false,
        }]);
        let at = archive
            .windows(TEXT.len())
            .position(|window| window == TEXT)
            .expect("stored content");
        archive[at] ^= 1;
        assert_eq!(
            parse(archive).err(),
            Some(AsicReadError::Malformed(
                "entry data does not match its CRC-32"
            ))
        );
    }

    #[test]
    fn a_non_zip_is_refused() {
        assert_eq!(
            parse(b"%PDF-1.7 not a container".to_vec()).err(),
            Some(AsicReadError::NotAZip)
        );
        assert_eq!(parse(Vec::new()).err(), Some(AsicReadError::NotAZip));
    }

    #[test]
    fn trailing_bytes_and_hidden_entries_are_refused() {
        let mut archive = zip(&[RawEntry {
            name: "a.txt",
            content: TEXT,
            method: METHOD_STORED,
            descriptor: false,
        }]);
        archive.extend_from_slice(b"trailing");
        assert!(matches!(
            parse(archive).err(),
            Some(AsicReadError::Malformed(_))
        ));
    }

    #[test]
    fn unsafe_names_are_refused() {
        for name in ["../escape.txt", "/absolute.txt", "a\\b.txt", "a//b.txt"] {
            let archive = zip(&[RawEntry {
                name,
                content: TEXT,
                method: METHOD_STORED,
                descriptor: false,
            }]);
            assert!(
                matches!(parse(archive).err(), Some(AsicReadError::Malformed(_))),
                "{name}"
            );
        }
    }

    /// The `CAdES` flavour our writer produces: the signature is paired
    /// with the manifest whose `SigReference` names it, and the archive
    /// manifest, which names a timestamp, is not mistaken for it.
    #[test]
    fn our_cades_container_pairs_signature_and_manifest() {
        let objects = vec![DataObject {
            name: "dossier.pdf".to_owned(),
            mime_type: "application/pdf".to_owned(),
            content: TEXT.to_vec(),
        }];
        let plan = crate::sign::asic::plan(objects, DigestAlgorithm::Sha256);
        let manifest = plan.manifest().to_vec();
        let archive_manifest = plan.archive_manifest(b"cms", DigestAlgorithm::Sha256);
        let archive = plan
            .finish_archived(b"cms", &archive_manifest, b"token")
            .expect("fits");
        let container = parse(archive).expect("reads");
        assert_eq!(container.mimetype(), Mimetype::AsicE);
        assert_eq!(container.data_files().len(), 1);
        let [cades] = container.cades_signatures() else {
            panic!("one CAdES signature");
        };
        assert_eq!(cades.signature.name, "META-INF/signature.p7s");
        assert_eq!(cades.signature.content, b"cms");
        let paired = cades.manifest.as_ref().expect("manifest paired");
        assert_eq!(paired.name, "META-INF/ASiCManifest.xml");
        assert_eq!(paired.content, manifest);
    }

    /// A `CAdES` container from our writer, with the manifest swapped
    /// for `manifest` and the data files for `objects`.
    fn cades_container(objects: Vec<DataObject>, manifest: Option<Vec<u8>>) -> AsicContainer {
        let plan = crate::sign::asic::plan(signed_objects(), DigestAlgorithm::Sha256);
        let manifest = manifest.unwrap_or_else(|| plan.manifest().to_vec());
        fn stored<'a>(name: &'a str, content: &'a [u8]) -> RawEntry<'a> {
            RawEntry {
                name,
                content,
                method: METHOD_STORED,
                descriptor: false,
            }
        }
        let mut entries = vec![stored(MIMETYPE_ENTRY, MIMETYPE_ASICE.as_bytes())];
        for object in &objects {
            entries.push(stored(&object.name, &object.content));
        }
        entries.push(stored("META-INF/ASiCManifest.xml", &manifest));
        entries.push(stored("META-INF/signature.p7s", b"cms"));
        parse(zip(&entries)).expect("reads")
    }

    fn signed_objects() -> Vec<DataObject> {
        vec![
            DataObject {
                name: "dossier.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: TEXT.to_vec(),
            },
            DataObject {
                name: "annex one.txt".to_owned(),
                mime_type: "text/plain".to_owned(),
                content: b"annex".to_vec(),
            },
        ]
    }

    fn manifest_intact(container: &AsicContainer) -> bool {
        let [cades] = container.cades_signatures() else {
            panic!("one CAdES signature");
        };
        container.manifest_intact(cades)
    }

    #[test]
    fn our_cades_manifest_is_intact() {
        let archive = crate::sign::asic::plan(signed_objects(), DigestAlgorithm::Sha256)
            .finish(b"cms")
            .expect("fits");
        assert!(manifest_intact(&parse(archive).expect("reads")));
        assert!(manifest_intact(&cades_container(signed_objects(), None)));
    }

    #[test]
    fn a_modified_data_file_breaks_the_manifest() {
        let mut objects = signed_objects();
        objects[0].content = b"a different declaration".to_vec();
        assert!(!manifest_intact(&cades_container(objects, None)));
    }

    #[test]
    fn an_unreferenced_data_file_breaks_the_manifest() {
        let mut objects = signed_objects();
        objects.push(DataObject {
            name: "smuggled.txt".to_owned(),
            mime_type: "text/plain".to_owned(),
            content: b"not listed".to_vec(),
        });
        assert!(!manifest_intact(&cades_container(objects, None)));
    }

    #[test]
    fn a_wrong_digest_or_method_breaks_the_manifest() {
        let manifest = String::from_utf8(
            crate::sign::asic::plan(signed_objects(), DigestAlgorithm::Sha256)
                .manifest()
                .to_vec(),
        )
        .expect("utf-8");
        let right = crate::base64::encode(&DigestAlgorithm::Sha256.digest(TEXT));
        let wrong = crate::base64::encode(&DigestAlgorithm::Sha256.digest(b"other"));
        let wrong_digest = manifest.replace(&right, &wrong);
        assert_ne!(wrong_digest, manifest);
        assert!(!manifest_intact(&cades_container(
            signed_objects(),
            Some(wrong_digest.into_bytes())
        )));

        let sha1 = manifest.replace(
            "http://www.w3.org/2001/04/xmlenc#sha256",
            "http://www.w3.org/2000/09/xmldsig#sha1",
        );
        assert_ne!(sha1, manifest);
        assert!(!manifest_intact(&cades_container(
            signed_objects(),
            Some(sha1.into_bytes())
        )));

        let other_signature = manifest.replace(
            "URI=\"META-INF/signature.p7s\"",
            "URI=\"META-INF/signature2.p7s\"",
        );
        assert_ne!(other_signature, manifest);
        let container = cades_container(signed_objects(), Some(other_signature.into_bytes()));
        let [cades] = container.cades_signatures() else {
            panic!("one CAdES signature");
        };
        assert!(
            cades.manifest.is_none(),
            "a manifest naming another signature is not paired"
        );
        assert!(!container.manifest_intact(cades));
    }

    #[test]
    fn percent_escapes_decode_to_utf8_names() {
        assert_eq!(
            percent_decode("a%20b%C3%A4.txt").as_deref(),
            Some("a b\u{e4}.txt")
        );
        assert_eq!(percent_decode("plain.txt").as_deref(), Some("plain.txt"));
        assert_eq!(percent_decode("bad%2"), None);
        assert_eq!(percent_decode("bad%zz"), None);
    }
}
