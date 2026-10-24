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

//! `refineid card emrtd --can <CAN>`: run PACE with the
//! card-printed CAN, drive the eMRTD personal-data read, and
//! print the parsed MRZ + face-image metadata as text.
//!
//! Flow: `PcscBackend` opens the card, lib-core's
//! [`refineid_lib_core::emrtd::read_personal_data`] runs PACE,
//! wraps the transport in `SmTransport`, SELECTs the eMRTD
//! applet, and READ BINARYs DG1 + DG2. The CAN never enters a
//! log line or a process argv list (see CLI wiring); we accept
//! it as `&str` and pass it straight into PACE.

use alloc::fmt;
use std::path::PathBuf;

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct CardEmrtdHelpers;

use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _, ReaderPickError};
use refineid_lib_core::emrtd::{DocumentImage, EmrtdError, EmrtdPersonalData, read_personal_data};
use refineid_lib_core::identity::CredentialIdentity;
use refineid_lib_core::pkcs15::FineidReaderPicker as _;
use refineid_lib_pcsc::{PcscBackend, PcscError};

/// Inputs.
#[derive(Debug, Clone)]
pub struct EmrtdReadOptions {
    /// Card Access Number (six digits, printed on the front of
    /// the FINEID card). Never logged.
    pub can: refineid_lib_core::can::Can,
    /// Optional output path for the face-image bytes. When set
    /// and DG2 carried a recognised JPEG / JPEG2000 envelope,
    /// the embedded image is written there.
    pub save_face: Option<PathBuf>,
    /// Optional output path for the cardholder's displayed-
    /// signature image (DG7 -- the handwritten signature
    /// scanned at issuance). When set and DG7 carried a
    /// recognised JPEG / JPEG2000 envelope, the embedded image
    /// is written there.
    pub save_signature: Option<PathBuf>,
    /// Optional substring match against reader names. `None`
    /// picks the first reader with a card present (the existing
    /// default); `Some("OMNIKEY")` would target a specific
    /// reader when multiple cards are connected.
    pub reader_filter: Option<String>,
}

/// One reader's worth of eMRTD output. Display-friendly via the
/// [`fmt::Display`] impl.
#[derive(Debug, Clone)]
pub struct EmrtdReadReport {
    /// PC/SC reader name the eMRTD APDUs landed against. Tier 0
    /// `String` from `ReaderId::as_str().to_owned()`.
    pub reader: String,
    /// Identity captured by the FINEID probe before PACE ran.
    /// Same value the CLI prints in the pre-flight identity line.
    /// Held in the report so the caller can correlate the post-
    /// PACE eMRTD MRZ data against the pre-PACE PKCS#15 identity.
    /// `None` on a contactless read: the PKCS#15 application (and
    /// with it every certificate) is sealed until PACE has run,
    /// so no pre-PACE identity exists to capture.
    pub preflight_identity: Option<CredentialIdentity>,
    /// Personal data Groups read from the chip: DG1 MRZ, DG2 face,
    /// DG7 displayed signature, DG11 additional personal data,
    /// DG12 additional document data, EF.SOD bytes, DG14 / DG15
    /// chip-auth / active-auth metadata (per ICAO Doc 9303-10).
    pub data: EmrtdPersonalData,
    /// Path where the face image was written, when `save_face`
    /// was set and DG2 carried a recognised image.
    pub face_saved_to: Option<PathBuf>,
    /// Path where the signature image was written, when
    /// `save_signature` was set and DG7 carried a recognised
    /// image.
    pub signature_saved_to: Option<PathBuf>,
}

/// Error returned from `read_first` / `card emrtd` flow.
#[derive(Debug)]
pub enum EmrtdReadError {
    /// Reader-selection failure (none / multiple / bad filter).
    /// See [`ReaderPickError`] for the variants and the multi-
    /// card-safety rule.
    ReaderPick(ReaderPickError),
    /// PC/SC connect / transmit error.
    Pcsc(PcscError),
    /// Lower-level eMRTD failure (PACE / SM glitch, SOD parse,
    /// READ BINARY error, etc.). Tier 0 `String`; presentational
    /// copy of the upstream error.
    Emrtd(String),
    /// PACE failed with the specific signature of a wrong CAN
    /// (card returned SW=0x6300 or the mutual-auth tag check
    /// failed). Lets the CLI surface a "CAN didn't match this
    /// card" message instead of a generic PACE-failed report,
    /// and to recommend checking the CAN printed on the card
    /// front.
    BadCan,
    /// `--save-*` file write failed. `what` is the human label
    /// for the artefact ("face", "signature") so the error
    /// message names the right thing.
    SaveFile {
        /// Human label for the artefact ("face", "signature",
        /// "DG7 (raw)"). Tier 0 `&'static str` from a fixed
        /// compile-time set.
        what: &'static str,
        /// Filesystem path the write was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
}

impl fmt::Display for EmrtdReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReaderPick(e) => write!(f, "{e}"),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::Emrtd(s) => write!(f, "eMRTD: {s}"),
            Self::BadCan => write!(
                f,
                "CAN did not match the card. Verify that the entered CAN matches the \
                 CAN printed on the card front."
            ),
            Self::SaveFile { what, path, source } => {
                write!(f, "save {what} to {}: {source}", path.display())
            }
        }
    }
}

impl From<ReaderPickError> for EmrtdReadError {
    fn from(e: ReaderPickError) -> Self {
        Self::ReaderPick(e)
    }
}

impl core::error::Error for EmrtdReadError {}

impl From<PcscError> for EmrtdReadError {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

/// Read DG1 + DG2 from the first reader that has a card present.
///
/// # Errors
/// PC/SC enumeration / connect failure, PACE failure (e.g. wrong
/// CAN), SM failure, applet SELECT or READ BINARY failure, MRZ
/// parse failure, or face-image save failure when
/// `options.save_face` is set.
pub fn read_first(
    backend: PcscBackend,
    options: &EmrtdReadOptions,
) -> Result<EmrtdReadReport, EmrtdReadError> {
    // FINEID-aware reader pick + pre-flight identity read. The
    // pick fn probes every card-present reader via PKCS#15
    // SELECT + EF.TokenInfo + auth-cert read; non-FINEID tokens
    // (YubiKey in CCID mode, etc.) are filtered out before the
    // ambiguity check. The returned identity is built from the
    // card's PKCS#15-public data (no CAN required) so it's
    // available for the pre-flight print *before* PACE consumes
    // the CAN against the wrong card.
    let filter = options
        .reader_filter
        .clone()
        .map(refineid_lib_core::backend::ReaderFilter::new);
    let (reader_id, preflight_identity) = match backend.pick_fineid_reader(filter.as_ref()) {
        Ok(pick) => (pick.reader_id, Some(pick.identity)),
        // Contactless fallback: over the contactless interface a
        // FINEID card seals PKCS#15 behind PACE (SELECT answers
        // SW 6982), so the contact probe sees "cards present,
        // none FINEID". If a card-present reader serves
        // EF.CardAccess -- the one file contactless exposes
        // pre-PACE -- treat it as the PACE-first candidate and
        // proceed without a pre-flight identity. The CAN is
        // printed on the card and has no retry counter, so a
        // PACE run against an unintended card wastes nothing.
        Err(original @ ReaderPickError::NoFineidCard { .. }) => {
            match backend.pick_contactless_reader(filter.as_ref()) {
                Ok(reader_id) => (reader_id, None),
                // No EF.CardAccess candidates either: the contact
                // probe's error names every reader and is the
                // truthful summary of both probes.
                Err(ReaderPickError::NoFineidCard { .. }) => return Err(original.into()),
                // Ambiguity / filter outcomes from the contactless
                // candidate set carry the actionable message.
                Err(e) => return Err(e.into()),
            }
        }
        Err(e) => return Err(e.into()),
    };
    let person = preflight_identity
        .as_ref()
        .map_or_else(String::new, CredentialIdentity::person_string);
    crate::events::CardTarget {
        device: reader_id.as_str(),
        card: preflight_identity
            .as_ref()
            .and_then(CredentialIdentity::best_serial)
            .unwrap_or(""),
        person: &person,
    }
    .emit();
    let mut transport = backend.open_session(&reader_id, ReaderAccessCap::Read)?;
    // Start PACE from a clean card. An earlier failed PACE leaves
    // the CAN suspended, and the card then reports a *correct*
    // CAN exactly like a wrong one until it is power-cycled (BSI
    // TR-03110-3 §2.4) -- so without this a single CAN typo makes
    // every later attempt fail until the card is physically
    // re-presented. Measured on a production card over an
    // ACR1581 PICC slot, 2026-07-24.
    transport.reset()?;
    let data = read_personal_data(transport, options.can).map_err(map_personal_data_error)?;

    let face_saved_to = match (&options.save_face, data.face.as_ref()) {
        (Some(path), Some(face)) => {
            CardEmrtdHelpers::write_artefact("face", path, face.bytes())?;
            Some(path.clone())
        }
        _ => None,
    };
    // --save-signature prefers the parsed image (JPEG / JPEG2000)
    // when detected, but falls back to the raw DG7 bytes when the
    // scan didn't find a known magic. The user asked for their
    // signature; giving them bytes-they-can-investigate beats
    // giving them nothing because we didn't recognise the format.
    let signature_saved_to = match &options.save_signature {
        Some(path) => {
            if let Some(img) = data.signature_image.as_ref() {
                CardEmrtdHelpers::write_artefact("signature", path, img.bytes())?;
                Some(path.clone())
            } else if let Some(raw) = data.dg7_der.as_deref() {
                CardEmrtdHelpers::write_artefact("DG7 (raw)", path, raw)?;
                Some(path.clone())
            } else {
                None
            }
        }
        None => None,
    };
    Ok(EmrtdReadReport {
        reader: reader_id.as_str().to_owned(),
        preflight_identity,
        data,
        face_saved_to,
        signature_saved_to,
    })
}

impl CardEmrtdHelpers {
    /// Persist an eMRTD artefact (face image, signature image)
    /// to disk and wrap any I/O failure in a
    /// labelled [`EmrtdReadError::SaveFile`].
    ///
    /// `what` is a stable `&'static str` so the error variant
    /// can name the artefact in the message ("face",
    /// "signature") without allocating per call.
    fn write_artefact(
        what: &'static str,
        path: &PathBuf,
        bytes: &[u8],
    ) -> Result<(), EmrtdReadError> {
        std::fs::write(path, bytes).map_err(|source| EmrtdReadError::SaveFile {
            what,
            path: path.clone(),
            source,
        })
    }
}

/// Lift an `EmrtdError<TE>` from `read_personal_data` into our
/// `EmrtdReadError`. The structured `BadCan` variant gets its
/// own carrier so the CLI can render a CAN-specific message;
/// everything else stringifies into the generic `Emrtd` variant.
fn map_personal_data_error<TE>(e: EmrtdError<TE>) -> EmrtdReadError
where
    TE: core::fmt::Debug + core::fmt::Display,
{
    match e {
        EmrtdError::BadCan => EmrtdReadError::BadCan,
        other @ (EmrtdError::Transport(_)
        | EmrtdError::Sw { .. }
        | EmrtdError::Ber(_)
        | EmrtdError::Pace(_)
        | EmrtdError::SecureMessaging(_)
        | EmrtdError::CardReset
        | EmrtdError::ParseFailure(_)
        | EmrtdError::ParseFailureDetail { .. }) => EmrtdReadError::Emrtd(format!("{other}")),
    }
}

impl fmt::Display for EmrtdReadReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = &self.data.mrz;
        writeln!(f, "reader:           {}", self.reader)?;
        writeln!(f, "document type:    {}", m.document_type)?;
        writeln!(f, "issuing country:  {}", m.issuing_country)?;
        writeln!(f, "document number:  {}", m.document_number)?;
        writeln!(f, "nationality:      {}", m.nationality)?;
        // MRZ identifiers carry the on-card form (A-Z + `<`);
        // `.spaced()` converts inner fillers to spaces for the
        // operator-readable line. `.to_native()` runs the
        // case-normalization heuristic for the native line
        // beneath; DG11 would be the proper source but DVV
        // doesn't currently provision it on FINEID cards.
        writeln!(f, "surname:          {}", m.primary_identifier.spaced())?;
        writeln!(f, "given names:      {}", m.secondary_identifier.spaced())?;
        if let (Ok(s), Ok(g)) = (
            m.primary_identifier.to_native(),
            m.secondary_identifier.to_native(),
        ) {
            writeln!(f, "native (heuristic): {g} {s}")?;
        }
        // MrzDate's Display renders the ISO 8601 form after
        // century resolution; raw 6-digit form falls through
        // only when the month / day fail validation.
        writeln!(f, "date of birth:    {}", m.date_of_birth)?;
        // Document expiry, not the holder's -- label it as the card's.
        writeln!(f, "card expiry:      {}", m.date_of_expiry)?;
        // MRZ byte ('M' / 'F' / '<') for spec traceability;
        // human-readable token in parens (MrzSex's Display).
        // `as_mrz_byte()` is documented to return an ASCII byte;
        // widening to `char` is total.
        #[expect(
            clippy::as_conversions,
            reason = "MrzSex::as_mrz_byte() returns an ASCII byte by contract; u8->char widen is total"
        )]
        let sex_char = m.sex.as_mrz_byte() as char;
        writeln!(f, "sex:              {sex_char} ({})", m.sex)?;
        match &self.data.face {
            Some(DocumentImage::Jpeg(bytes)) => {
                writeln!(f, "face image:       JPEG, {} bytes", bytes.len())?;
            }
            Some(DocumentImage::Jpeg2000(bytes)) => {
                writeln!(f, "face image:       JPEG2000, {} bytes", bytes.len())?;
            }
            None => {
                writeln!(f, "face image:       <none>")?;
            }
        }
        if let Some(path) = &self.face_saved_to {
            writeln!(f, "face saved to:    {}", path.display())?;
        }
        write_dg11(f, self.data.additional_personal.as_ref())?;
        write_dg12(f, self.data.additional_document.as_ref())?;
        write_name_consistency(f, self.preflight_identity.as_ref(), &self.data)?;
        match (&self.data.signature_image, &self.data.dg7_der) {
            (Some(DocumentImage::Jpeg(bytes)), _) => {
                writeln!(f, "signature (DG7):  JPEG, {} bytes", bytes.len())?;
            }
            (Some(DocumentImage::Jpeg2000(bytes)), _) => {
                writeln!(f, "signature (DG7):  JPEG2000, {} bytes", bytes.len())?;
            }
            (None, Some(raw)) => {
                writeln!(
                    f,
                    "signature (DG7):  {} raw bytes (no JPEG/JP2 magic; --save-signature \
                     writes the raw envelope for inspection)",
                    raw.len()
                )?;
            }
            (None, None) => {}
        }
        if let Some(path) = &self.signature_saved_to {
            writeln!(f, "signature saved to: {}", path.display())?;
        }
        write_data_groups(f, &self.data.data_groups)
    }
}

/// Number of data groups ICAO 9303-10 defines (DG1 to DG16).
const DATA_GROUP_COUNT: usize = 16;

/// List the data groups EF.SOD names, one per line, with the
/// ICAO 9303-10 content label. The list comes from the
/// unverified EF.SOD: it is an inventory, not an attestation.
fn write_data_groups(f: &mut fmt::Formatter<'_>, data_groups: &[u32]) -> fmt::Result {
    writeln!(f)?;
    writeln!(
        f,
        "data groups in EF.SOD ({} of {DATA_GROUP_COUNT} present):",
        data_groups.len()
    )?;
    for n in data_groups {
        let (label, note) = dg_content(*n);
        if note.is_empty() {
            writeln!(f, "  DG{n:<2}  {label}")?;
        } else {
            writeln!(f, "  DG{n:<2}  {label} ({note})")?;
        }
    }
    Ok(())
}

/// ICAO 9303-10 Table 3 friendly labels for the standard data
/// groups, plus an access-constraint note for the DGs that
/// can't be read with a citizen-tier inspection key (no
/// Terminal Authentication chain).
///
/// Returns `("<content label>", "<note or empty>")`. Unknown
/// DG numbers (none defined past 16) get a generic label.
const fn dg_content(n: u32) -> (&'static str, &'static str) {
    match n {
        1 => ("MRZ", ""),
        2 => ("face biometric image", ""),
        3 => (
            "fingerprints",
            "EAC-protected -- needs Terminal Authentication",
        ),
        4 => ("iris", "EAC-protected -- needs Terminal Authentication"),
        5 => ("displayed portrait", ""),
        6 => ("reserved", ""),
        7 => ("signature / mark image", ""),
        8 => ("data features", ""),
        9 => ("structure features", ""),
        10 => ("substance features", ""),
        11 => ("additional personal details", ""),
        12 => ("additional document details", ""),
        13 => ("issuer-defined optional", ""),
        14 => ("security options (CA / PACE info)", ""),
        15 => ("Active Authentication public key", ""),
        16 => ("person to notify / emergency contact", ""),
        _ => ("unknown / vendor-defined", ""),
    }
}

/// Width to left-pad DG11 / DG12 field labels in the dump.
/// Sized to the longest expected label
/// (`"personalisation device (0x5F56)"` = 31 chars), plus a
/// small headroom so future additions slot in without
/// re-aligning the whole block.
const DG_DUMP_LABEL_WIDTH: usize = 33;

/// Marker emitted for fields that the card didn't provision.
const DG_FIELD_ABSENT: &str = "<absent>";

/// Marker emitted for list-shaped fields that the card carries
/// but with zero entries.
const DG_LIST_EMPTY: &str = "<none>";

/// Marker emitted for the whole DG when the parser couldn't
/// surface it (either the data group isn't on the card, or the
/// read failed before we got to it).
const DG_NOT_READ: &str = "<not read>";

impl CardEmrtdHelpers {
    /// Write one DG11/DG12 string-shaped field with a
    /// consistent column-aligned label.
    ///
    /// `None` becomes [`DG_FIELD_ABSENT`] (`"<absent>"`) so the
    /// report reader can distinguish "card didn't carry this
    /// field" from "field was empty"; the alignment width is
    /// [`DG_DUMP_LABEL_WIDTH`].
    fn write_dg_field(f: &mut fmt::Formatter<'_>, label: &str, value: Option<&str>) -> fmt::Result {
        match value {
            Some(v) => writeln!(f, "  {label:<DG_DUMP_LABEL_WIDTH$}: {v}"),
            None => writeln!(f, "  {label:<DG_DUMP_LABEL_WIDTH$}: {DG_FIELD_ABSENT}"),
        }
    }
}

/// Like `write_dg_field` but takes any [`fmt::Display`]
/// value (typed dates, enums, numbers) instead of a string
/// slice -- so typed DG fields don't have to allocate a
/// temporary `String` at every call site.
/// Like [`CardEmrtdHelpers::write_dg_field`] but takes any
/// [`fmt::Display`] value rather than a string slice.
///
/// Lets typed fields (dates, enums, numbers) print to the
/// DG report without allocating an intermediate `String` per
/// call site. Same absence-marker contract as
/// [`CardEmrtdHelpers::write_dg_field`].
fn write_dg_display<T: fmt::Display>(
    f: &mut fmt::Formatter<'_>,
    label: &str,
    value: Option<&T>,
) -> fmt::Result {
    match value {
        Some(v) => writeln!(f, "  {label:<DG_DUMP_LABEL_WIDTH$}: {v}"),
        None => writeln!(f, "  {label:<DG_DUMP_LABEL_WIDTH$}: {DG_FIELD_ABSENT}"),
    }
}

/// Write a DG11/DG12 list-shaped field (e.g. "other names",
/// "other persons of contact") with a count header and one
/// indented entry per element.
///
/// Empty list emits [`DG_LIST_EMPTY`] (`"<none>"`) so the
/// caller can distinguish "field present but no entries" from
/// "field absent entirely". The plural-y/-ies fix-up is the
/// standard English shape; the report is English-only by
/// design.
fn write_dg_list<T: fmt::Display>(
    f: &mut fmt::Formatter<'_>,
    label: &str,
    values: &[T],
) -> fmt::Result {
    if values.is_empty() {
        return writeln!(f, "  {label:<DG_DUMP_LABEL_WIDTH$}: {DG_LIST_EMPTY}");
    }
    writeln!(
        f,
        "  {label:<DG_DUMP_LABEL_WIDTH$}: {} entr{}",
        values.len(),
        if values.len() == 1 { "y" } else { "ies" }
    )?;
    for v in values {
        writeln!(f, "    - {v}")?;
    }
    Ok(())
}

/// Write an image field (DG2 face, DG7 signature, DG12
/// front/rear images) as `<format>, <bytes>` so the report
/// reader knows the encoding without seeing the bytes.
///
/// The image payload itself is written to disk separately
/// (see `CardEmrtdReport::face_saved_to` /
/// `signature_saved_to`); only the metadata appears here.
fn write_dg_image(
    f: &mut fmt::Formatter<'_>,
    label: &str,
    img: Option<&DocumentImage>,
) -> fmt::Result {
    match img {
        Some(DocumentImage::Jpeg(b)) => writeln!(
            f,
            "  {label:<DG_DUMP_LABEL_WIDTH$}: JPEG, {} bytes",
            b.len()
        ),
        Some(DocumentImage::Jpeg2000(b)) => writeln!(
            f,
            "  {label:<DG_DUMP_LABEL_WIDTH$}: JPEG2000, {} bytes",
            b.len()
        ),
        None => writeln!(f, "  {label:<DG_DUMP_LABEL_WIDTH$}: {DG_FIELD_ABSENT}"),
    }
}

/// Dump every DG11 field defined by ICAO 9303-10 Table 71,
/// present-or-absent. The output marks unprovisioned fields
/// explicitly so an operator can see what *this* card carries
/// versus what the spec permits.
fn write_dg11(
    f: &mut fmt::Formatter<'_>,
    dg11: Option<&refineid_lib_core::emrtd::AdditionalPersonalData>,
) -> fmt::Result {
    writeln!(f)?;
    writeln!(f, "DG11 -- additional personal data:")?;
    let Some(p) = dg11 else {
        writeln!(f, "  {DG_NOT_READ}")?;
        return Ok(());
    };
    CardEmrtdHelpers::write_dg_field(
        f,
        "full name (0x5F0E)",
        p.full_name.as_ref().map(AsRef::as_ref),
    )?;
    CardEmrtdHelpers::write_dg_field(
        f,
        "personal number (0x5F10)",
        p.personal_number.as_ref().map(AsRef::as_ref),
    )?;
    write_dg_display(f, "full DoB (0x5F2B)", p.full_date_of_birth.as_ref())?;
    CardEmrtdHelpers::write_dg_field(
        f,
        "place of birth (0x5F11)",
        p.place_of_birth.as_ref().map(AsRef::as_ref),
    )?;
    CardEmrtdHelpers::write_dg_field(
        f,
        "permanent address (0x5F42)",
        p.permanent_address.as_ref().map(AsRef::as_ref),
    )?;
    CardEmrtdHelpers::write_dg_field(
        f,
        "telephone (0x5F12)",
        p.telephone.as_ref().map(AsRef::as_ref),
    )?;
    CardEmrtdHelpers::write_dg_field(
        f,
        "profession (0x5F13)",
        p.profession.as_ref().map(AsRef::as_ref),
    )?;
    CardEmrtdHelpers::write_dg_field(f, "title (0x5F14)", p.title.as_ref().map(AsRef::as_ref))?;
    CardEmrtdHelpers::write_dg_field(
        f,
        "personal summary (0x5F15)",
        p.personal_summary.as_ref().map(AsRef::as_ref),
    )?;
    CardEmrtdHelpers::write_dg_field(
        f,
        "custody info (0x5F18)",
        p.custody_information.as_ref().map(AsRef::as_ref),
    )?;
    write_dg_list(f, "other names (0x5F0F)", &p.other_names)?;
    write_dg_list(f, "other TD numbers (0x5F17)", &p.other_td_numbers)?;
    write_dg_image(
        f,
        "proof of citizenship (0x5F16)",
        p.proof_of_citizenship.as_ref(),
    )?;
    Ok(())
}

/// Dump every DG12 field defined by ICAO 9303-10 Table 73,
/// present-or-absent.
fn write_dg12(
    f: &mut fmt::Formatter<'_>,
    dg12: Option<&refineid_lib_core::emrtd::AdditionalDocumentData>,
) -> fmt::Result {
    writeln!(f)?;
    writeln!(f, "DG12 -- additional document data:")?;
    let Some(d) = dg12 else {
        writeln!(f, "  {DG_NOT_READ}")?;
        return Ok(());
    };
    CardEmrtdHelpers::write_dg_field(
        f,
        "issuing authority (0x5F19)",
        d.issuing_authority.as_ref().map(AsRef::as_ref),
    )?;
    write_dg_display(f, "date of issue (0x5F26)", d.date_of_issue.as_ref())?;
    CardEmrtdHelpers::write_dg_field(
        f,
        "endorsements (0x5F1B)",
        d.endorsements.as_ref().map(AsRef::as_ref),
    )?;
    CardEmrtdHelpers::write_dg_field(
        f,
        "tax/exit (0x5F1C)",
        d.tax_exit.as_ref().map(AsRef::as_ref),
    )?;
    write_dg_list(f, "other persons (0x5F1A)", &d.other_persons)?;
    write_dg_display(
        f,
        "personalisation time (0x5F55)",
        d.personalisation_time.as_ref(),
    )?;
    CardEmrtdHelpers::write_dg_field(
        f,
        "personalisation device (0x5F56)",
        d.personalisation_device_serial.as_ref().map(AsRef::as_ref),
    )?;
    write_dg_image(f, "image front (0x5F1D)", d.image_front.as_ref())?;
    write_dg_image(f, "image rear (0x5F1E)", d.image_rear.as_ref())?;
    Ok(())
}

/// Render the cross-correlation report between the three name
/// forms a FINEID card may carry: cert subject DN (preflight
/// identity), DG11 0x5F0E, DG1 MRZ.
///
/// Lines emit one of:
///   - `ok` -- both sources present and they agree
///   - `mismatch` -- both sources present and they disagree
///     (operator should investigate)
///   - `n/a (<reason>)` -- at least one source absent
fn write_name_consistency(
    f: &mut fmt::Formatter<'_>,
    preflight: Option<&CredentialIdentity>,
    data: &EmrtdPersonalData,
) -> fmt::Result {
    // Contactless read: no pre-PACE cert identity exists, so the
    // cert-side inputs run empty and their lines render "n/a";
    // the MRZ <-> DG11 checks still run on their own. The note
    // names the reason so the operator doesn't chase a phantom
    // cert-parse failure.
    let contactless = preflight.is_none();
    let empty_identity = CredentialIdentity::new();
    let preflight = preflight.unwrap_or(&empty_identity);
    let dg11_full = data
        .additional_personal
        .as_ref()
        .and_then(|p| p.full_name.as_ref());
    let dg11_dob = data
        .additional_personal
        .as_ref()
        .and_then(|p| p.full_date_of_birth.as_ref());
    let mrz_p = Some(&data.mrz.primary_identifier);
    let mrz_s = Some(&data.mrz.secondary_identifier);
    let mrz_dob = Some(&data.mrz.date_of_birth);
    let report = refineid_lib_core::identity::verify_emrtd_consistency(
        refineid_lib_core::identity::EmrtdConsistencyInputs {
            cert_surname: preflight.surname.as_ref(),
            cert_first: preflight.first_name.as_ref(),
            cert_second: preflight.second_name.as_ref(),
            cert_additional: &preflight.additional_names,
            dg11_full_name: dg11_full,
            dg11_dob,
            mrz_primary: mrz_p,
            mrz_secondary: mrz_s,
            mrz_dob,
        },
    );

    writeln!(f)?;
    writeln!(f, "eMRTD consistency:")?;
    if contactless {
        writeln!(
            f,
            "  (contactless read: certificates are sealed behind PACE, \
             so the cert-side checks have no source)"
        )?;
    }
    write_consistency_line(
        f,
        "cert <-> DG11 surname",
        report.cert_matches_dg11_surname,
        dg11_full.is_some(),
    )?;
    write_consistency_line(
        f,
        "cert <-> DG11 given names",
        report.cert_matches_dg11_given,
        dg11_full.is_some(),
    )?;
    write_consistency_line(
        f,
        "cert -> MRZ primary",
        report.cert_transliterates_to_mrz_surname,
        true, // MRZ always present in EmrtdPersonalData
    )?;
    write_consistency_line(
        f,
        "cert -> MRZ secondary",
        report.cert_transliterates_to_mrz_given,
        true,
    )?;
    write_consistency_line(
        f,
        "MRZ DoB <-> DG11 DoB",
        report.mrz_dob_matches_dg11_dob,
        dg11_dob.is_some(),
    )?;
    Ok(())
}

/// Write one cert->DG11->MRZ consistency line in the eMRTD
/// section.
///
/// Three states: `ok` (both sides parsed and match);
/// `MISMATCH` (both sides parsed but disagree); `n/a` (one
/// side absent or unparsed). `source_present` distinguishes
/// the two `n/a` reasons so the operator can fix the right
/// gap (missing DG11 vs unparseable cert subject).
fn write_consistency_line(
    f: &mut fmt::Formatter<'_>,
    label: &str,
    outcome: Option<bool>,
    source_present: bool,
) -> fmt::Result {
    let verdict = match outcome {
        Some(true) => "ok".to_owned(),
        Some(false) => "MISMATCH".to_owned(),
        None if !source_present => "n/a (source absent)".to_owned(),
        None => "n/a (cert side missing)".to_owned(),
    };
    writeln!(f, "  {label:<26}: {verdict}")
}

#[cfg(test)]
mod tests {
    use core::fmt;

    use refineid_lib_core::emrtd::{AdditionalDocumentData, AdditionalPersonalData};
    use refineid_lib_core::identity::{
        IssueDate, IssuingAuthority, MrzDate, OtherPerson, OtherTdNumber, PlaceOfBirth, Profession,
        Title,
    };

    use super::{write_dg11, write_dg12};
    use crate::test_util::{TestResult, check, check_true};

    struct DumpDg11<'a>(Option<&'a AdditionalPersonalData>);

    impl fmt::Display for DumpDg11<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_dg11(f, self.0)
        }
    }

    struct DumpDg12<'a>(Option<&'a AdditionalDocumentData>);

    impl fmt::Display for DumpDg12<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write_dg12(f, self.0)
        }
    }

    #[test]
    fn mrz_date_resolves_century_via_display() -> TestResult {
        // MrzDate's Display renders the canonical ISO 8601 form
        // after the 50/50 century resolution at construction.
        check(
            format!("{}", MrzDate::from_mrz_yymmdd(*b"780321")?).as_str(),
            "1978-03-21",
            "780321",
        )?;
        check(
            format!("{}", MrzDate::from_mrz_yymmdd(*b"260520")?).as_str(),
            "2026-05-20",
            "260520",
        )?;
        check(
            format!("{}", MrzDate::from_mrz_yymmdd(*b"490101")?).as_str(),
            "2049-01-01",
            "490101",
        )?;
        check(
            format!("{}", MrzDate::from_mrz_yymmdd(*b"500101")?).as_str(),
            "1950-01-01",
            "500101",
        )
    }

    #[test]
    fn mrz_date_rejects_non_digits_at_parse() -> TestResult {
        // Garbage doesn't even construct -- caught earlier in
        // the pipeline.
        check_true(MrzDate::from_mrz_yymmdd(*b"<<<<<<").is_err(), "<<<<<<")?;
        // Six-byte non-digit input.
        check_true(MrzDate::from_mrz_yymmdd(*b"abcdef").is_err(), "abcdef")
    }

    #[test]
    fn dg11_dump_marks_absent_when_dg_not_read() -> TestResult {
        let out = format!("{}", DumpDg11(None));
        check_true(out.contains("DG11 -- additional personal data:"), "header")?;
        check_true(out.contains("<not read>"), "<not read>")
    }

    #[test]
    fn dg11_dump_lists_every_field_with_absent_marker() -> TestResult {
        // Empty default carries no values. Every field should
        // still appear in the output, labelled <absent> / <none>.
        let dg11 = AdditionalPersonalData::default();
        let out = format!("{}", DumpDg11(Some(&dg11)));
        for label in [
            "full name (0x5F0E)",
            "personal number (0x5F10)",
            "full DoB (0x5F2B)",
            "place of birth (0x5F11)",
            "permanent address (0x5F42)",
            "telephone (0x5F12)",
            "profession (0x5F13)",
            "title (0x5F14)",
            "personal summary (0x5F15)",
            "custody info (0x5F18)",
            "other names (0x5F0F)",
            "other TD numbers (0x5F17)",
            "proof of citizenship (0x5F16)",
        ] {
            check_true(
                out.contains(label),
                &format!("DG11 dump missing label {label:?}"),
            )?;
        }
        check_true(out.contains("<absent>"), "<absent>")?;
        check_true(out.contains("<none>"), "<none>")
    }

    #[test]
    fn dg11_dump_renders_present_values_with_utf8_diacritics() -> TestResult {
        let dg11 = AdditionalPersonalData {
            place_of_birth: Some(
                PlaceOfBirth::try_from("HELSINKI<UUSIMAA<FIN".to_owned())
                    .map_err(|e| format!("PlaceOfBirth: {e}"))?,
            ),
            profession: Some(
                Profession::try_from("L\u{00e4}\u{00e4}k\u{00e4}ri".to_owned())
                    .map_err(|e| format!("Profession: {e}"))?,
            ),
            title: Some(Title::try_from("Prof.".to_owned()).map_err(|e| format!("Title: {e}"))?),
            other_td_numbers: vec![
                OtherTdNumber::try_from("P1234567".to_owned())
                    .map_err(|e| format!("OtherTdNumber: {e}"))?,
            ],
            ..AdditionalPersonalData::default()
        };
        let out = format!("{}", DumpDg11(Some(&dg11)));
        check_true(out.contains("HELSINKI<UUSIMAA<FIN"), "place_of_birth")?;
        check_true(out.contains("L\u{00e4}\u{00e4}k\u{00e4}ri"), "profession")?;
        check_true(out.contains("Prof."), "title")?;
        // List with one entry renders count + bulletted entry.
        check_true(out.contains("1 entry"), "1 entry")?;
        check_true(out.contains("- P1234567"), "- P1234567")
    }

    struct ConsistencyLineCase {
        label: &'static str,
        outcome: Option<bool>,
        source_present: bool,
    }

    impl fmt::Display for ConsistencyLineCase {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            super::write_consistency_line(f, self.label, self.outcome, self.source_present)
        }
    }

    #[test]
    fn consistency_line_renders_outcome_states() -> TestResult {
        use core::fmt::Write as _;

        let mut buf = String::new();
        write!(
            buf,
            "{}",
            ConsistencyLineCase {
                label: "ok case",
                outcome: Some(true),
                source_present: true,
            }
        )?;
        write!(
            buf,
            "{}",
            ConsistencyLineCase {
                label: "mismatch case",
                outcome: Some(false),
                source_present: true,
            }
        )?;
        write!(
            buf,
            "{}",
            ConsistencyLineCase {
                label: "absent case",
                outcome: None,
                source_present: false,
            }
        )?;
        write!(
            buf,
            "{}",
            ConsistencyLineCase {
                label: "cert-missing case",
                outcome: None,
                source_present: true,
            }
        )?;

        check_true(
            buf.contains("ok case                   : ok"),
            "ok case line",
        )?;
        check_true(
            buf.contains("mismatch case             : MISMATCH"),
            "mismatch case line",
        )?;
        check_true(
            buf.contains("absent case               : n/a (source absent)"),
            "absent case line",
        )?;
        check_true(
            buf.contains("cert-missing case         : n/a (cert side missing)"),
            "cert-missing case line",
        )
    }

    #[test]
    fn dg12_dump_renders_full_set() -> TestResult {
        let dg12 = AdditionalDocumentData {
            issuing_authority: Some(
                IssuingAuthority::try_from("DVV".to_owned())
                    .map_err(|e| format!("IssuingAuthority: {e}"))?,
            ),
            date_of_issue: Some(
                IssueDate::from_yyyymmdd(*b"20210101").map_err(|e| format!("IssueDate: {e}"))?,
            ),
            other_persons: vec![
                OtherPerson::try_from("KORHONEN<MAIJA".to_owned())
                    .map_err(|e| format!("OtherPerson: {e}"))?,
                OtherPerson::try_from("SMITH<JOHN".to_owned())
                    .map_err(|e| format!("OtherPerson: {e}"))?,
            ],
            ..AdditionalDocumentData::default()
        };
        let out = format!("{}", DumpDg12(Some(&dg12)));
        check_true(out.contains("DG12 -- additional document data:"), "header")?;
        check_true(
            out.contains("issuing authority (0x5F19)"),
            "label issuing authority",
        )?;
        check_true(out.contains("DVV"), "DVV")?;
        check_true(
            out.contains("date of issue (0x5F26)"),
            "label date of issue",
        )?;
        // IssueDate Display renders ISO 8601 form, not the
        // on-card YYYYMMDD shape.
        check_true(out.contains("2021-01-01"), "iso date")?;
        check_true(out.contains("2 entries"), "2 entries")?;
        check_true(out.contains("- KORHONEN<MAIJA"), "KORHONEN")?;
        check_true(out.contains("- SMITH<JOHN"), "SMITH")?;
        // Absent fields still appear.
        check_true(out.contains("endorsements (0x5F1B)"), "endorsements")?;
        check_true(out.contains("<absent>"), "<absent>")
    }
}
