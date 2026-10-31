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

//! Reading and judging the signed documents [`crate::sign::document`]
//! writes: a PDF carrying `PAdES` signatures, an `ASiC-E` or `BDOC`
//! container carrying `XAdES` or `CAdES` signatures, and a bare
//! `CAdES` `SignedData` with the document attached.
//!
//! The verdict is computed from the document's own bytes: the digest
//! over the signed spans, the signature over the signed attributes, the
//! ESS binding of the signer certificate, the path from the signer to a
//! trust anchor, every signature timestamp against its own embedded
//! chain, and the revocation answers the document carries. Nothing here
//! touches the network; a caller that wants a fresh revocation answer
//! asks for one above this crate and replaces [`Revocation::Unavailable`].
//!
//! # Conformance
//!
//! - `ETSI EN 319 142-1` V1.2.1 clause 4.1 and 6.3: `PAdES` baseline
//!   signatures, the `DSS` and document timestamps of clause 5.4.
//! - `ETSI EN 319 142-2` V1.2.1 clause 4: the `CMS` profile with the
//!   `adbe.pkcs7.detached` subfilter, and annex A.4 on serial
//!   signatures, each judged against its own byte range.
//! - `ETSI EN 319 122-1`, `EN 319 132-1`, `EN 319 162-1`: the `CAdES`,
//!   `XAdES` and `ASiC` sides.
//! - `ETSI EN 319 102-1` clause 5.2.6: a certificate is validated by a
//!   path to a trust anchor, at the validation time, with its
//!   revocation status; a signer that only verifies against its own
//!   embedded certificate is reported as unanchored, never as valid.

pub mod asic;
pub mod cades;
pub mod pdf;
pub mod trust;
pub mod xades;
pub mod xml;

use crate::crypto::digest::Sha256;
use crate::identity::Peuin;
use crate::sign::timestamp::VerifiedTimestampToken;
use crate::sign::validation::ValidationMaterial;
use crate::x509::{DateTime, OwnedCert};

/// The bytes of one document file, as read from disk or received from
/// a counterparty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentFile {
    /// The complete file.
    bytes: Vec<u8>,
}

impl DocumentFile {
    /// Wrap the complete contents of one file.
    #[must_use]
    pub const fn from_file(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// The complete file.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The root certificates a verifier trusts, as DER.
///
/// A path that ends in one of these is anchored; a path that ends in
/// any other self-signed certificate is not, however well it verifies.
/// The roots also serve as path candidates, since a document need not
/// carry the anchor it chains to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustAnchors<'a> {
    /// DER of the trusted root certificates.
    certificates: &'a [&'a [u8]],
}

impl<'a> TrustAnchors<'a> {
    /// Trust exactly these roots.
    #[must_use]
    pub const fn new(certificates: &'a [&'a [u8]]) -> Self {
        Self { certificates }
    }

    /// Whether a certificate with this fingerprint is a trusted root.
    #[must_use]
    pub fn contains(&self, fingerprint: Sha256) -> bool {
        self.certificates
            .iter()
            .any(|certificate| Sha256::of(certificate) == fingerprint)
    }

    /// DER of every trusted root.
    #[must_use]
    pub const fn certificates(&self) -> &'a [&'a [u8]] {
        self.certificates
    }
}

/// The holder a signer certificate names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerIdentity {
    /// The name the subject goes by.
    pub name: SubjectName,
    /// The Finnish electronic identifier, on certificates issued to a
    /// person.
    pub identifier: Option<Peuin>,
}

/// The name a certificate's subject goes by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectName {
    /// The subject's common name as the certificate spells it.
    CommonName(String),
    /// The whole subject as an RFC 4514 string, when it has no common
    /// name; empty when the subject is empty.
    Distinguished(String),
}

impl SubjectName {
    /// The name `certificate`'s subject goes by: its common name, else
    /// the whole subject.
    #[must_use]
    pub fn of(certificate: &OwnedCert) -> Self {
        let subject = certificate.view().subject;
        subject.common_name().map_or_else(
            || Self::Distinguished(subject.rfc4514()),
            |name| Self::CommonName(name.as_str().to_owned()),
        )
    }

    /// The name as the certificate spells it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::CommonName(name) | Self::Distinguished(name) => name,
        }
    }
}

/// A certificate path, nearest certificate first.
#[derive(Debug, Clone)]
pub struct CertificatePath {
    /// The certificates, each issued by the next.
    pub certificates: Vec<OwnedCert>,
    /// Whether the last certificate is a trust anchor.
    pub anchored: bool,
}

/// The revocation basis one signature reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// A verified OCSP response or CRL says the signer was good; the
    /// time is the answer's own production time.
    Good {
        /// `producedAt` of the OCSP response, or `thisUpdate` of the
        /// CRL, that answered.
        checked_at: DateTime,
    },
    /// A verified answer says a certificate on the signer's path is
    /// revoked.
    Revoked {
        /// The revocation time the answer states: OCSP
        /// `revocationTime` or the CRL entry's `revocationDate`.
        revoked_at: DateTime,
    },
    /// No verified answer was available.
    Unavailable,
}

/// One signature timestamp token, as a format reader checked it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampCheck {
    /// The token verifies under its embedded signer and imprints this
    /// signature.
    Verified(VerifiedTimestampToken),
    /// The token does not verify, or imprints other data.
    Unverified {
        /// The `genTime` the token states, when it parses.
        claimed_at: Option<DateTime>,
    },
}

/// One signature timestamp of a report.
#[derive(Debug, Clone)]
pub enum SignatureTimestamp {
    /// A verified token over this signature.
    Proven {
        /// The token's authenticated `genTime`.
        generated_at: DateTime,
        /// The token signer's path, signer first.
        chain: CertificatePath,
    },
    /// A token that did not verify over this signature, or whose
    /// signer's path reaches no pinned root.
    Unproven {
        /// The `genTime` the token states, when it parses.
        claimed_at: Option<DateTime>,
        /// The token signer's path as far as it was built, signer
        /// first, when the token verified.
        chain: Option<CertificatePath>,
    },
}

/// One document timestamp covering a signature (`ETSI EN 319 142-1`
/// clause 5.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentTimestamp {
    /// The token verifies over its byte range and its signer's path
    /// reaches a pinned root; it proves the signature existed.
    Proven {
        /// The token's authenticated `genTime`.
        generated_at: DateTime,
    },
    /// The token does not verify over its byte range, or its signer's
    /// path reaches no pinned root; it proves nothing.
    Unproven {
        /// The `genTime` the token states, when it parses.
        claimed_at: Option<DateTime>,
    },
}

/// One signature's verified facts.
#[derive(Debug, Clone)]
pub struct SignatureReport {
    /// The holder the signer certificate names.
    pub signer: SignerIdentity,
    /// The signer certificate, for revocation checks above this crate.
    pub signer_certificate: OwnedCert,
    /// The certificates above the signer, issuer first: the anchored
    /// path when there is one, else as far as it was built.
    pub chain: CertificatePath,
    /// Whether the digest over the signed spans equals the signed
    /// message digest, and every reference the signature makes was
    /// recomputed and matched.
    pub document_intact: bool,
    /// Whether the signature verifies over the signed attributes under
    /// the signer certificate, with the ESS binding where the profile
    /// requires it.
    pub signature_valid: bool,
    /// Whether the signer chains to one of the caller's trust anchors.
    pub chain_verified: bool,
    /// The signing time the signature claims: the `CMS` `signing-time`
    /// attribute, the `XAdES` `SigningTime` property, or the PDF
    /// signature dictionary's `/M` entry.
    pub claimed_signing_time: Option<DateTime>,
    /// The earliest verified proof that the signature existed: a
    /// signature timestamp over the signature value, or a document
    /// timestamp whose byte range covers it.
    pub proof_of_existence: Option<DateTime>,
    /// Every signature timestamp the signature carries, in encoded
    /// order.
    pub signature_timestamps: Vec<SignatureTimestamp>,
    /// Every document timestamp whose byte range covers this
    /// signature, in document order.
    pub document_timestamps: Vec<DocumentTimestamp>,
    /// Whether every signature timestamp present verified against its
    /// own embedded chain and imprints this signature, and at least one
    /// proof of existence was found.
    pub timestamps_valid: bool,
    /// Whether the signature's byte range runs to the end of the file.
    /// A signature followed by a document timestamp or a `DSS`
    /// revision does not, and is none the worse for it.
    pub covers_whole_document: bool,
    /// The revocation basis reached from the evidence the document
    /// carries.
    pub revocation: Revocation,
}

impl SignatureReport {
    /// The one-line verdict of the facts above. Revocation is not part
    /// of it: an unavailable answer is reported beside the verdict,
    /// a revoked answer is a verdict of its own.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.document_intact && self.signature_valid && self.chain_verified && self.timestamps_valid
    }
}

/// A signature of a profile this verifier does not implement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedSignature {
    /// The holder, when the signer certificate could be read.
    pub signer: Option<SignerIdentity>,
    /// The profile feature that was refused.
    pub profile: &'static str,
}

/// One signature a document carries.
#[derive(Debug, Clone)]
pub enum SignatureEntry {
    /// A signature this verifier judged.
    Judged(SignatureReport),
    /// A signature of a profile this verifier does not implement.
    Unsupported(UnsupportedSignature),
}

/// The complete verification of one document.
#[derive(Debug, Clone)]
pub struct DocumentReport {
    /// Every signature, in document order.
    pub signatures: Vec<SignatureEntry>,
}

impl DocumentReport {
    /// Whether every signature is judged valid and none is revoked.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.signatures.is_empty()
            && self.signatures.iter().all(|entry| match entry {
                SignatureEntry::Judged(signature) => {
                    signature.is_valid()
                        && !matches!(signature.revocation, Revocation::Revoked { .. })
                }
                SignatureEntry::Unsupported(_) => false,
            })
    }
}

/// Why a document yielded no report.
///
/// A negative verdict is not a failure; it lands on the report. These
/// are the cases where there is nothing to judge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentFailure {
    /// Neither a PDF, a ZIP container nor a `CMS` structure.
    NotASignedDocument,
    /// The file is of a known kind but its structure does not parse.
    Unreadable(&'static str),
    /// The file parses and carries no signature.
    NoSignatures,
    /// The file as a whole is of a profile this verifier does not
    /// implement, named so the reader knows what was refused.
    UnsupportedProfile(&'static str),
}

impl core::fmt::Display for DocumentFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotASignedDocument => f.write_str("not a signed document"),
            Self::Unreadable(what) => write!(f, "the document could not be read: {what}"),
            Self::NoSignatures => f.write_str("the document carries no signatures"),
            Self::UnsupportedProfile(what) => write!(f, "unsupported signature profile: {what}"),
        }
    }
}

impl core::error::Error for DocumentFailure {}

/// The header every PDF file starts with (ISO 32000-1 sec.7.5.2).
const PDF_HEADER: &[u8] = b"%PDF-";

/// The local file header signature that opens a ZIP archive, and so an
/// `ASiC` container (`ETSI EN 319 162-1` clause A.1; PKWARE APPNOTE
/// sec.4.3.7).
const ZIP_HEADER: &[u8] = b"PK\x03\x04";

/// The DER tag of the SEQUENCE a `CMS` `ContentInfo` starts with
/// (RFC 5652 sec.3; X.690 sec.8.9).
const DER_SEQUENCE_TAG: u8 = 0x30;

/// The kind of file the first bytes announce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileKind {
    /// A PDF, judged by [`pdf`].
    Pdf,
    /// A ZIP archive, judged as an `ASiC` container by [`asic`].
    Zip,
    /// A DER SEQUENCE, judged as a `CMS` structure with the document
    /// attached by [`cades`].
    Der,
}

impl FileKind {
    /// What the file's first bytes announce, if anything this module
    /// judges.
    fn of(file: &DocumentFile) -> Option<Self> {
        let bytes = file.as_bytes();
        if bytes.starts_with(PDF_HEADER) {
            Some(Self::Pdf)
        } else if bytes.starts_with(ZIP_HEADER) {
            Some(Self::Zip)
        } else if bytes.first() == Some(&DER_SEQUENCE_TAG) {
            Some(Self::Der)
        } else {
            None
        }
    }
}

/// Verify every signature of the document, as of `now`.
///
/// `now` stands in for the validation time of a signature that proves
/// no earlier existence; a signature with a verified timestamp is
/// judged at that time (`ETSI EN 319 102-1` clause 5.6.2).
///
/// # Errors
/// [`DocumentFailure`] when there is nothing to judge: the file is not
/// a signed document, does not parse, carries no signature, or carries
/// only signatures of a profile this module does not implement. A
/// negative verdict is not an error; it lands on the report.
pub fn verify(
    file: &DocumentFile,
    anchors: TrustAnchors<'_>,
    now: DateTime,
) -> Result<DocumentReport, DocumentFailure> {
    match FileKind::of(file).ok_or(DocumentFailure::NotASignedDocument)? {
        FileKind::Pdf => verify_pdf(file, anchors, now),
        FileKind::Zip => verify_asic(file, anchors, now),
        FileKind::Der => verify_attached_cades(file, anchors, now),
    }
}

/// Judge every signature dictionary of a PDF (`ETSI EN 319 142-1`
/// clause 6.3; `EN 319 142-2` clause 4.2.3 and annex A.4).
fn verify_pdf(
    file: &DocumentFile,
    anchors: TrustAnchors<'_>,
    now: DateTime,
) -> Result<DocumentReport, DocumentFailure> {
    let document = pdf::PdfDocument::parse(file)?;
    if document.signatures().is_empty() {
        return Err(DocumentFailure::NoSignatures);
    }
    let mut store = trust::MaterialPool::new();
    store.add_material(document.validation_store());
    let timestamp_anchor_ders = timestamp_anchors(anchors);
    let document_timestamps: Vec<VerifiedDocumentTimestamp> = document
        .signatures()
        .iter()
        .filter(|signature| signature.kind == pdf::SignatureKind::DocumentTimestamp)
        .map(|signature| {
            let verified = crate::sign::timestamp::verify_token(&signature.cms, |algorithm| {
                signature.byte_range.digest(file, algorithm)
            })
            .ok();
            let stamp = match verified {
                Some(token)
                    if trust::token_path(
                        &token,
                        &store,
                        TrustAnchors::new(&timestamp_anchor_ders),
                    )
                    .anchored =>
                {
                    DocumentTimestamp::Proven {
                        generated_at: token.generated_at,
                    }
                }
                Some(token) => DocumentTimestamp::Unproven {
                    claimed_at: Some(token.generated_at),
                },
                None => DocumentTimestamp::Unproven {
                    claimed_at: crate::sign::timestamp::claimed_generation_time(&signature.cms),
                },
            };
            VerifiedDocumentTimestamp {
                stamp,
                covers_up_to: signature.byte_range.end(),
            }
        })
        .collect();
    let mut signatures = Vec::new();
    for found in document.signatures() {
        let ess = match found.kind {
            pdf::SignatureKind::Signature(pdf::SubFilter::EtsiCadesDetached) => {
                cades::EssBinding::Required
            }
            pdf::SignatureKind::Signature(pdf::SubFilter::AdbePkcs7Detached) => {
                cades::EssBinding::NotRequired
            }
            pdf::SignatureKind::Signature(pdf::SubFilter::EtsiRfc3161 | pdf::SubFilter::Other) => {
                signatures.push(unsupported(None, "PDF signature subfilter"));
                continue;
            }
            pdf::SignatureKind::DocumentTimestamp => continue,
        };
        let signature = match cades::CadesSignature::parse(found.cms.clone()) {
            Ok(signature) => signature,
            Err(error) => {
                signatures.push(unsupported(None, unsupported_cades(error)));
                continue;
            }
        };
        let spans = found
            .byte_range
            .spans()
            .map(|span| file.as_bytes().get(span).unwrap_or_default());
        let digest = cades::ContentDigest::of_spans(signature.digest_algorithm(), &spans);
        let verdict = signature.verify(cades::Content::Detached { digest: &digest }, ess);
        let mut pool = trust::MaterialPool::new();
        pool.add_material(document.validation_store());
        signatures.push(SignatureEntry::Judged(report(
            SignatureFacts {
                signer: signature.signer_certificate(),
                embedded_certificates: signature.embedded_certificates(),
                material: signature.embedded_material(),
                document_intact: verdict.document_intact,
                signature_valid: verdict.signature_valid,
                claimed_signing_time: signature.signing_time().or(found.signing_time_entry),
                timestamps: verdict.signature_timestamps,
                covering_document_timestamps: document_timestamps
                    .iter()
                    .filter(|stamp| stamp.covers_up_to >= found.byte_range.end())
                    .map(|stamp| stamp.stamp)
                    .collect(),
                covers_whole_document: found.covers_whole_document,
            },
            pool,
            anchors,
            now,
        )));
    }
    if signatures.is_empty() {
        return Err(DocumentFailure::NoSignatures);
    }
    Ok(DocumentReport { signatures })
}

/// One document timestamp and how far into the file its byte range
/// reaches (`ETSI EN 319 142-1` clause 5.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifiedDocumentTimestamp {
    /// What the token proves.
    stamp: DocumentTimestamp,
    /// One past the last byte the token covers; a signature whose
    /// own range ends at or before it is proven to have existed.
    covers_up_to: usize,
}

/// Judge every signature of an `ASiC-E` or `BDOC` container: `XAdES`
/// signature files (`ETSI EN 319 162-1` clause A.4) and `CAdES`
/// signature files with their manifests (clause A.5).
fn verify_asic(
    file: &DocumentFile,
    anchors: TrustAnchors<'_>,
    now: DateTime,
) -> Result<DocumentReport, DocumentFailure> {
    let container = asic::AsicContainer::parse(file).map_err(|error| match error {
        asic::AsicReadError::NotAZip => DocumentFailure::NotASignedDocument,
        asic::AsicReadError::Malformed(what) => DocumentFailure::Unreadable(what),
        asic::AsicReadError::Unsupported(what) => DocumentFailure::UnsupportedProfile(what),
    })?;
    let mut signatures = Vec::new();
    for entry in container.xades_signature_files() {
        let Ok(found) = xades::signatures(entry) else {
            signatures.push(unsupported(None, "XAdES signature file"));
            continue;
        };
        for signature in found {
            if let Some(what) = signature.unsupported() {
                signatures.push(unsupported(Some(signature.signer_certificate()), what));
                continue;
            }
            let verdict = signature.verify(&container);
            signatures.push(SignatureEntry::Judged(report(
                SignatureFacts {
                    signer: signature.signer_certificate(),
                    embedded_certificates: signature.embedded_certificates(),
                    material: signature.embedded_material(),
                    document_intact: verdict.document_intact,
                    signature_valid: verdict.signature_valid,
                    claimed_signing_time: signature.signing_time(),
                    timestamps: verdict.signature_timestamps,
                    covering_document_timestamps: Vec::new(),
                    covers_whole_document: true,
                },
                trust::MaterialPool::new(),
                anchors,
                now,
            )));
        }
    }
    for entry in container.cades_signatures() {
        let signature = match cades::CadesSignature::parse(entry.signature.content.clone()) {
            Ok(signature) => signature,
            Err(error) => {
                signatures.push(unsupported(None, unsupported_cades(error)));
                continue;
            }
        };
        let Some(manifest) = &entry.manifest else {
            signatures.push(unsupported(
                Some(signature.signer_certificate()),
                "CAdES signature without a manifest",
            ));
            continue;
        };
        let digest =
            cades::ContentDigest::of_spans(signature.digest_algorithm(), &[&manifest.content]);
        let verdict = signature.verify(
            cades::Content::Detached { digest: &digest },
            cades::EssBinding::Required,
        );
        signatures.push(SignatureEntry::Judged(report(
            SignatureFacts {
                signer: signature.signer_certificate(),
                embedded_certificates: signature.embedded_certificates(),
                material: signature.embedded_material(),
                document_intact: verdict.document_intact && container.manifest_intact(entry),
                signature_valid: verdict.signature_valid,
                claimed_signing_time: signature.signing_time(),
                timestamps: verdict.signature_timestamps,
                covering_document_timestamps: Vec::new(),
                covers_whole_document: true,
            },
            trust::MaterialPool::new(),
            anchors,
            now,
        )));
    }
    if signatures.is_empty() {
        return Err(DocumentFailure::NoSignatures);
    }
    Ok(DocumentReport { signatures })
}

/// Judge a bare `CMS` structure carrying the document as its
/// `eContent` (`ETSI EN 319 122-1`).
fn verify_attached_cades(
    file: &DocumentFile,
    anchors: TrustAnchors<'_>,
    now: DateTime,
) -> Result<DocumentReport, DocumentFailure> {
    let signature = cades::CadesSignature::parse(file.as_bytes().to_vec())
        .map_err(|error| DocumentFailure::UnsupportedProfile(unsupported_cades(error)))?;
    let verdict = signature.verify(cades::Content::Attached, cades::EssBinding::Required);
    let report = report(
        SignatureFacts {
            signer: signature.signer_certificate(),
            embedded_certificates: signature.embedded_certificates(),
            material: signature.embedded_material(),
            document_intact: verdict.document_intact,
            signature_valid: verdict.signature_valid,
            claimed_signing_time: signature.signing_time(),
            timestamps: verdict.signature_timestamps,
            covering_document_timestamps: Vec::new(),
            covers_whole_document: true,
        },
        trust::MaterialPool::new(),
        anchors,
        now,
    );
    Ok(DocumentReport {
        signatures: vec![SignatureEntry::Judged(report)],
    })
}

/// The entry of a signature of a profile this module does not
/// implement, naming the holder when the signer certificate is known.
fn unsupported(signer: Option<&OwnedCert>, profile: &'static str) -> SignatureEntry {
    SignatureEntry::Unsupported(UnsupportedSignature {
        signer: signer.map(SignerIdentity::of),
        profile,
    })
}

/// What a `CMS` structure this module cannot parse is reported as.
const fn unsupported_cades(error: cades::CadesReadError) -> &'static str {
    match error {
        cades::CadesReadError::NotSignedData => "not a CMS SignedData with one signer",
        cades::CadesReadError::NoSignedAttributes => "CMS signature without signed attributes",
        cades::CadesReadError::UnsupportedDigest => "digest algorithm",
        cades::CadesReadError::UnsupportedSignatureAlgorithm => "signature algorithm",
        cades::CadesReadError::SignerCertificateMissing => "signer certificate not embedded",
        cades::CadesReadError::SignerCertificateAmbiguous => "ambiguous signer certificate",
    }
}

/// The roots a timestamp's signer must chain to for the timestamp to
/// prove a time: the caller's anchors and the pinned time-stamping
/// roots.
fn timestamp_anchors<'a>(anchors: TrustAnchors<'a>) -> Vec<&'a [u8]> {
    anchors
        .certificates()
        .iter()
        .copied()
        .chain(
            crate::trust_roots::PINNED_TIME_STAMPING_ROOT_DER
                .iter()
                .copied(),
        )
        .collect()
}

/// The facts a format reader established about one signature, before
/// the chain and revocation are judged.
struct SignatureFacts<'a> {
    /// The signer certificate.
    signer: &'a OwnedCert,
    /// Every certificate the signature embeds.
    embedded_certificates: &'a [Vec<u8>],
    /// The validation material the signature embeds.
    material: ValidationMaterial,
    /// Whether the signed content and every reference recomputed.
    document_intact: bool,
    /// Whether the signature verifies under the signer.
    signature_valid: bool,
    /// The signing time the signature claims.
    claimed_signing_time: Option<DateTime>,
    /// Every signature timestamp, in encoded order.
    timestamps: Vec<TimestampCheck>,
    /// The document timestamps covering this signature.
    covering_document_timestamps: Vec<DocumentTimestamp>,
    /// Whether the signature's range runs to the end of the file.
    covers_whole_document: bool,
}

/// Turn one signature's facts into a report row: chain and revocation
/// judged from the signature's own material, `pool` and the anchors,
/// at the earliest proof of existence.
fn report(
    facts: SignatureFacts<'_>,
    mut pool: trust::MaterialPool,
    anchors: TrustAnchors<'_>,
    now: DateTime,
) -> SignatureReport {
    pool.add_material(&facts.material);
    pool.add_certificates(facts.embedded_certificates);
    pool.add_certificates(
        &anchors
            .certificates()
            .iter()
            .map(|der| der.to_vec())
            .collect::<Vec<_>>(),
    );
    let timestamp_anchor_ders = timestamp_anchors(anchors);
    let timestamp_anchors = TrustAnchors::new(&timestamp_anchor_ders);
    let signature_timestamps: Vec<SignatureTimestamp> = facts
        .timestamps
        .iter()
        .map(|check| match check {
            TimestampCheck::Verified(token) => {
                let chain = trust::token_path(token, &pool, timestamp_anchors);
                if chain.anchored {
                    SignatureTimestamp::Proven {
                        generated_at: token.generated_at,
                        chain,
                    }
                } else {
                    SignatureTimestamp::Unproven {
                        claimed_at: Some(token.generated_at),
                        chain: Some(chain),
                    }
                }
            }
            TimestampCheck::Unverified { claimed_at } => SignatureTimestamp::Unproven {
                claimed_at: *claimed_at,
                chain: None,
            },
        })
        .collect();
    let proven: Vec<DateTime> = signature_timestamps
        .iter()
        .filter_map(|timestamp| match timestamp {
            SignatureTimestamp::Proven { generated_at, .. } => Some(*generated_at),
            SignatureTimestamp::Unproven { .. } => None,
        })
        .collect();
    let proof_of_existence = proven
        .iter()
        .copied()
        .chain(
            facts
                .covering_document_timestamps
                .iter()
                .filter_map(|stamp| match stamp {
                    DocumentTimestamp::Proven { generated_at } => Some(*generated_at),
                    DocumentTimestamp::Unproven { .. } => None,
                }),
        )
        .min();
    let timestamps_valid =
        proof_of_existence.is_some() && proven.len() == signature_timestamps.len();
    let chain = trust::judge(
        facts.signer,
        &pool,
        anchors,
        proof_of_existence.unwrap_or(now),
    );
    SignatureReport {
        signer: SignerIdentity::of(facts.signer),
        signer_certificate: facts.signer.clone(),
        chain: chain.path,
        document_intact: facts.document_intact,
        signature_valid: facts.signature_valid,
        chain_verified: chain.anchored,
        claimed_signing_time: facts.claimed_signing_time,
        proof_of_existence,
        signature_timestamps,
        document_timestamps: facts.covering_document_timestamps,
        timestamps_valid,
        covers_whole_document: facts.covers_whole_document,
        revocation: chain.revocation,
    }
}

impl SignerIdentity {
    /// The holder a certificate names: its [`SubjectName`], and the
    /// electronic identifier.
    #[must_use]
    pub fn of(certificate: &OwnedCert) -> Self {
        Self {
            name: SubjectName::of(certificate),
            identifier: certificate.view().subject.peuin(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CertificatePath, DocumentFailure, DocumentFile, DocumentReport, DocumentTimestamp,
        Revocation, SignatureEntry, SignatureReport, SignatureTimestamp, SignerIdentity,
        SubjectName, TrustAnchors, UnsupportedSignature, verify,
    };
    use crate::ber::tlv;
    use crate::document::trust::testkit::{
        CertificateSpec, Curve, OcspSpec, PRINTABLE_STRING, TestKey, UTF8_STRING, ca_extensions,
        certificate, certificate_named, day, minimal_pdf, name_of, ocsp_response, timestamp_token,
        timestamping_extensions,
    };
    use crate::hex::Hex;
    use crate::oid::known;
    use crate::sign::asic::DataObject;
    use crate::sign::cades::{DigestAlgorithm, SignatureAlgorithm, SignerParameters, SigningTime};
    use crate::sign::document::{Format, plan};
    use crate::sign::pades::{
        DEFAULT_SIGNATURE_CAPACITY, SignatureMetadata, prepare_document_timestamp,
    };
    use crate::sign::validation::ValidationMaterial;
    use crate::x509::{Certificate, OwnedCert};

    /// Root common name.
    const ROOT: &str = "Synthetic Root CA";
    /// Intermediate common name.
    const INTERMEDIATE: &str = "Synthetic Issuing CA";
    /// Common name of the signer the root issues.
    const DIRECT_SIGNER: &str = "Synthetic Signer";
    /// Common name of the signer the intermediate issues.
    const ISSUED_SIGNER: &str = "Synthetic Issued Signer";
    /// TSA common name.
    const TSA: &str = "Synthetic Time Stamping Unit";
    /// Common name of a root nobody trusts.
    const STRANGER: &str = "Synthetic Stranger CA";
    /// Root serial.
    const ROOT_SERIAL: u8 = 1;
    /// Intermediate serial.
    const INTERMEDIATE_SERIAL: u8 = 2;
    /// Direct signer serial.
    const DIRECT_SIGNER_SERIAL: u8 = 3;
    /// Issued signer serial.
    const ISSUED_SIGNER_SERIAL: u8 = 4;
    /// TSA serial.
    const TSA_SERIAL: u8 = 5;
    /// Stranger root serial.
    const STRANGER_SERIAL: u8 = 6;
    /// Person certificate serial.
    const PERSON_SERIAL: u8 = 7;
    /// Day every certificate starts.
    const ISSUED: u8 = 1;
    /// Day of the timestamps.
    const STAMPED: u8 = 10;
    /// Day the OCSP answers are produced, after the timestamps.
    const ANSWERED: u8 = 11;
    /// The validation day.
    const NOW: u8 = 20;
    /// Day every certificate ends.
    const ENDS: u8 = 28;
    /// The signing time the writers assert.
    const SIGNING_TIME: SigningTime = SigningTime {
        year: 2026,
        month: 6,
        day: 10,
        hour: 12,
        minute: 0,
        second: 0,
    };
    /// A container entry's content.
    const NOTE: &[u8] = b"Synthetic note, signed for the verifier tests";
    /// A container entry's name.
    const NOTE_NAME: &str = "note.txt";
    /// A container entry's media type.
    const NOTE_TYPE: &str = "text/plain";
    /// The PDF's entry name for the router.
    const PDF_NAME: &str = "document.pdf";
    /// The PDF media type.
    const PDF_TYPE: &str = "application/pdf";
    /// Text inside the first signed span of every signed fixture PDF.
    const MEDIA_BOX: &[u8] = b"/MediaBox [0 0 200 200]";
    /// The same text with one byte changed.
    const TAMPERED_MEDIA_BOX: &[u8] = b"/MediaBox [0 0 200 201]";
    /// Given name of the person certificate.
    const GIVEN: &str = "Given";
    /// Surname of the person certificate.
    const SURNAME: &str = "Surname";
    /// Common name of the person certificate.
    const PERSON: &str = "Surname Given 12345678X";
    /// A synthetic electronic identifier of the right shape.
    const IDENTIFIER: &str = "12345678X";
    /// A country name.
    const COUNTRY: &str = "FI";
    /// An organization name with a character RFC 4514 escapes.
    const ORGANIZATION: &str = "Synthetic, Org";
    /// An organization name carrying NUL.
    const WITH_NUL: &str = "Synthetic\0Org";
    /// [`WITH_NUL`] as RFC 4514 writes it.
    const ESCAPED_WITH_NUL: &str = r"Synthetic\00Org";
    /// [`ORGANIZATION`] as RFC 4514 writes it.
    const ESCAPED_ORGANIZATION: &str = "Synthetic\\, Org";

    /// Which signer signs.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Signer {
        /// Issued by the root.
        Direct,
        /// Issued by the intermediate.
        Issued,
    }

    /// Keys and certificates of one test world.
    struct World {
        /// Root key.
        root_key: TestKey,
        /// Root.
        root: Vec<u8>,
        /// Intermediate key.
        intermediate_key: TestKey,
        /// Intermediate, issued by the root.
        intermediate: Vec<u8>,
        /// Key of both signers.
        signer_key: TestKey,
        /// Signer issued by the root.
        direct_signer: Vec<u8>,
        /// Signer issued by the intermediate.
        issued_signer: Vec<u8>,
        /// TSA key.
        tsa_key: TestKey,
        /// TSA, issued by the root.
        tsa: Vec<u8>,
        /// A self-signed root nobody trusts.
        stranger: Vec<u8>,
    }

    /// A certificate valid from `ISSUED` to `ENDS`.
    fn spec<'a>(
        serial: u8,
        subject: &'a str,
        issuer: &'a str,
        extensions: Vec<Vec<u8>>,
    ) -> CertificateSpec<'a> {
        CertificateSpec {
            serial,
            subject,
            issuer,
            not_before: day(ISSUED),
            not_after: day(ENDS),
            extensions,
        }
    }

    impl World {
        /// Fresh keys and certificates.
        fn new() -> Self {
            let root_key = TestKey::generate(Curve::P384);
            let intermediate_key = TestKey::generate(Curve::P384);
            let signer_key = TestKey::generate(Curve::P256);
            let tsa_key = TestKey::generate(Curve::P256);
            let stranger_key = TestKey::generate(Curve::P256);
            Self {
                root: certificate(
                    &spec(ROOT_SERIAL, ROOT, ROOT, ca_extensions()),
                    &root_key,
                    &root_key,
                ),
                intermediate: certificate(
                    &spec(INTERMEDIATE_SERIAL, INTERMEDIATE, ROOT, ca_extensions()),
                    &intermediate_key,
                    &root_key,
                ),
                direct_signer: certificate(
                    &spec(DIRECT_SIGNER_SERIAL, DIRECT_SIGNER, ROOT, Vec::new()),
                    &signer_key,
                    &root_key,
                ),
                issued_signer: certificate(
                    &spec(
                        ISSUED_SIGNER_SERIAL,
                        ISSUED_SIGNER,
                        INTERMEDIATE,
                        Vec::new(),
                    ),
                    &signer_key,
                    &intermediate_key,
                ),
                tsa: certificate(
                    &spec(TSA_SERIAL, TSA, ROOT, timestamping_extensions()),
                    &tsa_key,
                    &root_key,
                ),
                stranger: certificate(
                    &spec(STRANGER_SERIAL, STRANGER, STRANGER, ca_extensions()),
                    &stranger_key,
                    &stranger_key,
                ),
                root_key,
                intermediate_key,
                signer_key,
                tsa_key,
            }
        }

        /// Sign `objects` as `format` through the repository's router,
        /// optionally with a signature timestamp, embedding `material`.
        fn sign(
            &self,
            format: Format,
            objects: Vec<DataObject>,
            signer: Signer,
            timestamp: bool,
            material: &ValidationMaterial,
        ) -> Vec<u8> {
            let der = match signer {
                Signer::Direct => &self.direct_signer,
                Signer::Issued => &self.issued_signer,
            };
            let certificate = Certificate::from_der(der).expect("signer parses");
            let parameters = SignerParameters {
                certificate: &certificate,
                digest_algorithm: DigestAlgorithm::Sha256,
                signature_algorithm: SignatureAlgorithm::EcdsaSha256,
                signing_time: Some(SIGNING_TIME),
            };
            let planned =
                plan(format, objects, &parameters, &SignatureMetadata::default()).expect("plans");
            let signature = self.signer_key.sign_raw(planned.to_be_signed());
            let mut timestamps = Vec::new();
            if timestamp {
                let imprint = planned
                    .timestamp_digest(&parameters, &signature, DigestAlgorithm::Sha256)
                    .expect("timestamp digest");
                timestamps.push(timestamp_token(
                    &self.tsa,
                    &self.tsa_key,
                    &imprint,
                    day(STAMPED),
                ));
            }
            planned
                .finish(&parameters, &signature, &timestamps, material)
                .expect("finishes")
        }

        /// A signed PDF.
        fn pdf(&self, signer: Signer, timestamp: bool, material: &ValidationMaterial) -> Vec<u8> {
            self.sign(
                Format::Pades,
                vec![DataObject {
                    name: PDF_NAME.to_owned(),
                    mime_type: PDF_TYPE.to_owned(),
                    content: minimal_pdf(),
                }],
                signer,
                timestamp,
                material,
            )
        }

        /// A signed container or CMS over the note.
        fn note(&self, format: Format) -> Vec<u8> {
            self.sign(
                format,
                vec![DataObject {
                    name: NOTE_NAME.to_owned(),
                    mime_type: NOTE_TYPE.to_owned(),
                    content: NOTE.to_vec(),
                }],
                Signer::Direct,
                false,
                &ValidationMaterial::default(),
            )
        }

        /// The issued signer's chain and OCSP answers about the signer
        /// and the intermediate, produced after the timestamps.
        fn lt_material(&self, revoked: bool, with_root: bool) -> ValidationMaterial {
            let issuer = OwnedCert::from_der(&self.intermediate).expect("intermediate parses");
            let answer = ocsp_response(&OcspSpec {
                responder_key: &self.intermediate_key,
                responder: INTERMEDIATE,
                issuer: &issuer,
                serial: ISSUED_SIGNER_SERIAL,
                revoked: revoked.then(|| day(ISSUED)),
                produced_at: day(ANSWERED),
                this_update: day(ANSWERED),
                next_update: Some(day(ENDS)),
                embedded: Vec::new(),
            });
            let root = OwnedCert::from_der(&self.root).expect("root parses");
            let intermediate_answer = ocsp_response(&OcspSpec {
                responder_key: &self.root_key,
                responder: ROOT,
                issuer: &root,
                serial: INTERMEDIATE_SERIAL,
                revoked: None,
                produced_at: day(ANSWERED),
                this_update: day(ANSWERED),
                next_update: Some(day(ENDS)),
                embedded: Vec::new(),
            });
            let mut certificates = vec![self.intermediate.clone()];
            if with_root {
                certificates.push(self.root.clone());
            }
            ValidationMaterial {
                certificates,
                ocsp_responses: vec![answer, intermediate_answer],
                crls: Vec::new(),
            }
        }

        /// Verify `bytes` trusting the root.
        fn verify_trusting_root(&self, bytes: Vec<u8>) -> Result<DocumentReport, DocumentFailure> {
            verify_with(bytes, &[&self.root])
        }
    }

    /// Verify `bytes` at `NOW` trusting `anchors`.
    fn verify_with(bytes: Vec<u8>, anchors: &[&[u8]]) -> Result<DocumentReport, DocumentFailure> {
        verify(
            &DocumentFile::from_file(bytes),
            TrustAnchors::new(anchors),
            day(NOW),
        )
    }

    /// The one signature of a report.
    fn only(report: &DocumentReport) -> &SignatureReport {
        let [SignatureEntry::Judged(signature)] = report.signatures.as_slice() else {
            panic!("one judged signature");
        };
        signature
    }

    /// The subject names along `path`.
    fn names(path: &CertificatePath) -> Vec<String> {
        path.certificates
            .iter()
            .map(|certificate| SubjectName::of(certificate).as_str().to_owned())
            .collect()
    }

    /// Change one byte inside the first signed span.
    fn tamper(mut pdf: Vec<u8>) -> Vec<u8> {
        let at = pdf
            .windows(MEDIA_BOX.len())
            .position(|window| window == MEDIA_BOX)
            .expect("media box present");
        pdf.get_mut(at..at.saturating_add(MEDIA_BOX.len()))
            .expect("in range")
            .copy_from_slice(TAMPERED_MEDIA_BOX);
        pdf
    }

    #[test]
    fn a_level_b_pdf_is_intact_valid_and_anchored_without_proof_of_existence() {
        let world = World::new();
        let report = world
            .verify_trusting_root(world.pdf(Signer::Direct, false, &ValidationMaterial::default()))
            .expect("report");
        let signature = only(&report);
        assert!(signature.document_intact);
        assert!(signature.signature_valid);
        assert!(signature.chain_verified);
        assert_eq!(signature.proof_of_existence, None);
        assert!(!signature.timestamps_valid);
        assert!(signature.covers_whole_document);
        assert_eq!(signature.revocation, Revocation::Unavailable);
        assert_eq!(
            signature.signer.name,
            SubjectName::CommonName(DIRECT_SIGNER.to_owned())
        );
        assert_eq!(signature.claimed_signing_time, Some(day(STAMPED)));
        assert!(signature.signature_timestamps.is_empty());
        assert!(signature.document_timestamps.is_empty());
        assert_eq!(names(&signature.chain), vec![ROOT.to_owned()]);
        assert!(signature.chain.anchored);
    }

    #[test]
    fn a_signature_timestamp_proves_existence() {
        let world = World::new();
        let report = world
            .verify_trusting_root(world.pdf(Signer::Direct, true, &ValidationMaterial::default()))
            .expect("report");
        let signature = only(&report);
        assert!(signature.document_intact);
        assert!(signature.signature_valid);
        assert!(signature.chain_verified);
        assert_eq!(signature.proof_of_existence, Some(day(STAMPED)));
        assert!(signature.timestamps_valid);
        assert!(signature.is_valid());
        let [
            SignatureTimestamp::Proven {
                generated_at,
                chain,
            },
        ] = signature.signature_timestamps.as_slice()
        else {
            panic!("one proven timestamp");
        };
        assert_eq!(*generated_at, day(STAMPED));
        assert_eq!(names(chain), vec![TSA.to_owned(), ROOT.to_owned()]);
        assert!(chain.anchored);
    }

    #[test]
    fn a_timestamp_whose_root_is_not_pinned_proves_no_time() {
        let world = World::new();
        let report = verify_with(
            world.pdf(Signer::Direct, true, &ValidationMaterial::default()),
            &[&world.stranger],
        )
        .expect("report");
        let signature = only(&report);
        let [
            SignatureTimestamp::Unproven {
                claimed_at,
                chain: Some(chain),
            },
        ] = signature.signature_timestamps.as_slice()
        else {
            panic!("one unproven timestamp");
        };
        assert_eq!(*claimed_at, Some(day(STAMPED)));
        assert_eq!(names(chain), vec![TSA.to_owned()]);
        assert!(!chain.anchored);
        assert_eq!(signature.proof_of_existence, None);
        assert!(!signature.timestamps_valid);
    }

    #[test]
    fn level_lt_chains_through_the_store_and_reads_a_later_ocsp_answer() {
        let world = World::new();
        let pdf = world.pdf(Signer::Issued, true, &world.lt_material(false, false));
        let report = world.verify_trusting_root(pdf).expect("report");
        let signature = only(&report);
        assert!(signature.document_intact);
        assert!(signature.signature_valid);
        assert!(signature.chain_verified);
        assert!(signature.timestamps_valid);
        assert!(!signature.covers_whole_document);
        assert_eq!(
            signature.revocation,
            Revocation::Good {
                checked_at: day(ANSWERED)
            }
        );
        assert!(report.is_valid());
    }

    #[test]
    fn a_document_timestamp_covering_the_signature_proves_existence() {
        let world = World::new();
        let signed = world.pdf(Signer::Direct, false, &ValidationMaterial::default());
        let placeholder =
            prepare_document_timestamp(&signed, DEFAULT_SIGNATURE_CAPACITY).expect("prepares");
        let token = timestamp_token(
            &world.tsa,
            &world.tsa_key,
            &placeholder.digest(DigestAlgorithm::Sha256),
            day(STAMPED),
        );
        let stamped = placeholder.finish(&token).expect("finishes");
        let report = world.verify_trusting_root(stamped).expect("report");
        let signature = only(&report);
        assert!(signature.document_intact);
        assert!(signature.signature_valid);
        assert_eq!(signature.proof_of_existence, Some(day(STAMPED)));
        assert!(signature.timestamps_valid);
        assert!(!signature.covers_whole_document);
        assert_eq!(
            signature.document_timestamps,
            vec![DocumentTimestamp::Proven {
                generated_at: day(STAMPED)
            }]
        );
    }

    #[test]
    fn a_document_timestamp_under_an_unknown_root_is_listed_and_proves_nothing() {
        let world = World::new();
        let signed = world.pdf(Signer::Direct, false, &ValidationMaterial::default());
        let placeholder =
            prepare_document_timestamp(&signed, DEFAULT_SIGNATURE_CAPACITY).expect("prepares");
        let token = timestamp_token(
            &world.tsa,
            &world.tsa_key,
            &placeholder.digest(DigestAlgorithm::Sha256),
            day(STAMPED),
        );
        let stamped = placeholder.finish(&token).expect("finishes");
        let report = verify_with(stamped, &[&world.stranger]).expect("report");
        let signature = only(&report);
        assert_eq!(
            signature.document_timestamps,
            vec![DocumentTimestamp::Unproven {
                claimed_at: Some(day(STAMPED))
            }]
        );
        assert_eq!(signature.proof_of_existence, None);
        assert!(!signature.timestamps_valid);
    }

    #[test]
    fn a_changed_byte_in_the_signed_span_breaks_only_integrity() {
        let world = World::new();
        let pdf = tamper(world.pdf(Signer::Direct, false, &ValidationMaterial::default()));
        let report = world.verify_trusting_root(pdf).expect("report");
        let signature = only(&report);
        assert!(!signature.document_intact);
        assert!(signature.signature_valid);
        assert!(signature.chain_verified);
        assert_eq!(signature.proof_of_existence, None);
        assert!(!report.is_valid());
    }

    #[test]
    fn an_untrusted_root_leaves_the_chain_unverified_but_names_the_issuer() {
        let world = World::new();
        let pdf = world.pdf(Signer::Issued, true, &world.lt_material(false, true));
        let report = verify_with(pdf, &[&world.stranger]).expect("report");
        let signature = only(&report);
        assert!(signature.document_intact);
        assert!(signature.signature_valid);
        assert!(!signature.chain_verified);
        assert_eq!(
            names(&signature.chain),
            vec![INTERMEDIATE.to_owned(), ROOT.to_owned()]
        );
        assert!(!signature.chain.anchored);
        assert!(!report.is_valid());
    }

    #[test]
    fn an_asic_e_xades_container_verifies() {
        let world = World::new();
        let report = world
            .verify_trusting_root(world.note(Format::AsicEXades))
            .expect("report");
        let signature = only(&report);
        assert_eq!(signature.claimed_signing_time, Some(day(STAMPED)));
        assert!(signature.document_intact);
        assert!(signature.signature_valid);
        assert!(signature.chain_verified);
    }

    #[test]
    fn an_asic_e_cades_container_verifies() {
        let world = World::new();
        let report = world
            .verify_trusting_root(world.note(Format::AsicECades))
            .expect("report");
        let signature = only(&report);
        assert_eq!(signature.claimed_signing_time, Some(day(STAMPED)));
        assert!(signature.document_intact);
        assert!(signature.signature_valid);
        assert!(signature.chain_verified);
    }

    #[test]
    fn an_attached_cades_file_verifies() {
        let world = World::new();
        let report = world
            .verify_trusting_root(world.note(Format::Cades))
            .expect("report");
        let signature = only(&report);
        assert_eq!(signature.claimed_signing_time, Some(day(STAMPED)));
        assert!(signature.document_intact);
        assert!(signature.signature_valid);
        assert!(signature.chain_verified);
    }

    #[test]
    fn files_without_a_signature_are_failures() {
        let world = World::new();
        assert_eq!(
            world.verify_trusting_root(NOTE.to_vec()).map(|_report| ()),
            Err(DocumentFailure::NotASignedDocument)
        );
        assert_eq!(
            world.verify_trusting_root(minimal_pdf()).map(|_report| ()),
            Err(DocumentFailure::NoSignatures)
        );
    }

    #[test]
    fn a_revoked_signer_makes_the_document_invalid() {
        let world = World::new();
        let pdf = world.pdf(Signer::Issued, true, &world.lt_material(true, false));
        let report = world.verify_trusting_root(pdf).expect("report");
        let signature = only(&report);
        assert_eq!(
            signature.revocation,
            Revocation::Revoked {
                revoked_at: day(ISSUED)
            }
        );
        assert!(signature.is_valid());
        assert!(!report.is_valid());
    }

    #[test]
    fn an_unsupported_signature_makes_the_document_invalid() {
        let report = DocumentReport {
            signatures: vec![SignatureEntry::Unsupported(UnsupportedSignature {
                signer: None,
                profile: "PDF signature subfilter",
            })],
        };
        assert!(!report.is_valid());
    }

    #[test]
    fn the_signer_identity_is_the_common_name_verbatim() {
        let key = TestKey::generate(Curve::P256);
        let person = certificate_named(
            &spec(PERSON_SERIAL, PERSON, PERSON, Vec::new()),
            &name_of(&[
                (known::COMMON_NAME, UTF8_STRING, PERSON),
                (known::SURNAME, UTF8_STRING, SURNAME),
                (known::GIVEN_NAME, UTF8_STRING, GIVEN),
                (known::SERIAL_NUMBER, PRINTABLE_STRING, IDENTIFIER),
            ]),
            &key,
            &key,
        );
        let identity = SignerIdentity::of(&OwnedCert::from_der(person).expect("parses"));
        assert_eq!(identity.name, SubjectName::CommonName(PERSON.to_owned()));
        assert_eq!(
            identity.identifier.as_ref().map(|peuin| peuin.as_str()),
            Some(IDENTIFIER)
        );

        let plain = certificate(
            &spec(PERSON_SERIAL, DIRECT_SIGNER, DIRECT_SIGNER, Vec::new()),
            &key,
            &key,
        );
        let identity = SignerIdentity::of(&OwnedCert::from_der(plain).expect("parses"));
        assert_eq!(
            identity.name,
            SubjectName::CommonName(DIRECT_SIGNER.to_owned())
        );
        assert!(identity.identifier.is_none());
    }

    #[test]
    fn without_a_common_name_the_subject_is_named_as_rfc_4514() {
        let key = TestKey::generate(Curve::P256);
        let person = certificate_named(
            &spec(PERSON_SERIAL, PERSON, PERSON, Vec::new()),
            &name_of(&[
                (known::COUNTRY_NAME, PRINTABLE_STRING, COUNTRY),
                (known::ORGANIZATION_NAME, UTF8_STRING, ORGANIZATION),
                (known::SURNAME, UTF8_STRING, SURNAME),
            ]),
            &key,
            &key,
        );
        let identity = SignerIdentity::of(&OwnedCert::from_der(person).expect("parses"));
        assert_eq!(
            identity.name,
            SubjectName::Distinguished(format!(
                "{}=#{},O={ESCAPED_ORGANIZATION},C={COUNTRY}",
                known::SURNAME,
                Hex::encode(&tlv(UTF8_STRING, SURNAME.as_bytes()))
            ))
        );
    }

    #[test]
    fn rfc_4514_writes_nul_as_an_escaped_pair() {
        let key = TestKey::generate(Curve::P256);
        let subject = certificate_named(
            &spec(PERSON_SERIAL, PERSON, PERSON, Vec::new()),
            &name_of(&[(known::ORGANIZATION_NAME, UTF8_STRING, WITH_NUL)]),
            &key,
            &key,
        );
        assert_eq!(
            SubjectName::of(&OwnedCert::from_der(subject).expect("parses")),
            SubjectName::Distinguished(format!("O={ESCAPED_WITH_NUL}"))
        );
    }
}
