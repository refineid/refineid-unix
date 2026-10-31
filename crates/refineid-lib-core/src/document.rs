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

/// The roots a verifier trusts, by SHA-256 fingerprint of the
/// certificate DER.
///
/// A path that ends in one of these is anchored; a path that ends in
/// any other self-signed certificate is not, however well it verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustAnchors<'a> {
    /// Fingerprints of the trusted root certificates.
    fingerprints: &'a [Sha256],
}

impl<'a> TrustAnchors<'a> {
    /// Trust exactly these roots.
    #[must_use]
    pub const fn new(fingerprints: &'a [Sha256]) -> Self {
        Self { fingerprints }
    }

    /// Whether a certificate with this fingerprint is a trusted root.
    #[must_use]
    pub fn contains(&self, fingerprint: Sha256) -> bool {
        self.fingerprints.contains(&fingerprint)
    }
}

/// The holder a signer certificate names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerIdentity {
    /// The given names and surname when the certificate carries them,
    /// else its common name; empty when it carries neither.
    pub name: String,
    /// The Finnish electronic identifier, on certificates issued to a
    /// person.
    pub identifier: Option<Peuin>,
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
    /// A verified answer says the signer certificate is revoked.
    Revoked,
    /// No verified answer was available.
    Unavailable,
}

/// One signature's verified facts.
#[derive(Debug, Clone)]
pub struct SignatureReport {
    /// The holder the signer certificate names.
    pub signer: SignerIdentity,
    /// The signer certificate, for revocation checks above this crate.
    pub signer_certificate: OwnedCert,
    /// The issuer the chain step was proven against, when one matched.
    pub issuer_certificate: Option<OwnedCert>,
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
    /// The earliest verified proof that the signature existed: a
    /// signature timestamp over the signature value, or a document
    /// timestamp whose byte range covers it.
    pub proof_of_existence: Option<DateTime>,
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

/// The complete verification of one document.
#[derive(Debug, Clone)]
pub struct DocumentReport {
    /// Every signature's verified facts, in document order.
    pub signatures: Vec<SignatureReport>,
    /// The generation times of the verified document timestamps, in
    /// document order.
    pub document_timestamps: Vec<DateTime>,
}

impl DocumentReport {
    /// Whether every signature is valid and none is revoked.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.signatures.is_empty()
            && self.signatures.iter().all(|signature| {
                signature.is_valid() && signature.revocation != Revocation::Revoked
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
    /// The file carries signatures of a profile this verifier does not
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
