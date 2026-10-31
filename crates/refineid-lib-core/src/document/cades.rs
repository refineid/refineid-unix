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

//! Verifying one CMS `SignedData` in the `CAdES` profile.
//!
//! [`CadesSignature::parse`] reads the structure once and selects the
//! signer certificate; [`CadesSignature::verify`] judges it against
//! the signed content and reports the facts separately: whether the
//! content is the one signed, whether the signature and its
//! certificate binding hold, and which signature timestamps verify.
//! Every digest follows `SignerInfo.digestAlgorithm`; the signature
//! follows `SignerInfo.signatureAlgorithm`, dispatched on the signer
//! key type.
//!
//! # Conformance
//!
//! - RFC 5652: `SignedData`, `SignerInfo`, and the signature over the
//!   DER `SET OF` signed attributes (section 5.4). One `SignerInfo`
//!   per structure, as `ETSI EN 319 142-1` clause 4.1 a) requires of
//!   a PDF signature; [`crate::cms`] refuses any other count.
//! - `ETSI EN 319 122-1` clause 5.1: `content-type` is `id-data` and
//!   `message-digest` equals the digest of the signed content.
//! - `ETSI EN 319 122-1` clause 5.2.2 and RFC 5035: the ESS
//!   `signing-certificate` or `signing-certificate-v2` attribute
//!   binds the signer certificate. `ETSI EN 319 142-2` clause 4.2.3 c)
//!   ignores that reference in the plain CMS profile, so the caller
//!   says whether it is required ([`EssBinding`]).
//! - `ETSI EN 319 122-1` clause 5.3: each `signature-time-stamp`
//!   token's `messageImprint` is computed over the octets of
//!   `SignerInfo.signature`.
//! - `ETSI EN 319 122-1` clause 5.5.3 and RFC 5126 sec.6.4.1:
//!   `archive-time-stamp-v3` and `archive-time-stamp` (v2) attributes
//!   are counted, not verified.
//! - `ETSI EN 319 122-2` level LT: the validation material travels in
//!   `SignedData.certificates` and `SignedData.crls`, OCSP responses
//!   as `id-ri-ocsp-response` (RFC 5940); that is what
//!   [`crate::sign::cades::signed_data`] writes and
//!   [`CadesSignature::embedded_material`] reads back.

use crate::ber::BerTlvAny;
use crate::cms::{CmsAttribute, RevocationInfoChoice, SignedData};
use crate::document::TimestampCheck;
use crate::oid::{Oid, known};
use crate::sign::cades::DigestAlgorithm;
use crate::sign::timestamp::{
    TimestampError, claimed_generation_time, select_signer_certificate,
    verify_signing_certificate_attribute, verify_token,
};
use crate::sign::validation::ValidationMaterial;
use crate::x509::{Certificate, DateTime, EcCurve, OwnedCert, PublicKeyAlgorithm};
use sha2::Digest as _;

/// Why a structure is not a `CAdES` signature this reader verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CadesReadError {
    /// The bytes are not a CMS `SignedData` with exactly one
    /// `SignerInfo`.
    NotSignedData,
    /// The `SignerInfo` carries no signed attributes, which
    /// `ETSI EN 319 122-1` clause 5.1 makes mandatory.
    NoSignedAttributes,
    /// `SignerInfo.digestAlgorithm` is neither SHA-256 nor SHA-384.
    UnsupportedDigest,
    /// `SignerInfo.signatureAlgorithm` is not RSA PKCS#1 v1.5 or
    /// ECDSA over P-256 or P-384 with SHA-256 or SHA-384, or does not
    /// fit the signer key.
    UnsupportedSignatureAlgorithm,
    /// No embedded certificate matches the `SignerIdentifier`.
    SignerCertificateMissing,
    /// More than one distinct embedded certificate matches the
    /// `SignerIdentifier`.
    SignerCertificateAmbiguous,
}

impl core::fmt::Display for CadesReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotSignedData => "not a CMS SignedData with one signer",
            Self::NoSignedAttributes => "the signer has no signed attributes",
            Self::UnsupportedDigest => "unsupported digest algorithm",
            Self::UnsupportedSignatureAlgorithm => "unsupported signature algorithm",
            Self::SignerCertificateMissing => "the signer certificate is not embedded",
            Self::SignerCertificateAmbiguous => "several embedded certificates match the signer",
        })
    }
}

impl core::error::Error for CadesReadError {}

/// The digest of content signed outside the structure, computed here
/// under a named algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDigest {
    /// The algorithm the digest was computed under.
    algorithm: DigestAlgorithm,
    /// The digest.
    value: Vec<u8>,
}

impl ContentDigest {
    /// The digest of `spans` concatenated in order: the byte ranges of
    /// a PDF signature, or one container entry.
    #[must_use]
    pub fn of_spans(algorithm: DigestAlgorithm, spans: &[&[u8]]) -> Self {
        let value = match algorithm {
            DigestAlgorithm::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                for span in spans {
                    hasher.update(span);
                }
                hasher.finalize().to_vec()
            }
            DigestAlgorithm::Sha384 => {
                let mut hasher = sha2::Sha384::new();
                for span in spans {
                    hasher.update(span);
                }
                hasher.finalize().to_vec()
            }
        };
        Self { algorithm, value }
    }

    /// The algorithm the digest was computed under.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }
}

/// Where the signed content is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content<'a> {
    /// `eContent` is inside the structure and is digested under
    /// [`CadesSignature::digest_algorithm`].
    Attached,
    /// The content is outside the structure; the caller digested it
    /// under [`CadesSignature::digest_algorithm`].
    Detached {
        /// The digest of the external content.
        digest: &'a ContentDigest,
    },
}

/// Whether the ESS signing-certificate attribute must bind the signer
/// certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EssBinding {
    /// `CAdES` and `PAdES` baseline: the attribute must be present
    /// and hash the signer certificate.
    Required,
    /// The plain CMS profile of `ETSI EN 319 142-2` clause 4.2.3 c):
    /// the attribute is ignored.
    NotRequired,
}

/// The facts [`CadesSignature::verify`] establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CadesVerdict {
    /// The `message-digest` attribute equals the digest of the
    /// content.
    pub document_intact: bool,
    /// The signature verifies over the signed attributes under the
    /// signer key, `content-type` is `id-data`, and, when required,
    /// the ESS attribute binds the signer certificate.
    pub signature_valid: bool,
    /// Every `signature-time-stamp` token, checked under its embedded
    /// TSA certificate against this signature value, in encoded order.
    pub signature_timestamps: Vec<TimestampCheck>,
    /// How many `archive-time-stamp-v3` and `archive-time-stamp` (v2)
    /// tokens are present; they are not verified.
    pub archive_timestamps_present: usize,
}

/// One parsed `CAdES` signature: the CMS DER, its signer certificate
/// and the material it embeds.
#[derive(Debug, Clone)]
pub struct CadesSignature {
    /// The CMS `ContentInfo` or `SignedData` DER.
    cms: Vec<u8>,
    /// `SignerInfo.digestAlgorithm`.
    digest_algorithm: DigestAlgorithm,
    /// The embedded certificate the `SignerIdentifier` selects.
    signer_certificate: OwnedCert,
    /// Every distinct parseable embedded certificate.
    embedded_certificates: Vec<Vec<u8>>,
    /// Chain certificates and revocation answers from the structure.
    embedded_material: ValidationMaterial,
    /// The `signing-time` signed attribute, when present and readable.
    signing_time: Option<DateTime>,
}

impl CadesSignature {
    /// Parse `cms` and select its signer certificate.
    ///
    /// # Errors
    /// [`CadesReadError`] when the structure is not a one-signer
    /// `SignedData` with signed attributes, its algorithms are outside
    /// SHA-256 / SHA-384 with RSA PKCS#1 v1.5 or ECDSA P-256 / P-384,
    /// or the signer certificate is not embedded exactly once.
    pub fn parse(cms: Vec<u8>) -> Result<Self, CadesReadError> {
        let (digest_algorithm, signer_certificate, embedded_certificates, material, signing_time) = {
            let signed =
                SignedData::parse(&cms).map_err(|_ignored| CadesReadError::NotSignedData)?;
            if signed.signer.signed_data_to_verify.is_none() {
                return Err(CadesReadError::NoSignedAttributes);
            }
            let digest_algorithm = DigestAlgorithm::from_oid(signed.signer.digest_algorithm_oid)
                .ok_or(CadesReadError::UnsupportedDigest)?;
            let signer = select_signer_certificate(&signed).map_err(|error| match error {
                TimestampError::AmbiguousTsaCertificate => {
                    CadesReadError::SignerCertificateAmbiguous
                }
                _ => CadesReadError::SignerCertificateMissing,
            })?;
            if !signature_fits_key(
                signed.signer.signature_algorithm_oid,
                signer.spki.algorithm(),
            ) {
                return Err(CadesReadError::UnsupportedSignatureAlgorithm);
            }
            let signer_certificate = OwnedCert::from_der(signer.raw_der)
                .map_err(|_ignored| CadesReadError::SignerCertificateMissing)?;
            let embedded = embedded_certificates(&signed);
            let material = embedded_material(&signed, &embedded, signer.raw_der);
            let signing_time =
                attribute_values(&signed.signer.signed_attributes, known::SIGNING_TIME)
                    .first()
                    .and_then(|value| asn1_time(value));
            (
                digest_algorithm,
                signer_certificate,
                embedded,
                material,
                signing_time,
            )
        };
        Ok(Self {
            cms,
            digest_algorithm,
            signer_certificate,
            embedded_certificates,
            embedded_material: material,
            signing_time,
        })
    }

    /// `SignerInfo.digestAlgorithm`, under which the content and the
    /// signed attributes are digested.
    #[must_use]
    pub const fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    /// The embedded certificate the `SignerIdentifier` selects.
    #[must_use]
    pub const fn signer_certificate(&self) -> &OwnedCert {
        &self.signer_certificate
    }

    /// Every distinct parseable certificate in
    /// `SignedData.certificates`, the signer's included, for chain
    /// building.
    #[must_use]
    pub fn embedded_certificates(&self) -> &[Vec<u8>] {
        &self.embedded_certificates
    }

    /// The level-LT material the structure carries: the embedded
    /// certificates other than the signer's, the CRLs and the
    /// `id-ri-ocsp-response` entries of `SignedData.crls`.
    #[must_use]
    pub fn embedded_material(&self) -> ValidationMaterial {
        self.embedded_material.clone()
    }

    /// The `signing-time` signed attribute (RFC 5652 sec.11.3), when
    /// present and readable.
    #[must_use]
    pub const fn signing_time(&self) -> Option<DateTime> {
        self.signing_time
    }

    /// Judge the signature against `content`.
    #[must_use]
    pub fn verify(&self, content: Content<'_>, ess: EssBinding) -> CadesVerdict {
        let Ok(signed) = SignedData::parse(&self.cms) else {
            return CadesVerdict::nothing_verified();
        };
        let signer = self.signer_certificate.view();
        let content_digest = match content {
            Content::Attached => signed
                .econtent_der
                .map(|econtent| self.digest_algorithm.digest(econtent)),
            Content::Detached { digest } => {
                (digest.algorithm == self.digest_algorithm).then(|| digest.value.clone())
            }
        };
        let document_intact = content_digest
            .is_some_and(|digest| signed.signer.message_digest == Some(digest.as_slice()));
        let ess_binds = match ess {
            EssBinding::Required => verify_signing_certificate_attribute(&signed, &signer).is_ok(),
            EssBinding::NotRequired => true,
        };
        let signature_valid = signed.econtent_type_oid == known::DATA
            && ess_binds
            && signed.verify_signer_signature(signer.spki.as_der()).is_ok();
        CadesVerdict {
            document_intact,
            signature_valid,
            signature_timestamps: signature_timestamps(&signed),
            archive_timestamps_present: [
                known::ARCHIVE_TIME_STAMP_V2,
                known::ARCHIVE_TIME_STAMP_V3,
            ]
            .into_iter()
            .map(|oid| attribute_values(&signed.signer.unsigned_attributes, oid).len())
            .sum(),
        }
    }
}

impl CadesVerdict {
    /// The verdict when nothing could be checked.
    const fn nothing_verified() -> Self {
        Self {
            document_intact: false,
            signature_valid: false,
            signature_timestamps: Vec::new(),
            archive_timestamps_present: 0,
        }
    }
}

/// Whether `signature_algorithm` is a scheme this reader verifies for
/// a signer key of type `key`. The bare key OIDs take their digest from
/// `SignerInfo.digestAlgorithm` ([`crate::cms`] dispatch).
fn signature_fits_key(signature_algorithm: Oid<'_>, key: PublicKeyAlgorithm) -> bool {
    match key {
        PublicKeyAlgorithm::Rsa { .. } => [
            known::SHA256_WITH_RSA,
            known::SHA384_WITH_RSA,
            known::RSA_ENCRYPTION,
        ]
        .contains(&signature_algorithm),
        PublicKeyAlgorithm::Ec(EcCurve::Secp256r1 | EcCurve::Secp384r1) => [
            known::ECDSA_WITH_SHA256,
            known::ECDSA_WITH_SHA384,
            known::EC_PUBLIC_KEY,
        ]
        .contains(&signature_algorithm),
        PublicKeyAlgorithm::Ec(
            EcCurve::BrainpoolP256r1 | EcCurve::BrainpoolP384r1 | EcCurve::Other,
        )
        | PublicKeyAlgorithm::EcExplicit { .. }
        | PublicKeyAlgorithm::Other => false,
    }
}

/// Every distinct parseable certificate in `SignedData.certificates`.
fn embedded_certificates(signed: &SignedData<'_>) -> Vec<Vec<u8>> {
    let mut certificates: Vec<Vec<u8>> = Vec::new();
    for der in &signed.certificates_der {
        if Certificate::from_der(der).is_ok()
            && certificates.iter().all(|seen| seen.as_slice() != *der)
        {
            certificates.push(der.to_vec());
        }
    }
    certificates
}

/// The chain certificates other than `signer_der`, and the CRLs and
/// OCSP responses of `SignedData.crls`. Other revocation formats are
/// left out.
fn embedded_material(
    signed: &SignedData<'_>,
    certificates: &[Vec<u8>],
    signer_der: &[u8],
) -> ValidationMaterial {
    let mut material = ValidationMaterial {
        certificates: certificates
            .iter()
            .filter(|der| der.as_slice() != signer_der)
            .cloned()
            .collect(),
        ocsp_responses: Vec::new(),
        crls: Vec::new(),
    };
    for choice in &signed.revocation_info {
        match *choice {
            RevocationInfoChoice::Crl(der) => material.crls.push(der.to_vec()),
            RevocationInfoChoice::Other { format, info_der } => {
                if format == known::OCSP_RESPONSE_REVOCATION_INFO {
                    material.ocsp_responses.push(info_der.to_vec());
                }
            }
        }
    }
    material
}

/// The `signature-time-stamp` tokens, each checked with an imprint over
/// the `SignerInfo.signature` octets.
fn signature_timestamps(signed: &SignedData<'_>) -> Vec<TimestampCheck> {
    attribute_values(
        &signed.signer.unsigned_attributes,
        known::SIGNATURE_TIME_STAMP_TOKEN,
    )
    .iter()
    .map(|token| {
        verify_token(token, |algorithm| algorithm.digest(signed.signer.signature)).map_or_else(
            |_ignored| TimestampCheck::Unverified {
                claimed_at: claimed_generation_time(token),
            },
            TimestampCheck::Verified,
        )
    })
    .collect()
}

/// A `Time` value (RFC 5652 sec.11.3: `UTCTime` or `GeneralizedTime`)
/// as DER.
fn asn1_time(value_der: &[u8]) -> Option<DateTime> {
    use spki::der::Decode as _;
    use spki::der::asn1::{GeneralizedTime, UtcTime};
    UtcTime::from_der(value_der)
        .map(|time| time.to_date_time())
        .or_else(|_ignored| GeneralizedTime::from_der(value_der).map(|time| time.to_date_time()))
        .ok()
}

/// The complete DER of every value of every attribute of type `oid`.
/// A value set that does not parse to its end counts its unreadable
/// tail as one value, so it is reported as present and fails to verify.
fn attribute_values<'a>(attributes: &[CmsAttribute<'a>], oid: Oid<'_>) -> Vec<&'a [u8]> {
    let mut values = Vec::new();
    for attribute in attributes.iter().filter(|attribute| attribute.oid == oid) {
        let mut rest = attribute.values_der;
        while !rest.is_empty() {
            let Ok(value) = BerTlvAny::parse(rest) else {
                values.push(rest);
                break;
            };
            let (value_der, tail) = rest.split_at(value.size.min(rest.len()));
            values.push(value_der);
            rest = tail;
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::{
        CadesReadError, CadesSignature, Content, ContentDigest, EssBinding, embedded_material,
    };
    use crate::ber::tlv;
    use crate::crypto::digest::Sha256;
    use crate::document::TimestampCheck;
    use crate::document::trust::testkit::{
        CertificateSpec, CmsParts, Curve, OBJECT_IDENTIFIER, OCTET_STRING, OcspSpec, SEQUENCE,
        TestKey, attribute, attribute_set, ca_extensions, certificate, cms, crl, day,
        ocsp_response, timestamp_token, timestamping_extensions,
    };
    use crate::document::trust::{MaterialPool, judge};
    use crate::document::{Revocation, TrustAnchors};
    use crate::oid::known;
    use crate::sign::cades::{
        DigestAlgorithm, Encapsulation, SignerParameters, SigningTime, signed_attributes,
        signed_data,
    };
    use crate::sign::validation::ValidationMaterial;
    use crate::x509::{Certificate, DateTime, OwnedCert};

    /// Root common name.
    const ROOT: &str = "Synthetic Root CA";
    /// Signer common name.
    const SIGNER: &str = "Synthetic Signer";
    /// TSA common name.
    const TSA: &str = "Synthetic Time Stamping Unit";
    /// Root serial.
    const ROOT_SERIAL: u8 = 1;
    /// Signer serial.
    const SIGNER_SERIAL: u8 = 2;
    /// TSA serial.
    const TSA_SERIAL: u8 = 3;
    /// Day every certificate starts.
    const ISSUED: u8 = 1;
    /// Day revocation answers are produced.
    const ANSWERED: u8 = 9;
    /// Day of signing and of the timestamp.
    const SIGNED: u8 = 10;
    /// Day every certificate ends.
    const ENDS: u8 = 28;
    /// The signing time the writer asserts.
    const SIGNING_TIME: SigningTime = SigningTime {
        year: 2026,
        month: 6,
        day: 10,
        hour: 12,
        minute: 0,
        second: 0,
    };
    /// [`SIGNING_TIME`] as the reader returns it.
    fn signing_time() -> DateTime {
        DateTime::new(
            SIGNING_TIME.year,
            SIGNING_TIME.month,
            SIGNING_TIME.day,
            SIGNING_TIME.hour,
            SIGNING_TIME.minute,
            SIGNING_TIME.second,
        )
        .expect("signing time")
    }
    /// The signed document.
    const DOCUMENT: &[u8] = b"Synthetic declaration, signed for the verifier tests";
    /// Another document.
    const OTHER_DOCUMENT: &[u8] = b"A different declaration";
    /// Keys and certificates of one test world.
    struct World {
        /// Root key.
        root_key: TestKey,
        /// Self-signed root.
        root: Vec<u8>,
        /// Signer key.
        signer_key: TestKey,
        /// Signer certificate, issued by the root.
        signer: Vec<u8>,
        /// TSA key.
        tsa_key: TestKey,
        /// TSA certificate, issued by the root.
        tsa: Vec<u8>,
    }

    impl World {
        /// A world whose signer key is on `curve`.
        fn new(curve: Curve) -> Self {
            let root_key = TestKey::generate(Curve::P384);
            let signer_key = TestKey::generate(curve);
            let tsa_key = TestKey::generate(Curve::P256);
            let root = certificate(
                &spec(ROOT_SERIAL, ROOT, ca_extensions()),
                &root_key,
                &root_key,
            );
            let signer = certificate(
                &spec(SIGNER_SERIAL, SIGNER, Vec::new()),
                &signer_key,
                &root_key,
            );
            let tsa = certificate(
                &spec(TSA_SERIAL, TSA, timestamping_extensions()),
                &tsa_key,
                &root_key,
            );
            Self {
                root_key,
                root,
                signer_key,
                signer,
                tsa_key,
                tsa,
            }
        }

        /// A `CAdES` signature the repository's writer produces over
        /// `DOCUMENT`.
        fn written(&self, written: &Written) -> Vec<u8> {
            let certificate = Certificate::from_der(&self.signer).expect("signer parses");
            let parameters = SignerParameters {
                certificate: &certificate,
                digest_algorithm: self.signer_key.digest_algorithm(),
                signature_algorithm: self.signer_key.cades_algorithm(),
                signing_time: Some(SIGNING_TIME),
            };
            let digest = parameters.digest_algorithm.digest(DOCUMENT);
            let attributes = signed_attributes(&parameters, &digest);
            let mut signature = self.signer_key.sign(attributes.as_bytes());
            if written.flip_signature
                && let Some(last) = signature.last_mut()
            {
                *last ^= 1;
            }
            let mut timestamps = Vec::new();
            if let Some(stamp) = written.timestamp {
                let imprint = DigestAlgorithm::Sha256.digest(&signature);
                let mut token = self.timestamp_token(&imprint);
                if stamp == Stamp::Corrupt
                    && let Some(last) = token.last_mut()
                {
                    *last ^= 1;
                }
                timestamps.push(token);
            }
            signed_data(
                &parameters,
                &attributes,
                &signature,
                written.encapsulation,
                DOCUMENT,
                &written.material,
                &timestamps,
            )
        }

        /// An RFC 3161 token over `imprint` (SHA-256) from the TSA.
        fn timestamp_token(&self, imprint: &[u8]) -> Vec<u8> {
            timestamp_token(&self.tsa, &self.tsa_key, imprint, day(SIGNED))
        }
    }

    /// A certificate valid from `ISSUED` to `ENDS`, issued by the root.
    fn spec(serial: u8, subject: &str, extensions: Vec<Vec<u8>>) -> CertificateSpec<'_> {
        CertificateSpec {
            serial,
            subject,
            issuer: ROOT,
            not_before: day(ISSUED),
            not_after: day(ENDS),
            extensions,
        }
    }

    /// How the writer is driven.
    struct Written {
        /// Attached or detached.
        encapsulation: Encapsulation,
        /// Material to embed.
        material: ValidationMaterial,
        /// Flip a bit of the signature value.
        flip_signature: bool,
        /// Add a signature timestamp.
        timestamp: Option<Stamp>,
    }

    /// A signature timestamp, intact or not.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Stamp {
        /// Verifies.
        Intact,
        /// Its signature has a flipped bit.
        Corrupt,
    }

    impl Written {
        /// Plain level B.
        fn plain(encapsulation: Encapsulation) -> Self {
            Self {
                encapsulation,
                material: ValidationMaterial::default(),
                flip_signature: false,
                timestamp: None,
            }
        }
    }

    /// A `CAdES` structure over `DOCUMENT` signed by the world's signer,
    /// with only `content-type` and `message-digest` signed.
    fn without_ess(world: &World, digest_algorithm: Vec<u8>) -> Vec<u8> {
        without_ess_with_unsigned(world, digest_algorithm, Vec::new())
    }

    /// [`without_ess`] carrying `unsigned_attributes`.
    fn without_ess_with_unsigned(
        world: &World,
        digest_algorithm: Vec<u8>,
        unsigned_attributes: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let attributes = attribute_set(&[
            attribute(
                known::CONTENT_TYPE,
                &tlv(OBJECT_IDENTIFIER, known::DATA.as_bytes()),
            ),
            attribute(
                known::MESSAGE_DIGEST,
                &tlv(OCTET_STRING, Sha256::of(DOCUMENT).as_bytes()),
            ),
        ]);
        cms(&CmsParts {
            econtent_type: known::DATA,
            econtent: Some(DOCUMENT),
            digest_algorithm,
            signed_attributes: attributes,
            key: &world.signer_key,
            signer: &world.signer,
            certificates: vec![world.signer.clone()],
            unsigned_attributes,
        })
    }

    /// The digest of `content` under the signature's algorithm.
    fn detached_digest(signature: &CadesSignature, content: &[u8]) -> ContentDigest {
        ContentDigest::of_spans(signature.digest_algorithm(), &[content])
    }

    #[test]
    fn an_attached_signature_from_the_writer_verifies() {
        let world = World::new(Curve::P256);
        let signature =
            CadesSignature::parse(world.written(&Written::plain(Encapsulation::Attached)))
                .expect("parses");
        assert_eq!(signature.digest_algorithm(), DigestAlgorithm::Sha256);
        assert_eq!(
            signature.signer_certificate().as_der(),
            world.signer.as_slice()
        );
        assert_eq!(signature.signing_time(), Some(signing_time()));
        let verdict = signature.verify(Content::Attached, EssBinding::Required);
        assert!(verdict.document_intact);
        assert!(verdict.signature_valid);
        assert!(verdict.signature_timestamps.is_empty());
        assert_eq!(verdict.archive_timestamps_present, 0);
    }

    #[test]
    fn a_detached_sha384_signature_verifies_against_the_content_digest() {
        let world = World::new(Curve::P384);
        let signature =
            CadesSignature::parse(world.written(&Written::plain(Encapsulation::Detached)))
                .expect("parses");
        assert_eq!(signature.digest_algorithm(), DigestAlgorithm::Sha384);
        let digest = ContentDigest::of_spans(
            DigestAlgorithm::Sha384,
            &[
                DOCUMENT.split_at(DOCUMENT.len() / 2).0,
                DOCUMENT.split_at(DOCUMENT.len() / 2).1,
            ],
        );
        let verdict = signature.verify(Content::Detached { digest: &digest }, EssBinding::Required);
        assert!(verdict.document_intact);
        assert!(verdict.signature_valid);

        // No eContent to digest.
        let verdict = signature.verify(Content::Attached, EssBinding::Required);
        assert!(!verdict.document_intact);
        assert!(verdict.signature_valid);

        // A digest under another algorithm is not this content's digest.
        let sha256 = ContentDigest::of_spans(DigestAlgorithm::Sha256, &[DOCUMENT]);
        let verdict = signature.verify(Content::Detached { digest: &sha256 }, EssBinding::Required);
        assert!(!verdict.document_intact);
    }

    #[test]
    fn a_flipped_signature_bit_invalidates_the_signature_only() {
        let world = World::new(Curve::P256);
        let mut written = Written::plain(Encapsulation::Attached);
        written.flip_signature = true;
        let signature = CadesSignature::parse(world.written(&written)).expect("parses");
        let verdict = signature.verify(Content::Attached, EssBinding::Required);
        assert!(verdict.document_intact);
        assert!(!verdict.signature_valid);
    }

    #[test]
    fn other_content_is_not_intact() {
        let world = World::new(Curve::P256);
        let signature =
            CadesSignature::parse(world.written(&Written::plain(Encapsulation::Detached)))
                .expect("parses");
        let digest = detached_digest(&signature, OTHER_DOCUMENT);
        let verdict = signature.verify(Content::Detached { digest: &digest }, EssBinding::Required);
        assert!(!verdict.document_intact);
        assert!(verdict.signature_valid);
    }

    #[test]
    fn sha1_is_refused() {
        let world = World::new(Curve::P256);
        let sha1 = tlv(SEQUENCE, tlv(OBJECT_IDENTIFIER, known::SHA1.as_bytes()));
        assert_eq!(
            CadesSignature::parse(without_ess(&world, sha1)).map(|_parsed| ()),
            Err(CadesReadError::UnsupportedDigest)
        );
    }

    #[test]
    fn the_ess_binding_is_required_only_when_asked() {
        let world = World::new(Curve::P256);
        let signature = CadesSignature::parse(without_ess(
            &world,
            DigestAlgorithm::Sha256.algorithm_identifier(),
        ))
        .expect("parses");
        assert_eq!(signature.signing_time(), None);
        let required = signature.verify(Content::Attached, EssBinding::Required);
        assert!(required.document_intact);
        assert!(!required.signature_valid);
        let ignored = signature.verify(Content::Attached, EssBinding::NotRequired);
        assert!(ignored.document_intact);
        assert!(ignored.signature_valid);
    }

    #[test]
    fn a_signer_certificate_not_embedded_is_refused() {
        let world = World::new(Curve::P256);
        let attributes = attribute_set(&[
            attribute(
                known::CONTENT_TYPE,
                &tlv(OBJECT_IDENTIFIER, known::DATA.as_bytes()),
            ),
            attribute(
                known::MESSAGE_DIGEST,
                &tlv(OCTET_STRING, Sha256::of(DOCUMENT).as_bytes()),
            ),
        ]);
        let bare = cms(&CmsParts {
            econtent_type: known::DATA,
            econtent: Some(DOCUMENT),
            digest_algorithm: DigestAlgorithm::Sha256.algorithm_identifier(),
            signed_attributes: attributes,
            key: &world.signer_key,
            signer: &world.signer,
            certificates: vec![world.root.clone()],
            unsigned_attributes: Vec::new(),
        });
        assert_eq!(
            CadesSignature::parse(bare).map(|_parsed| ()),
            Err(CadesReadError::SignerCertificateMissing)
        );
    }

    #[test]
    fn a_signature_timestamp_is_verified_over_the_signature_value() {
        let world = World::new(Curve::P256);
        let mut written = Written::plain(Encapsulation::Attached);
        written.timestamp = Some(Stamp::Intact);
        let signature = CadesSignature::parse(world.written(&written)).expect("parses");
        let verdict = signature.verify(Content::Attached, EssBinding::Required);
        assert!(verdict.signature_valid);
        let [TimestampCheck::Verified(token)] = verdict.signature_timestamps.as_slice() else {
            panic!("one verified token");
        };
        assert_eq!(token.generated_at, day(SIGNED));

        written.timestamp = Some(Stamp::Corrupt);
        let signature = CadesSignature::parse(world.written(&written)).expect("parses");
        let verdict = signature.verify(Content::Attached, EssBinding::Required);
        assert!(verdict.signature_valid);
        assert!(matches!(
            verdict.signature_timestamps.as_slice(),
            [TimestampCheck::Unverified { .. }]
        ));
    }

    #[test]
    fn embedded_material_reads_back_what_the_writer_embeds_and_judges_offline() {
        let world = World::new(Curve::P256);
        let root = OwnedCert::from_der(&world.root).expect("root parses");
        let answer = ocsp_response(&OcspSpec {
            responder_key: &world.root_key,
            responder: ROOT,
            issuer: &root,
            serial: SIGNER_SERIAL,
            revoked: None,
            produced_at: day(ANSWERED),
            this_update: day(ANSWERED),
            next_update: Some(day(ENDS)),
            embedded: Vec::new(),
        });
        let list = crl(
            ROOT,
            &world.root_key,
            day(ANSWERED),
            Some(day(ENDS)),
            &[],
            day(ISSUED),
        );
        let material = ValidationMaterial {
            certificates: vec![world.root.clone()],
            ocsp_responses: vec![answer],
            crls: vec![list],
        };
        let mut written = Written::plain(Encapsulation::Detached);
        written.material = material.clone();
        let signature = CadesSignature::parse(world.written(&written)).expect("parses");
        assert_eq!(signature.embedded_material(), material);
        assert_eq!(signature.embedded_certificates().len(), 2);

        let mut pool = MaterialPool::new();
        pool.add_material(&signature.embedded_material());
        let anchors = [world.root.as_slice()];
        let at: DateTime = day(SIGNED);
        let verdict = judge(
            signature.signer_certificate(),
            &pool,
            TrustAnchors::new(&anchors),
            at,
        );
        assert!(verdict.anchored);
        assert_eq!(
            verdict.revocation,
            Revocation::Good {
                checked_at: day(ANSWERED)
            }
        );
    }

    #[test]
    fn a_plain_signature_embeds_no_material() {
        let world = World::new(Curve::P256);
        let der = world.written(&Written::plain(Encapsulation::Attached));
        let signature = CadesSignature::parse(der.clone()).expect("parses");
        assert_eq!(signature.embedded_material(), ValidationMaterial::default());
        let signed = crate::cms::SignedData::parse(&der).expect("parses");
        let certificates = vec![world.signer.clone()];
        assert_eq!(
            embedded_material(&signed, &certificates, &world.signer),
            ValidationMaterial::default()
        );
    }

    #[test]
    fn archive_timestamps_of_both_versions_are_counted() {
        let world = World::new(Curve::P256);
        let token = world.timestamp_token(Sha256::of(DOCUMENT).as_bytes());
        let other_token = world.timestamp_token(Sha256::of(OTHER_DOCUMENT).as_bytes());
        let archive = |unsigned: Vec<Vec<u8>>| {
            CadesSignature::parse(without_ess_with_unsigned(
                &world,
                DigestAlgorithm::Sha256.algorithm_identifier(),
                unsigned,
            ))
            .expect("parses")
            .verify(Content::Attached, EssBinding::NotRequired)
            .archive_timestamps_present
        };
        let v2 = attribute(known::ARCHIVE_TIME_STAMP_V2, &token);
        let v3 = attribute(known::ARCHIVE_TIME_STAMP_V3, &token);
        let v3_twice = attribute(
            known::ARCHIVE_TIME_STAMP_V3,
            &[token.clone(), token].concat(),
        );
        assert_eq!(archive(Vec::new()), 0);
        assert_eq!(archive(vec![v2.clone()]), 1);
        assert_eq!(archive(vec![v3]), 1);
        assert_eq!(archive(vec![v2.clone(), v3_twice]), 3);
        let v2_again = attribute(known::ARCHIVE_TIME_STAMP_V2, &other_token);
        assert_eq!(archive(vec![v2, v2_again]), 2);
    }
}
