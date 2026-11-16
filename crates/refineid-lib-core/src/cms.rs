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

//! Structural CMS `SignedData` and ICAO 9303 `EF.SOD` parser (RFC 5652).
//!
//! Surface:
//!
//! - [`OwnedSignedData`] and `SignedData::parse` -- accept the bare
//!   `SignedData` SEQUENCE, the outer `ContentInfo`-wrapped form, or
//!   ICAO 9303's `[APPLICATION 23] IMPLICIT` form (the byte stream
//!   read from `EF.SOD` on an eMRTD).
//! - [`SignedData`] exposes the encapsulated content type OID, the
//!   attached `eContent` bytes (`LDSSecurityObject` DER for an eMRTD
//!   SOD), and the embedded X.509 certificates while validating the
//!   surrounding CMS and single-signer `SignerInfo` grammar (covering
//!   RSA PKCS#1 v1.5, `id-RSASSA-PSS`, and ECDSA `AlgorithmIdentifier`
//!   encodings).
//! - [`LdsSecurityObject`] decodes the ICAO Doc 9303-10 `EF.SOD`
//!   data-group hash inventory.
//!
//! Not in scope: countersignatures, multiple `SignerInfo` entries, and
//! non-X.509 `CertificateChoices` variants.

use crate::ber::{BerTag, BerTlv, BerTlvAny, BerTlvIter, Integer, OctetString, Oid, Sequence, Set};
use crate::oid::known;

/// `[APPLICATION 23]` IMPLICIT (tag `0x77`) -- `EF.SOD` outer wrapper
/// per ICAO Doc 9303-10 sec. 4.6.2.
#[derive(Debug, Clone, Copy)]
struct EfSodWrapper;
impl BerTag for EfSodWrapper {
    const TAG: u16 = 0x77;
}

/// `[0] EXPLICIT` / `[0] IMPLICIT` constructed context-specific tag
/// (`0xA0`) used in `ContentInfo.content`, `SignedData.certificates`,
/// and `SignerInfo.signedAttrs` (RFC 5652 sec. 3 / sec. 5).
#[derive(Debug, Clone, Copy)]
struct Asn1ContentExplicit0;
impl BerTag for Asn1ContentExplicit0 {
    const TAG: u16 = 0xA0;
}

/// `[1] IMPLICIT` constructed context-specific tag (`0xA1`) used in
/// `SignedData.crls` and `SignerInfo.unsignedAttrs`.
#[derive(Debug, Clone, Copy)]
struct Asn1ContentImplicit1;
impl BerTag for Asn1ContentImplicit1 {
    const TAG: u16 = 0xA1;
}

/// `SignerIdentifier.subjectKeyIdentifier [0] IMPLICIT OCTET STRING`
/// (tag `0x80`).
#[derive(Debug, Clone, Copy)]
struct SignerSubjectKeyIdentifier;
impl BerTag for SignerSubjectKeyIdentifier {
    const TAG: u16 = 0x80;
}

// ----- Hash algorithm OID mapping -----

/// SHA-2 digest algorithm recorded in `LDSSecurityObject`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (OID `2.16.840.1.101.3.4.2.1`).
    Sha256,
    /// SHA-384 (OID `2.16.840.1.101.3.4.2.2`).
    Sha384,
    /// SHA-512 (OID `2.16.840.1.101.3.4.2.3`).
    Sha512,
}

impl HashAlgorithm {
    /// Decode an OID body into the typed enum. Returns `None` for any
    /// OID outside SHA-256, SHA-384, and SHA-512.
    #[must_use]
    #[inline]
    pub fn from_oid<B: AsRef<[u8]>>(oid: B) -> Option<Self> {
        let oid = oid.as_ref();
        match oid {
            v if v == known::SHA256.as_bytes() => Some(Self::Sha256),
            v if v == known::SHA384.as_bytes() => Some(Self::Sha384),
            v if v == known::SHA512.as_bytes() => Some(Self::Sha512),
            _ => None,
        }
    }
}

// ----- SignedData public surface -----

/// Error returned from the structural CMS / `EF.SOD` parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    variant_size_differences,
    reason = "`UnexpectedStructure(&'static str)` carries a 16 B fat pointer while `Ber(BerError)` and `UnsupportedDigestAlgorithm` are smaller; keeping a compile-time &'static str shape diagnostic matches X509Error and EmrtdError without heap indirection."
)]
pub enum CmsError {
    /// BER / TLV decode failure during structural parse.
    Ber(crate::ber::BerError),
    /// Structural shape mismatch (wrong tag, wrong nesting, or missing
    /// required field).
    UnexpectedStructure(&'static str),
    /// `LDSSecurityObject.hashAlgorithm` OID is not one of the
    /// supported SHA-2 variants ([`HashAlgorithm`]).
    UnsupportedDigestAlgorithm,
}

impl From<crate::ber::BerError> for CmsError {
    #[inline]
    fn from(e: crate::ber::BerError) -> Self {
        Self::Ber(e)
    }
}

impl core::fmt::Display for CmsError {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ber(e) => write!(f, "CMS BER: {e}"),
            Self::UnexpectedStructure(s) => write!(f, "CMS: {s}"),
            Self::UnsupportedDigestAlgorithm => write!(f, "CMS: unsupported digest algorithm"),
        }
    }
}

impl core::error::Error for CmsError {}

/// Structurally validated view of a single-signer CMS `SignedData`.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SignedData<'a> {
    /// Inner `EncapsulatedContentInfo.eContentType` OID, validated at
    /// the BER boundary via [`crate::oid::Oid`].
    pub econtent_type_oid: crate::oid::Oid<'a>,
    /// Inner `eContent` OCTET STRING value bytes, or `None` for a
    /// detached `SignedData` (RFC 5652 sec. 5.2). For an eMRTD `EF.SOD`
    /// this holds the DER encoding of `LDSSecurityObject`.
    pub econtent_der: Option<&'a [u8]>,
    /// Embedded X.509 certificates (for `EF.SOD`, typically the
    /// Document Signer Certificate). Each slice is the full DER of one
    /// certificate `SEQUENCE`.
    pub certificates_der: Vec<&'a [u8]>,
}

/// Owning wrapper around a validated CMS `SignedData` buffer.
///
/// Follows the same lifetime-anchor pattern as
/// [`crate::x509::OwnedCert`], [`crate::crl::OwnedCrl`], and
/// [`crate::ocsp::OwnedOcspResponse`]: validates the DER on
/// construction and hands out borrowed [`SignedData`] views on demand.
#[derive(Debug, Clone)]
pub struct OwnedSignedData {
    /// Validated raw DER bytes.
    der: Vec<u8>,
}

impl OwnedSignedData {
    /// Parse `der` as a CMS `SignedData` (accepting the bare-SEQUENCE,
    /// `ContentInfo`-wrapped, and `EF.SOD`-wrapped forms) and retain an
    /// owned copy.
    ///
    /// # Errors
    /// [`CmsError`] if `der` fails BER or CMS structural validation.
    #[inline]
    pub fn from_der<B: AsRef<[u8]>>(der: B) -> Result<Self, CmsError> {
        let bytes = der.as_ref().to_vec();
        drop(SignedData::parse(&bytes)?);
        Ok(Self { der: bytes })
    }

    /// Re-parse the owned DER and return a borrowed [`SignedData`] view.
    ///
    /// # Performance
    /// Parses the DER on every call (`O(n)` in the DER length). Bind
    /// the returned view once when reading multiple fields.
    ///
    /// # Panics
    /// Never -- [`Self::from_der`] validated `self.der` at construction.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "from_der validated the DER at construction; re-parsing the immutable Vec cannot fail under #![deny(unsafe_code)]."
    )]
    #[inline]
    pub fn view(&self) -> SignedData<'_> {
        SignedData::parse(&self.der)
            .expect("OwnedSignedData: from_der validated DER at construction")
    }

    /// Borrow the underlying raw DER bytes.
    #[must_use]
    #[inline]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

impl<'a> SignedData<'a> {
    /// Parse a CMS `SignedData` from raw DER across the three wrappings
    /// seen in FINEID and eMRTD deployments (RFC 5652 sec. 3 / sec. 5.1
    /// and ICAO Doc 9303-10 sec. 4.6.2.2):
    ///
    /// 1. Bare `SignedData` `SEQUENCE`,
    /// 2. `ContentInfo` wrapping `SignedData`,
    /// 3. `EF.SOD` wrapper (`[APPLICATION 23]`) wrapping `ContentInfo`.
    pub(crate) fn parse(input: &'a [u8]) -> Result<Self, CmsError> {
        let Some((&first, _rest)) = input.split_first() else {
            return Err(CmsError::UnexpectedStructure("empty input"));
        };
        let signed_data_body = match u16::from(first) {
            <EfSodWrapper as BerTag>::TAG => {
                let outer = CmsHelpers::parse_exact::<EfSodWrapper>(
                    input,
                    "trailing bytes after EF.SOD wrapper",
                )?;
                CmsHelpers::decode_content_info(&ContentInfoDer { input: outer.value })?
            }
            <Sequence as BerTag>::TAG => {
                let outer =
                    CmsHelpers::parse_exact::<Sequence>(input, "trailing bytes after CMS value")?;
                let mut it = BerTlvIter::new(outer.value);
                let first_any = it.next().ok_or(CmsError::UnexpectedStructure("empty"))??;
                if first_any.tag == <Oid as BerTag>::TAG {
                    CmsHelpers::decode_content_info(&ContentInfoDer { input })?
                } else {
                    outer.value
                }
            }
            _ => return Err(CmsError::UnexpectedStructure("unknown wrapper tag")),
        };
        CmsHelpers::parse_signed_data_body(&SignedDataBody {
            body: signed_data_body,
        })
    }
}

/// Structural CMS parser helpers hosted on a unit struct.
struct CmsHelpers;

/// `ContentInfo` DER wrapper for CMS parser helpers.
struct ContentInfoDer<'a> {
    /// `ContentInfo` DER bytes.
    input: &'a [u8],
}

/// `SignedData` body bytes.
struct SignedDataBody<'a> {
    /// Inner `SignedData` `SEQUENCE` value bytes.
    body: &'a [u8],
}

/// `SignerInfo` body bytes.
struct SignerInfoBody<'a> {
    /// Inner `SignerInfo` `SEQUENCE` value bytes.
    body: &'a [u8],
}

impl CmsHelpers {
    /// Parse one typed TLV and reject any trailing bytes after it.
    fn parse_exact<'a, T: BerTag>(
        input: &'a [u8],
        trailing: &'static str,
    ) -> Result<BerTlv<'a, T>, CmsError> {
        let tlv = BerTlv::<T>::parse(input)?;
        if tlv.size != input.len() {
            return Err(CmsError::UnexpectedStructure(trailing));
        }
        Ok(tlv)
    }

    /// Decode `ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }`.
    fn decode_content_info<'a>(content_info: &ContentInfoDer<'a>) -> Result<&'a [u8], CmsError> {
        let outer =
            Self::parse_exact::<Sequence>(content_info.input, "trailing bytes after ContentInfo")?;
        let mut it = BerTlvIter::new(outer.value);
        let oid = it
            .next()
            .ok_or(CmsError::UnexpectedStructure("ContentInfo missing OID"))??
            .expect::<Oid>()
            .or(Err(CmsError::UnexpectedStructure(
                "ContentInfo OID malformed",
            )))?;
        crate::oid::Oid::new(oid.value).or(Err(CmsError::UnexpectedStructure(
            "ContentInfo OID malformed",
        )))?;
        if oid.value != known::SIGNED_DATA.as_bytes() {
            return Err(CmsError::UnexpectedStructure("ContentInfo not SignedData"));
        }
        let explicit = it
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "ContentInfo missing [0] EXPLICIT",
            ))??
            .expect::<Asn1ContentExplicit0>()
            .or(Err(CmsError::UnexpectedStructure(
                "ContentInfo content tag not [0] EXPLICIT",
            )))?;
        if it.next().is_some() {
            return Err(CmsError::UnexpectedStructure(
                "ContentInfo has trailing fields",
            ));
        }
        let inner_sd =
            Self::parse_exact::<Sequence>(explicit.value, "trailing bytes in ContentInfo content")?;
        Ok(inner_sd.value)
    }

    /// Parse and validate a `SignedData` body and its sole `SignerInfo`.
    #[expect(
        clippy::too_many_lines,
        reason = "the SignedData grammar is validated in RFC 5652 field order so ordering and one-signer invariants stay auditable in one place"
    )]
    fn parse_signed_data_body<'a>(
        signed_data: &SignedDataBody<'a>,
    ) -> Result<SignedData<'a>, CmsError> {
        let mut it = BerTlvIter::new(signed_data.body);
        let version = it
            .next()
            .ok_or(CmsError::UnexpectedStructure("SignedData missing version"))??
            .expect::<Integer>()
            .or(Err(CmsError::UnexpectedStructure(
                "SignedData version not INTEGER",
            )))?;
        if version.value.is_empty() {
            return Err(CmsError::UnexpectedStructure("SignedData version is empty"));
        }

        let digest_algorithms = it
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "SignedData missing digestAlgorithms",
            ))??
            .expect::<Set>()
            .or(Err(CmsError::UnexpectedStructure(
                "SignedData digestAlgorithms not SET",
            )))?;
        let digest_algorithm_oids = Self::parse_digest_algorithms(digest_algorithms.value)?;

        let encap = it
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "SignedData missing encapContentInfo",
            ))??
            .expect::<Sequence>()
            .or(Err(CmsError::UnexpectedStructure(
                "encapContentInfo not SEQUENCE",
            )))?;
        let mut e_it = BerTlvIter::new(encap.value);
        let econtent_type = e_it
            .next()
            .ok_or(CmsError::UnexpectedStructure("encap missing eContentType"))??
            .expect::<Oid>()
            .or(Err(CmsError::UnexpectedStructure("eContentType not OID")))?;
        let econtent_type_oid = crate::oid::Oid::new(econtent_type.value).or(Err(
            CmsError::UnexpectedStructure("eContentType OID malformed"),
        ))?;
        let econtent_der = match e_it.next() {
            None => None,
            Some(explicit) => {
                let explicit = explicit?.expect::<Asn1ContentExplicit0>().or(Err(
                    CmsError::UnexpectedStructure("eContent tag not [0] EXPLICIT"),
                ))?;
                let octet =
                    Self::parse_exact::<OctetString>(explicit.value, "trailing bytes in eContent")?;
                Some(octet.value)
            }
        };
        if e_it.next().is_some() {
            return Err(CmsError::UnexpectedStructure(
                "encapContentInfo has trailing fields",
            ));
        }

        let mut remaining = Vec::new();
        for tlv in it {
            remaining.push(tlv?);
        }

        let mut field_index = 0_usize;
        let mut certificates_der = Vec::new();
        if remaining
            .get(field_index)
            .is_some_and(|field| field.tag == <Asn1ContentExplicit0 as BerTag>::TAG)
        {
            let certificates = remaining
                .get(field_index)
                .ok_or(CmsError::UnexpectedStructure("certificates missing"))?;
            certificates_der = Self::parse_certificates(certificates.value)?;
            field_index = field_index.saturating_add(1);
        }
        if remaining
            .get(field_index)
            .is_some_and(|field| field.tag == <Asn1ContentImplicit1 as BerTag>::TAG)
        {
            let crls = remaining
                .get(field_index)
                .ok_or(CmsError::UnexpectedStructure("crls missing"))?;
            Self::validate_nonempty_tlv_stream(crls.value, "empty crls field")?;
            field_index = field_index.saturating_add(1);
        }

        let signer_infos = remaining
            .get(field_index)
            .ok_or(CmsError::UnexpectedStructure(
                "SignedData missing signerInfos",
            ))?
            .expect::<Set>()
            .or(Err(CmsError::UnexpectedStructure(
                "SignedData signerInfos not SET",
            )))?;
        field_index = field_index.saturating_add(1);
        if field_index != remaining.len() {
            return Err(CmsError::UnexpectedStructure(
                "SignedData has trailing or out-of-order fields",
            ));
        }

        let mut signers = BerTlvIter::new(signer_infos.value);
        let signer_tlv = signers
            .next()
            .ok_or(CmsError::UnexpectedStructure("signerInfos is empty"))??
            .expect::<Sequence>()
            .or(Err(CmsError::UnexpectedStructure(
                "signerInfo not SEQUENCE",
            )))?;
        match signers.next() {
            None => {}
            Some(Ok(_extra)) => {
                return Err(CmsError::UnexpectedStructure(
                    "SignedData must contain exactly one signerInfo",
                ));
            }
            Some(Err(error)) => return Err(error.into()),
        }
        let signer_digest_oid = Self::validate_signer_info(
            &SignerInfoBody {
                body: signer_tlv.value,
            },
            econtent_type_oid,
        )?;
        if !digest_algorithm_oids.contains(&signer_digest_oid) {
            return Err(CmsError::UnexpectedStructure(
                "signer digestAlgorithm absent from SignedData set",
            ));
        }

        Ok(SignedData {
            econtent_type_oid,
            econtent_der,
            certificates_der,
        })
    }

    /// Parse and validate every `AlgorithmIdentifier` in `digestAlgorithms`.
    fn parse_digest_algorithms(
        digest_algorithms: &[u8],
    ) -> Result<Vec<crate::oid::Oid<'_>>, CmsError> {
        let mut algorithms = Vec::new();
        for algorithm in BerTlvIter::new(digest_algorithms) {
            let algorithm =
                algorithm?
                    .expect::<Sequence>()
                    .or(Err(CmsError::UnexpectedStructure(
                        "digestAlgorithms entry not SEQUENCE",
                    )))?;
            algorithms.push(Self::parse_algorithm_identifier(algorithm)?);
        }
        if algorithms.is_empty() {
            return Err(CmsError::UnexpectedStructure("digestAlgorithms is empty"));
        }
        Ok(algorithms)
    }

    /// Parse an `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`.
    ///
    /// Accepts parameterless forms (ECDSA), `NULL` parameters (RSA
    /// PKCS#1 v1.5 / SHA-2), and structured `SEQUENCE` parameters such
    /// as `RSASSA-PSS-params` on `id-RSASSA-PSS` (`1.2.840.113549.1.1.10`).
    fn parse_algorithm_identifier(
        algorithm: BerTlv<'_, Sequence>,
    ) -> Result<crate::oid::Oid<'_>, CmsError> {
        let mut it = algorithm.iter_children();
        let oid = it
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "AlgorithmIdentifier missing OID",
            ))??
            .expect::<Oid>()
            .or(Err(CmsError::UnexpectedStructure(
                "AlgorithmIdentifier algorithm not OID",
            )))?;
        let oid = crate::oid::Oid::new(oid.value).or(Err(CmsError::UnexpectedStructure(
            "AlgorithmIdentifier OID malformed",
        )))?;
        if let Some(parameters) = it.next() {
            parameters?;
            if let Some(extra) = it.next() {
                extra?;
                return Err(CmsError::UnexpectedStructure(
                    "AlgorithmIdentifier has trailing fields",
                ));
            }
        }
        Ok(oid)
    }

    /// Collect direct X.509 `Certificate` choices and reject every other
    /// `CertificateChoices` alternative.
    fn parse_certificates(certificates: &[u8]) -> Result<Vec<&[u8]>, CmsError> {
        if certificates.is_empty() {
            return Err(CmsError::UnexpectedStructure("empty certificates field"));
        }
        let mut result = Vec::new();
        let mut cursor = 0_usize;
        while cursor < certificates.len() {
            let tail = certificates
                .get(cursor..)
                .ok_or(CmsError::UnexpectedStructure("certificate cursor invalid"))?;
            let certificate = BerTlvAny::parse(tail)?;
            if certificate.tag != <Sequence as BerTag>::TAG {
                return Err(CmsError::UnexpectedStructure(
                    "unsupported CMS CertificateChoices entry",
                ));
            }
            let end = cursor.saturating_add(certificate.size);
            let certificate_der = certificates
                .get(cursor..end)
                .ok_or(CmsError::UnexpectedStructure("certificate truncated"))?;
            result.push(certificate_der);
            cursor = end;
        }
        Ok(result)
    }

    /// Require a constructed IMPLICIT field to contain at least one complete TLV.
    fn validate_nonempty_tlv_stream(values: &[u8], empty: &'static str) -> Result<(), CmsError> {
        let mut count = 0_usize;
        for value in BerTlvIter::new(values) {
            value?;
            count = count.saturating_add(1);
        }
        if count == 0 {
            return Err(CmsError::UnexpectedStructure(empty));
        }
        Ok(())
    }

    /// Validate a CMS `SignerInfo` (RFC 5652 sec. 5.3) and return its
    /// `digestAlgorithm` OID so the caller can confirm membership in
    /// `SignedData.digestAlgorithms`.
    fn validate_signer_info<'a>(
        signer_info: &SignerInfoBody<'a>,
        expected_content_type: crate::oid::Oid<'a>,
    ) -> Result<crate::oid::Oid<'a>, CmsError> {
        let mut children = BerTlvIter::new(signer_info.body);
        let version = children
            .next()
            .ok_or(CmsError::UnexpectedStructure("signerInfo missing version"))??
            .expect::<Integer>()
            .or(Err(CmsError::UnexpectedStructure(
                "signerInfo version not INTEGER",
            )))?;
        let sid = children
            .next()
            .ok_or(CmsError::UnexpectedStructure("signerInfo missing sid"))??;
        Self::validate_signer_identifier(sid, version.value)?;

        let digest_alg_seq = children
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "signerInfo missing digestAlgorithm",
            ))??
            .expect::<Sequence>()
            .or(Err(CmsError::UnexpectedStructure(
                "digestAlgorithm not SEQUENCE",
            )))?;
        let digest_algorithm_oid = Self::parse_algorithm_identifier(digest_alg_seq)?;

        let after_digest = children.next().ok_or(CmsError::UnexpectedStructure(
            "signerInfo missing signature material",
        ))??;
        let (signed_attrs_value, signature_algorithm) =
            if after_digest.tag == <Asn1ContentExplicit0 as BerTag>::TAG {
                let signature_algorithm = children.next().ok_or(
                    CmsError::UnexpectedStructure("signerInfo missing signatureAlgorithm"),
                )??;
                (Some(after_digest.value), signature_algorithm)
            } else {
                (None, after_digest)
            };
        let sig_alg_seq =
            signature_algorithm
                .expect::<Sequence>()
                .or(Err(CmsError::UnexpectedStructure(
                    "signatureAlgorithm not SEQUENCE",
                )))?;
        let _signature_algorithm_oid = Self::parse_algorithm_identifier(sig_alg_seq)?;
        let _sig_octet = children
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "signerInfo missing signature material",
            ))??
            .expect::<OctetString>()
            .or(Err(CmsError::UnexpectedStructure(
                "signature not OCTET STRING",
            )))?;

        if let Some(unsigned_attrs) = children.next() {
            let unsigned_attrs = unsigned_attrs?;
            if unsigned_attrs.tag != <Asn1ContentImplicit1 as BerTag>::TAG {
                return Err(CmsError::UnexpectedStructure(
                    "signerInfo trailing field is not unsignedAttrs",
                ));
            }
            let _discarded = Self::parse_attributes(unsigned_attrs.value, false)?;
        }
        if children.next().is_some() {
            return Err(CmsError::UnexpectedStructure(
                "signerInfo has trailing fields",
            ));
        }

        if let Some(attrs_value) = signed_attrs_value {
            let content_type = Self::parse_attributes(attrs_value, true)?;
            if content_type != Some(expected_content_type) {
                return Err(CmsError::UnexpectedStructure(
                    "signed contentType does not match eContentType",
                ));
            }
        }
        Ok(digest_algorithm_oid)
    }

    /// Validate `SignerIdentifier` syntax and RFC 5652 version coupling.
    fn validate_signer_identifier(sid: BerTlvAny<'_>, version: &[u8]) -> Result<(), CmsError> {
        const VERSION_ISSUER_AND_SERIAL: u8 = 1;
        const VERSION_SUBJECT_KEY_IDENTIFIER: u8 = 3;

        if sid.tag == <Sequence as BerTag>::TAG {
            if version != [VERSION_ISSUER_AND_SERIAL] {
                return Err(CmsError::UnexpectedStructure(
                    "issuerAndSerialNumber signerInfo version is not 1",
                ));
            }
            let sid = sid.expect::<Sequence>()?;
            let mut it = sid.iter_children();
            let issuer = it
                .next()
                .ok_or(CmsError::UnexpectedStructure("sid missing issuer"))??
                .expect::<Sequence>()
                .or(Err(CmsError::UnexpectedStructure(
                    "sid issuer is not Name SEQUENCE",
                )))?;
            let serial = it
                .next()
                .ok_or(CmsError::UnexpectedStructure("sid missing serialNumber"))??
                .expect::<Integer>()
                .or(Err(CmsError::UnexpectedStructure(
                    "sid serialNumber not INTEGER",
                )))?;
            if serial.value.is_empty() || it.next().is_some() {
                return Err(CmsError::UnexpectedStructure(
                    "issuerAndSerialNumber malformed",
                ));
            }
            let _issuer_der = sid
                .value
                .get(..issuer.size)
                .ok_or(CmsError::UnexpectedStructure("sid issuer truncated"))?;
            Ok(())
        } else if sid.tag == <SignerSubjectKeyIdentifier as BerTag>::TAG {
            if version != [VERSION_SUBJECT_KEY_IDENTIFIER] {
                return Err(CmsError::UnexpectedStructure(
                    "subjectKeyIdentifier signerInfo version is not 3",
                ));
            }
            let sid = sid.expect::<SignerSubjectKeyIdentifier>()?;
            if sid.value.is_empty() {
                return Err(CmsError::UnexpectedStructure(
                    "subjectKeyIdentifier is empty",
                ));
            }
            Ok(())
        } else {
            Err(CmsError::UnexpectedStructure(
                "unsupported SignerIdentifier choice",
            ))
        }
    }

    /// Parse an `Attribute` set. Signed attributes require exactly one
    /// `contentType` OID and one `messageDigest` OCTET STRING; returns
    /// the `contentType` OID when `require_mandatory_signed` is set.
    fn parse_attributes(
        attrs_value: &[u8],
        require_mandatory_signed: bool,
    ) -> Result<Option<crate::oid::Oid<'_>>, CmsError> {
        let mut content_type = None;
        let mut has_message_digest = false;

        for attr in BerTlvIter::new(attrs_value) {
            let attr = attr?
                .expect::<Sequence>()
                .or(Err(CmsError::UnexpectedStructure("attribute not SEQUENCE")))?;
            let mut it = attr.iter_children();
            let oid = it
                .next()
                .ok_or(CmsError::UnexpectedStructure("attribute missing OID"))??
                .expect::<Oid>()
                .or(Err(CmsError::UnexpectedStructure("attribute type not OID")))?;
            let oid = crate::oid::Oid::new(oid.value).or(Err(CmsError::UnexpectedStructure(
                "attribute OID malformed",
            )))?;
            let values = it
                .next()
                .ok_or(CmsError::UnexpectedStructure("attribute missing values"))??
                .expect::<Set>()
                .or(Err(CmsError::UnexpectedStructure(
                    "attribute values not SET",
                )))?;
            if it.next().is_some() {
                return Err(CmsError::UnexpectedStructure(
                    "attribute has trailing fields",
                ));
            }
            Self::validate_nonempty_tlv_stream(values.value, "attribute value set is empty")?;

            if require_mandatory_signed && oid == known::CONTENT_TYPE {
                if content_type.is_some() {
                    return Err(CmsError::UnexpectedStructure(
                        "duplicate signed contentType attribute",
                    ));
                }
                let value = Self::parse_exact::<Oid>(
                    values.value,
                    "contentType attribute has multiple values",
                )?;
                content_type = Some(crate::oid::Oid::new(value.value).or(Err(
                    CmsError::UnexpectedStructure("contentType attribute OID malformed"),
                ))?);
            } else if require_mandatory_signed && oid == known::MESSAGE_DIGEST {
                if has_message_digest {
                    return Err(CmsError::UnexpectedStructure(
                        "duplicate signed messageDigest attribute",
                    ));
                }
                let _value = Self::parse_exact::<OctetString>(
                    values.value,
                    "messageDigest attribute has multiple values",
                )?;
                has_message_digest = true;
            }
        }

        if require_mandatory_signed && content_type.is_none() {
            return Err(CmsError::UnexpectedStructure(
                "signedAttrs missing contentType",
            ));
        }
        if require_mandatory_signed && !has_message_digest {
            return Err(CmsError::UnexpectedStructure(
                "signedAttrs missing messageDigest",
            ));
        }
        Ok(content_type)
    }
}

// ----- LDSSecurityObject (the eContent for eMRTD SOD) -----

/// Parsed eMRTD `LDSSecurityObject` (the `eContent` of an `EF.SOD`
/// `SignedData`, ICAO Doc 9303-10 sec. 4.6.2).
#[derive(Debug, Clone)]
pub struct LdsSecurityObject<'a> {
    /// `hashAlgorithm` OID mapped to SHA-256, SHA-384, or SHA-512.
    pub hash_algorithm: HashAlgorithm,
    /// Per-data-group `(dataGroupNumber, hash)` pairs.
    pub data_group_hashes: Vec<(u32, &'a [u8])>,
}

impl<'a> LdsSecurityObject<'a> {
    /// Parse `LDSSecurityObject` from the `econtent_der` slice of an
    /// eMRTD `EF.SOD`.
    ///
    /// # Errors
    /// [`CmsError`] on BER decode failure, malformed structure, or
    /// unsupported digest algorithm OID.
    pub(crate) fn parse(der: &'a [u8]) -> Result<Self, CmsError> {
        const BITS_PER_BYTE: u32 = 8;

        let outer = BerTlv::<Sequence>::parse(der)?;
        let mut it = BerTlvIter::new(outer.value);
        let _version = it.next().ok_or(CmsError::UnexpectedStructure(
            "LDSSecurityObject missing version",
        ))??;
        let hash_alg_seq = it
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "LDSSecurityObject missing hashAlgorithm",
            ))??
            .expect::<Sequence>()
            .or(Err(CmsError::UnexpectedStructure(
                "hashAlgorithm not SEQUENCE",
            )))?;
        let hash_oid_tlv = BerTlv::<Oid>::parse(hash_alg_seq.value).or(Err(
            CmsError::UnexpectedStructure("hashAlgorithm OID missing"),
        ))?;
        let hash_algorithm = HashAlgorithm::from_oid(hash_oid_tlv.value)
            .ok_or(CmsError::UnsupportedDigestAlgorithm)?;
        let dgh_seq = it
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "LDSSecurityObject missing dataGroupHashValues",
            ))??
            .expect::<Sequence>()
            .or(Err(CmsError::UnexpectedStructure(
                "dataGroupHashValues not SEQUENCE",
            )))?;
        let mut data_group_hashes: Vec<(u32, &[u8])> = Vec::new();
        for dg in BerTlvIter::new(dgh_seq.value) {
            let Ok(dg) = dg?.expect::<Sequence>() else {
                continue;
            };
            let mut dit = BerTlvIter::new(dg.value);
            let num_tlv = dit
                .next()
                .ok_or(CmsError::UnexpectedStructure("DG hash missing number"))??;
            let Ok(num_tlv) = num_tlv.expect::<Integer>() else {
                continue;
            };
            let mut num: u32 = 0;
            for &b in num_tlv.value {
                num = num.wrapping_shl(BITS_PER_BYTE) | u32::from(b);
            }
            let hash_tlv = dit.next().ok_or(CmsError::UnexpectedStructure(
                "DG hash missing OCTET STRING",
            ))??;
            let Ok(hash_tlv) = hash_tlv.expect::<OctetString>() else {
                continue;
            };
            data_group_hashes.push((num, hash_tlv.value));
        }
        Ok(LdsSecurityObject {
            hash_algorithm,
            data_group_hashes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CmsError, CmsHelpers, HashAlgorithm, LdsSecurityObject, OwnedSignedData, SignedData,
    };
    use crate::ber::{BerTlv, BerTlvIter, Sequence, tlv};
    use crate::oid::{Oid, known};
    use crate::x509::Certificate;

    const TAG_INTEGER: u8 = 0x02;
    const TAG_OCTET_STRING: u8 = 0x04;
    const TAG_NULL: u8 = 0x05;
    const TAG_OID: u8 = 0x06;
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_SET: u8 = 0x31;
    const TAG_EF_SOD: u8 = 0x77;
    const TAG_SUBJECT_KEY_ID: u8 = 0x80;
    const TAG_CONTEXT_0: u8 = 0xA0;
    const TAG_CONTEXT_1: u8 = 0xA1;
    const TAG_CONTEXT_2: u8 = 0xA2;

    const VERSION_0: u8 = 0;
    const VERSION_1: u8 = 1;
    const VERSION_3: u8 = 3;
    const SERIAL_ONE: u8 = 1;
    const PSS_SALT_LEN_SHA256: u8 = 32;
    const DG_NUMBER_1: u32 = 1;
    const DG_NUMBER_2: u32 = 2;
    const EXPECTED_DG_COUNT: usize = 2;
    const EXPECTED_EMBEDDED_CERTS: usize = 1;
    const SIGNER_COUNT_ZERO: usize = 0;
    const SIGNER_COUNT_ONE: usize = 1;
    const SIGNER_COUNT_TWO: usize = 2;
    const TRAILING_ZERO_BYTE: u8 = 0;

    // Committed OpenSSL-generated CMS fixtures carrying an eMRTD
    // LDSSecurityObject with DG1 = SHA256("refineid-test-DG1") and
    // DG2 = SHA256("refineid-test-DG2").
    //
    // RSA-2048/SHA-256 CMS SignedData with signedAttrs present.
    const RSA_CMS_HEX: &str = "\
        3082060906092a864886f70d010702a08205fa308205f6020103310d300b0609\
        60864801650304020130700606678108010101a06604643062020100300d0609\
        6086480165030402010500304e3025020101042040d486fedd456ab92c4d02b2\
        704362570c096df55f421fee53945e70c6831bfd3025020102042072fc7341e3\
        f5f8935e96be104329ea083e88d8f009bcb46a340be9968902c008a082032530\
        82032130820209a00302010202141abbaecfaf492906d7fc069b27857f73ee21\
        0b4b300d06092a864886f70d01010b05003020311e301c06035504030c155265\
        46696e65494420546573742044534320525341301e170d323630363238313532\
        3834385a170d3336303632353135323834385a3020311e301c06035504030c15\
        526546696e6549442054657374204453432052534130820122300d06092a8648\
        86f70d01010105000382010f003082010a0282010100ed28349290c82f3dd487\
        1eff7b2ec12d057a9d2dc9ba566cd8ce23a0b5fc559ce4456738e2b69b57fd56\
        f84d0f6a5ca91f22d36a3a64864c0c3c50f0d96af2a18ecd5a7c1f934c2f3638\
        5264d867982f70487004cd5105d16cd47a7ec61c204a37d947c5d997ebf8e1ef\
        f6581823b15d753123991b308669ec5633214e7d75b35fbbdb937c6782f6e406\
        aed8edca9b5a028297891acad926fecb3adaa806daaf0bf886bb16c667762269\
        c9ecf3f6edd3398d151cbbe8f1b50ba6b4f4365451ad21fbc4804ff2bc406d61\
        db7041239b7bf53c4bfc5724302c2b392530e9b56c57c4d6072528fa2b3f95ed\
        90d6144869d5c5e9f48f74da2b1babed1d9d2bb2ef130203010001a353305130\
        1d0603551d0e04160414e5c676464f2bbed52b1298910619a21cde4f372a301f\
        0603551d23041830168014e5c676464f2bbed52b1298910619a21cde4f372a30\
        0f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003\
        82010100773ea57116db9ed8a192ce9c79faa1f6628b1d948f8d98aebb1a14fe\
        c50c931d89afbf74fd8f7890461231d1c29dfae7b4abfe71e7414a6b09191f69\
        608d940b9735fb3064152349f793ef0acc89a30bdf41383762cba983f0d4248a\
        67867cb7fce688a0a34454a2653648eeedd9b20b03bc73cd19df061cf3e045e1\
        26c3eb25aa529c872134bfa1c4057f3fd4177983ea2a7608d8ea413846d3c9f0\
        c0bb2f304246bbaaeb99c77fb761a711d630dea9dd37b8619a3030b47cdcc948\
        15f4baa7bf471fe4c5371ebe77e7e99d161eb5bf3a16802622899c8a3c07f45c\
        e1f9bded56c3e3b14e9201be3d585573af6a3441c0dbe94378e6fd9a984cbc3d\
        f865f8f1318202453082024102010130383020311e301c06035504030c155265\
        46696e6549442054657374204453432052534102141abbaecfaf492906d7fc06\
        9b27857f73ee210b4b300b0609608648016503040201a081e1301506092a8648\
        86f70d01090331080606678108010101301c06092a864886f70d010905310f17\
        0d3236303632383135323834385a302f06092a864886f70d01090431220420b4\
        f0af7f043f5d2153918add8d1aeee3214894d7d086ddec9332a3a6524989d230\
        7906092a864886f70d01090f316c306a300b060960864801650304012a300b06\
        09608648016503040116300b0609608648016503040102300a06082a864886f7\
        0d0307300e06082a864886f70d030202020080300d06082a864886f70d030202\
        0140300706052b0e030207300d06082a864886f70d0302020128300d06092a86\
        4886f70d010101050004820100515a1e751b91741f1c30ee975c3c7c84b94a2d\
        6b7f44bbd7edacaba05e39f7a116905c4d0c097ca694119542f43b3e9c28e84a\
        c4ded455743185b90122ad8b9e802b2cdf80f6c4f8be4dc9eeefcd72a679688d\
        9a6e0de0c0401d4a71f2b36edb763ab42b7cc8738b52f92a3b2f8f69b318d44e\
        0a53df2a5afead31394a89419a535a3656e0b4dfdbf585d0bceb04fdc258987a\
        afa1d3e2f49273c257dcb638b78c106ed077554742a2450a04a610f0e9104510\
        bec7224c82b5d65442376ff4a746ccd879056ee3347e02ceadf2f89cecc7d2b2\
        6613fd61ac2e60db8d4039844238e15e5e76de70305e2624d429ecf66c193b99\
        dda4b5a213bde6bd9e531be4d8";

    // RSA CMS with no signedAttrs (signature directly over eContent).
    const RSA_CMS_NOATTR_HEX: &str = "\
        3082052506092a864886f70d010702a082051630820512020103310d300b0609\
        60864801650304020130700606678108010101a06604643062020100300d0609\
        6086480165030402010500304e3025020101042040d486fedd456ab92c4d02b2\
        704362570c096df55f421fee53945e70c6831bfd3025020102042072fc7341e3\
        f5f8935e96be104329ea083e88d8f009bcb46a340be9968902c008a082032530\
        82032130820209a00302010202141abbaecfaf492906d7fc069b27857f73ee21\
        0b4b300d06092a864886f70d01010b05003020311e301c06035504030c155265\
        46696e65494420546573742044534320525341301e170d323630363238313532\
        3834385a170d3336303632353135323834385a3020311e301c06035504030c15\
        526546696e6549442054657374204453432052534130820122300d06092a8648\
        86f70d01010105000382010f003082010a0282010100ed28349290c82f3dd487\
        1eff7b2ec12d057a9d2dc9ba566cd8ce23a0b5fc559ce4456738e2b69b57fd56\
        f84d0f6a5ca91f22d36a3a64864c0c3c50f0d96af2a18ecd5a7c1f934c2f3638\
        5264d867982f70487004cd5105d16cd47a7ec61c204a37d947c5d997ebf8e1ef\
        f6581823b15d753123991b308669ec5633214e7d75b35fbbdb937c6782f6e406\
        aed8edca9b5a028297891acad926fecb3adaa806daaf0bf886bb16c667762269\
        c9ecf3f6edd3398d151cbbe8f1b50ba6b4f4365451ad21fbc4804ff2bc406d61\
        db7041239b7bf53c4bfc5724302c2b392530e9b56c57c4d6072528fa2b3f95ed\
        90d6144869d5c5e9f48f74da2b1babed1d9d2bb2ef130203010001a353305130\
        1d0603551d0e04160414e5c676464f2bbed52b1298910619a21cde4f372a301f\
        0603551d23041830168014e5c676464f2bbed52b1298910619a21cde4f372a30\
        0f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003\
        82010100773ea57116db9ed8a192ce9c79faa1f6628b1d948f8d98aebb1a14fe\
        c50c931d89afbf74fd8f7890461231d1c29dfae7b4abfe71e7414a6b09191f69\
        608d940b9735fb3064152349f793ef0acc89a30bdf41383762cba983f0d4248a\
        67867cb7fce688a0a34454a2653648eeedd9b20b03bc73cd19df061cf3e045e1\
        26c3eb25aa529c872134bfa1c4057f3fd4177983ea2a7608d8ea413846d3c9f0\
        c0bb2f304246bbaaeb99c77fb761a711d630dea9dd37b8619a3030b47cdcc948\
        15f4baa7bf471fe4c5371ebe77e7e99d161eb5bf3a16802622899c8a3c07f45c\
        e1f9bded56c3e3b14e9201be3d585573af6a3441c0dbe94378e6fd9a984cbc3d\
        f865f8f1318201613082015d02010130383020311e301c06035504030c155265\
        46696e6549442054657374204453432052534102141abbaecfaf492906d7fc06\
        9b27857f73ee210b4b300b0609608648016503040201300d06092a864886f70d\
        010101050004820100c50f17039d657b9db4409440fb31dd8a533536d531f24a\
        1a178ba3aa68f6b9d244ab90334b17ed5d6f9fbd1447457767aff5df575f7078\
        5b7da4e074b894d38bd031fdb832f3f5b849e56b422f761e5e7d90a09de3c355\
        c07401c30f3b93b847331c58fce3a7fa7d528047c26cd501703890fbf1749366\
        44f0a629bc8f92c5b27387a0c471a143a699b44f26d52599ccdcbc98138021a9\
        f9da851b537d6a3742a9aea9f8c21e2f0f25fce140d06e5cc292e9ba44411877\
        51b757982fb02400debe82f44284afe38acbfa82a73a2a01bf55d6183dc379ab\
        30f8d4431d11aad7c4e093745b3637c5750e23abb9e74b702168c132a927be11\
        822c4f64257fc36736";

    // ECDSA P-256/SHA-256 CMS SignedData with signedAttrs present.
    const EC_CMS_HEX: &str = "\
        308203bc06092a864886f70d010702a08203ad308203a9020103310d300b0609\
        60864801650304020130700606678108010101a06604643062020100300d0609\
        6086480165030402010500304e3025020101042040d486fedd456ab92c4d02b2\
        704362570c096df55f421fee53945e70c6831bfd3025020102042072fc7341e3\
        f5f8935e96be104329ea083e88d8f009bcb46a340be9968902c008a082019730\
        82019330820139a003020102021471a3c90d57ff365af954e6298b760e8b68a5\
        36c9300a06082a8648ce3d040302301f311d301b06035504030c14526546696e\
        654944205465737420445343204543301e170d3236303632383135323834385a\
        170d3336303632353135323834385a301f311d301b06035504030c1452654669\
        6e6549442054657374204453432045433059301306072a8648ce3d020106082a\
        8648ce3d03010703420004c82edd70fc6c5829254ff642c69c483feca07c0f57\
        d5b5cd4bad59712052f4d553093ef81441b72a492198db93b5d58883510913a7\
        fd0753e78ba5a9c42f9e2fa3533051301d0603551d0e04160414e7c57be92206\
        76dada052580999f3f92c82de40a301f0603551d23041830168014e7c57be922\
        0676dada052580999f3f92c82de40a300f0603551d130101ff040530030101ff\
        300a06082a8648ce3d0403020348003045022100dd757be3366a3347f052e80d\
        b4f4214967d9ec1cf17b2999345e2654da98c48302206ff6106e4bb18565c328\
        d450380776cecb39ad07cc3a1de9065b9807d042374031820186308201820201\
        013037301f311d301b06035504030c14526546696e6549442054657374204453\
        43204543021471a3c90d57ff365af954e6298b760e8b68a536c9300b06096086\
        48016503040201a081e1301506092a864886f70d010903310806066781080101\
        01301c06092a864886f70d010905310f170d3236303632383135323834385a30\
        2f06092a864886f70d01090431220420b4f0af7f043f5d2153918add8d1aeee3\
        214894d7d086ddec9332a3a6524989d2307906092a864886f70d01090f316c30\
        6a300b060960864801650304012a300b0609608648016503040116300b060960\
        8648016503040102300a06082a864886f70d0307300e06082a864886f70d0302\
        02020080300d06082a864886f70d0302020140300706052b0e030207300d0608\
        2a864886f70d0302020128300a06082a8648ce3d040302044730450221009ca7\
        26305b257a65ed479616b39b82d90d80e29ede124348caa561157599805c0220\
        20f1188ac93ef8dcfb94db3fb4e5288d57db45f5ad6cdf857003d68a7b5f903c";

    // SHA256("refineid-test-DG1") baked into the fixture LDSSecurityObject.
    const DG1_HASH_HEX: &str = "40d486fedd456ab92c4d02b2704362570c096df55f421fee53945e70c6831bfd";
    // SHA256("refineid-test-DG2") baked into the fixture LDSSecurityObject.
    const DG2_HASH_HEX: &str = "72fc7341e3f5f8935e96be104329ea083e88d8f009bcb46a340be9968902c008";

    /// MGF1 OID (`1.2.840.113549.1.1.8`) used inside `RSASSA-PSS-params`
    /// (RFC 4055 sec. 2.1).
    const MGF1_OID: Oid<'static> = Oid::const_new(
        ::const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8").as_bytes(),
    );

    fn unhex(hex_fixture: &str) -> Vec<u8> {
        let cleaned: String = hex_fixture
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        hex::decode(cleaned).expect("fixture hex decodes")
    }

    fn alg_id_no_params(oid: Oid<'_>) -> Vec<u8> {
        tlv(TAG_SEQUENCE, tlv(TAG_OID, oid.as_bytes()))
    }

    fn alg_id_with_null(oid: Oid<'_>) -> Vec<u8> {
        let mut body = tlv(TAG_OID, oid.as_bytes());
        body.extend_from_slice(&tlv(TAG_NULL, b""));
        tlv(TAG_SEQUENCE, body)
    }

    /// Build `AlgorithmIdentifier` for `id-RSASSA-PSS` carrying explicit
    /// `RSASSA-PSS-params` (`hashAlgorithm`, `maskGenAlgorithm`, `saltLength`).
    fn rsassa_pss_sha256_alg_id() -> Vec<u8> {
        let hash_alg = alg_id_with_null(known::SHA256);
        let mut mgf1_body = tlv(TAG_OID, MGF1_OID.as_bytes());
        mgf1_body.extend_from_slice(&hash_alg);
        let mgf_alg = tlv(TAG_SEQUENCE, mgf1_body);

        let mut pss_params = tlv(TAG_CONTEXT_0, hash_alg);
        pss_params.extend_from_slice(&tlv(TAG_CONTEXT_1, mgf_alg));
        pss_params.extend_from_slice(&tlv(TAG_CONTEXT_2, tlv(TAG_INTEGER, [PSS_SALT_LEN_SHA256])));

        let mut alg_body = tlv(TAG_OID, known::RSASSA_PSS.as_bytes());
        alg_body.extend_from_slice(&tlv(TAG_SEQUENCE, pss_params));
        tlv(TAG_SEQUENCE, alg_body)
    }

    /// Minimal structurally valid `SignerInfo` for parser cardinality
    /// and structural-invariant tests.
    fn minimal_signer_info_with_algs(digest_oid: Oid<'_>, sig_alg_der: &[u8]) -> Vec<u8> {
        let mut sid = tlv(TAG_SEQUENCE, b"");
        sid.extend_from_slice(&tlv(TAG_INTEGER, [SERIAL_ONE]));
        let mut body = tlv(TAG_INTEGER, [VERSION_1]);
        body.extend_from_slice(&tlv(TAG_SEQUENCE, sid));
        body.extend_from_slice(&alg_id_no_params(digest_oid));
        body.extend_from_slice(sig_alg_der);
        body.extend_from_slice(&tlv(TAG_OCTET_STRING, b"signature"));
        tlv(TAG_SEQUENCE, body)
    }

    fn minimal_signer_info() -> Vec<u8> {
        let sig_alg = alg_id_no_params(known::SHA256_WITH_RSA);
        minimal_signer_info_with_algs(known::SHA256, &sig_alg)
    }

    /// Minimal bare `SignedData` carrying `signer_count` identical
    /// `SignerInfo` values.
    fn minimal_signed_data(signer_count: usize) -> Vec<u8> {
        let mut encap = tlv(TAG_OID, known::DATA.as_bytes());
        encap.extend_from_slice(&tlv(TAG_CONTEXT_0, tlv(TAG_OCTET_STRING, b"content")));
        let mut body = tlv(TAG_INTEGER, [VERSION_1]);
        body.extend_from_slice(&tlv(TAG_SET, alg_id_no_params(known::SHA256)));
        body.extend_from_slice(&tlv(TAG_SEQUENCE, encap));
        let mut signers = Vec::new();
        for _ in 0..signer_count {
            signers.extend_from_slice(&minimal_signer_info());
        }
        body.extend_from_slice(&tlv(TAG_SET, signers));
        tlv(TAG_SEQUENCE, body)
    }

    /// Encode one CMS `Attribute` with one already-encoded value TLV.
    fn attribute(oid: Oid<'_>, value: &[u8]) -> Vec<u8> {
        let mut body = tlv(TAG_OID, oid.as_bytes());
        body.extend_from_slice(&tlv(TAG_SET, value));
        tlv(TAG_SEQUENCE, body)
    }

    #[derive(Clone, Copy)]
    struct ContentInfoFixture<'a> {
        der: &'a [u8],
    }

    fn inner_signed_data_seq(content_info: ContentInfoFixture<'_>) -> Vec<u8> {
        let ci = BerTlv::<Sequence>::parse(content_info.der).expect("ContentInfo SEQUENCE");
        let mut it = BerTlvIter::new(ci.value);
        let _oid = it
            .next()
            .expect("contentType present")
            .expect("contentType TLV");
        let explicit = it
            .next()
            .expect("[0] EXPLICIT present")
            .expect("[0] EXPLICIT TLV");
        explicit.value.to_vec()
    }

    // ----- HashAlgorithm OID mapping -----

    #[test]
    fn hash_algorithm_from_oid_maps_sha2_only() {
        assert_eq!(
            HashAlgorithm::from_oid(known::SHA256.as_bytes()),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            HashAlgorithm::from_oid(known::SHA384.as_bytes()),
            Some(HashAlgorithm::Sha384)
        );
        assert_eq!(
            HashAlgorithm::from_oid(known::SHA512.as_bytes()),
            Some(HashAlgorithm::Sha512)
        );
        assert_eq!(
            HashAlgorithm::from_oid(known::RSA_ENCRYPTION.as_bytes()),
            None
        );
        assert_eq!(HashAlgorithm::from_oid(known::SHA1.as_bytes()), None);
        assert_eq!(HashAlgorithm::from_oid(b""), None);
    }

    // ----- SignedData::parse: positive wrappings and algorithms -----

    #[test]
    fn parses_contentinfo_wrapped_rsa_and_embedded_dsc() {
        let der = unhex(RSA_CMS_HEX);
        let sd = SignedData::parse(&der).expect("parse RSA CMS");
        assert_eq!(sd.econtent_type_oid, known::ICAO_LDS_SECURITY_OBJECT);
        assert_eq!(
            sd.econtent_der.and_then(|content| content.first()),
            Some(&TAG_SEQUENCE)
        );
        assert_eq!(sd.certificates_der.len(), EXPECTED_EMBEDDED_CERTS);
        let cert_der = sd.certificates_der.first().copied().expect("one cert");
        Certificate::from_der(cert_der).expect("embedded DSC parses as X.509");
    }

    #[test]
    fn parses_contentinfo_wrapped_ecdsa() {
        let der = unhex(EC_CMS_HEX);
        let sd = SignedData::parse(&der).expect("parse ECDSA CMS");
        assert_eq!(sd.econtent_type_oid, known::ICAO_LDS_SECURITY_OBJECT);
        assert_eq!(sd.certificates_der.len(), EXPECTED_EMBEDDED_CERTS);
        let lds = LdsSecurityObject::parse(sd.econtent_der.expect("attached")).expect("LDS parses");
        assert_eq!(lds.hash_algorithm, HashAlgorithm::Sha256);
        assert_eq!(lds.data_group_hashes.len(), EXPECTED_DG_COUNT);
    }

    #[test]
    fn parses_signer_info_without_signed_attrs() {
        let der = unhex(RSA_CMS_NOATTR_HEX);
        let sd = SignedData::parse(&der).expect("parse no-signedAttrs RSA CMS");
        assert_eq!(sd.econtent_type_oid, known::ICAO_LDS_SECURITY_OBJECT);
        assert_eq!(sd.certificates_der.len(), EXPECTED_EMBEDDED_CERTS);
        assert!(sd.econtent_der.is_some());
    }

    #[test]
    fn parses_ef_sod_signed_with_rsassa_pss() {
        let rsa_fixture = unhex(RSA_CMS_HEX);
        let rsa_sd = SignedData::parse(&rsa_fixture).expect("fixture parses");
        let lds_der = rsa_sd.econtent_der.expect("fixture eContent");
        let dsc_der = rsa_sd
            .certificates_der
            .first()
            .copied()
            .expect("fixture DSC");

        let mut encap = tlv(TAG_OID, known::ICAO_LDS_SECURITY_OBJECT.as_bytes());
        encap.extend_from_slice(&tlv(TAG_CONTEXT_0, tlv(TAG_OCTET_STRING, lds_der)));

        let mut signed_attrs = attribute(
            known::CONTENT_TYPE,
            &tlv(TAG_OID, known::ICAO_LDS_SECURITY_OBJECT.as_bytes()),
        );
        signed_attrs.extend_from_slice(&attribute(
            known::MESSAGE_DIGEST,
            &tlv(TAG_OCTET_STRING, b"refineid-pss-digest-commitment"),
        ));

        let mut signer_body = tlv(TAG_INTEGER, [VERSION_3]);
        signer_body.extend_from_slice(&tlv(TAG_SUBJECT_KEY_ID, b"pss-dsc-ski"));
        signer_body.extend_from_slice(&alg_id_with_null(known::SHA256));
        signer_body.extend_from_slice(&tlv(TAG_CONTEXT_0, signed_attrs));
        signer_body.extend_from_slice(&rsassa_pss_sha256_alg_id());
        signer_body.extend_from_slice(&tlv(TAG_OCTET_STRING, b"rsassa-pss-signature"));
        let signer_info = tlv(TAG_SEQUENCE, signer_body);

        let mut sd_body = tlv(TAG_INTEGER, [VERSION_3]);
        sd_body.extend_from_slice(&tlv(TAG_SET, alg_id_with_null(known::SHA256)));
        sd_body.extend_from_slice(&tlv(TAG_SEQUENCE, encap));
        sd_body.extend_from_slice(&tlv(TAG_CONTEXT_0, dsc_der));
        sd_body.extend_from_slice(&tlv(TAG_SET, signer_info));
        let sd_seq = tlv(TAG_SEQUENCE, sd_body);

        let mut ci_body = tlv(TAG_OID, known::SIGNED_DATA.as_bytes());
        ci_body.extend_from_slice(&tlv(TAG_CONTEXT_0, sd_seq));
        let ef_sod = tlv(TAG_EF_SOD, tlv(TAG_SEQUENCE, ci_body));

        let owned = OwnedSignedData::from_der(&ef_sod).expect("RSASSA-PSS EF.SOD parses");
        let view = owned.view();
        assert_eq!(view.econtent_type_oid, known::ICAO_LDS_SECURITY_OBJECT);
        assert_eq!(view.econtent_der, Some(lds_der));
        assert_eq!(view.certificates_der, vec![dsc_der]);
    }

    #[test]
    fn three_wrappings_decode_to_same_signeddata() {
        let content_info = unhex(RSA_CMS_HEX);
        let bare = inner_signed_data_seq(ContentInfoFixture { der: &content_info });
        let ef_sod = tlv(TAG_EF_SOD, &content_info);

        let from_ci = SignedData::parse(&content_info).expect("ContentInfo");
        let from_bare = SignedData::parse(&bare).expect("bare SignedData");
        let from_efsod = SignedData::parse(&ef_sod).expect("EF.SOD wrapper");

        for other in [&from_bare, &from_efsod] {
            assert_eq!(other.econtent_der, from_ci.econtent_der);
            assert_eq!(other.certificates_der, from_ci.certificates_der);
            assert_eq!(
                other.econtent_type_oid.as_bytes(),
                from_ci.econtent_type_oid.as_bytes()
            );
        }
    }

    #[test]
    fn detached_signeddata_parses_with_none_econtent() {
        let encap = tlv(TAG_SEQUENCE, tlv(TAG_OID, known::DATA.as_bytes()));
        let mut body = tlv(TAG_INTEGER, [VERSION_1]);
        body.extend_from_slice(&tlv(TAG_SET, alg_id_no_params(known::SHA256)));
        body.extend_from_slice(&encap);
        body.extend_from_slice(&tlv(TAG_SET, minimal_signer_info()));
        let sd_seq = tlv(TAG_SEQUENCE, &body);
        let sd = SignedData::parse(&sd_seq).expect("detached SignedData parses");
        assert!(sd.econtent_der.is_none());
    }

    // ----- SignedData::parse: structural rejection -----

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(
            SignedData::parse(b""),
            Err(CmsError::UnexpectedStructure("empty input"))
        ));
    }

    #[test]
    fn rejects_unknown_wrapper_tag() {
        let input = tlv(TAG_INTEGER, [VERSION_0]);
        assert!(matches!(
            SignedData::parse(&input),
            Err(CmsError::UnexpectedStructure("unknown wrapper tag"))
        ));
    }

    #[test]
    fn rejects_bytes_after_complete_cms_value() {
        let mut der = unhex(RSA_CMS_HEX);
        der.push(TRAILING_ZERO_BYTE);
        assert!(matches!(
            SignedData::parse(&der),
            Err(CmsError::UnexpectedStructure(
                "trailing bytes after CMS value"
            ))
        ));
    }

    #[test]
    fn requires_exactly_one_signer_info() {
        SignedData::parse(&minimal_signed_data(SIGNER_COUNT_ONE)).expect("one signer is accepted");
        assert!(matches!(
            SignedData::parse(&minimal_signed_data(SIGNER_COUNT_ZERO)),
            Err(CmsError::UnexpectedStructure("signerInfos is empty"))
        ));
        assert!(matches!(
            SignedData::parse(&minimal_signed_data(SIGNER_COUNT_TWO)),
            Err(CmsError::UnexpectedStructure(
                "SignedData must contain exactly one signerInfo"
            ))
        ));
    }

    #[test]
    fn rejects_signer_digest_absent_from_signed_data_set() {
        let sig_alg = alg_id_no_params(known::SHA256_WITH_RSA);
        let mismatched_signer = minimal_signer_info_with_algs(known::SHA384, &sig_alg);

        let mut encap = tlv(TAG_OID, known::DATA.as_bytes());
        encap.extend_from_slice(&tlv(TAG_CONTEXT_0, tlv(TAG_OCTET_STRING, b"content")));
        let mut body = tlv(TAG_INTEGER, [VERSION_1]);
        body.extend_from_slice(&tlv(TAG_SET, alg_id_no_params(known::SHA256)));
        body.extend_from_slice(&tlv(TAG_SEQUENCE, encap));
        body.extend_from_slice(&tlv(TAG_SET, mismatched_signer));

        assert!(matches!(
            SignedData::parse(&tlv(TAG_SEQUENCE, body)),
            Err(CmsError::UnexpectedStructure(
                "signer digestAlgorithm absent from SignedData set"
            ))
        ));
    }

    #[test]
    fn rejects_signer_identifier_version_mismatch() {
        let mut ski_v1_signer = tlv(TAG_INTEGER, [VERSION_1]);
        ski_v1_signer.extend_from_slice(&tlv(TAG_SUBJECT_KEY_ID, b"ski-bytes"));
        ski_v1_signer.extend_from_slice(&alg_id_no_params(known::SHA256));
        ski_v1_signer.extend_from_slice(&alg_id_no_params(known::SHA256_WITH_RSA));
        ski_v1_signer.extend_from_slice(&tlv(TAG_OCTET_STRING, b"signature"));

        let encap = tlv(TAG_SEQUENCE, tlv(TAG_OID, known::DATA.as_bytes()));
        let mut body = tlv(TAG_INTEGER, [VERSION_3]);
        body.extend_from_slice(&tlv(TAG_SET, alg_id_no_params(known::SHA256)));
        body.extend_from_slice(&encap);
        body.extend_from_slice(&tlv(TAG_SET, tlv(TAG_SEQUENCE, ski_v1_signer)));

        assert!(matches!(
            SignedData::parse(&tlv(TAG_SEQUENCE, body)),
            Err(CmsError::UnexpectedStructure(
                "subjectKeyIdentifier signerInfo version is not 3"
            ))
        ));
    }

    #[test]
    fn rejects_empty_sequence() {
        let input = tlv(TAG_SEQUENCE, b"");
        assert!(matches!(
            SignedData::parse(&input),
            Err(CmsError::UnexpectedStructure("empty"))
        ));
    }

    #[test]
    fn efsod_rejects_non_signeddata_contentinfo() {
        let mut ci_body = tlv(TAG_OID, known::RSA_ENCRYPTION.as_bytes());
        ci_body.extend_from_slice(&tlv(TAG_CONTEXT_0, tlv(TAG_SEQUENCE, b"")));
        let content_info = tlv(TAG_SEQUENCE, &ci_body);
        let ef_sod = tlv(TAG_EF_SOD, &content_info);
        assert!(matches!(
            SignedData::parse(&ef_sod),
            Err(CmsError::UnexpectedStructure("ContentInfo not SignedData"))
        ));
    }

    #[test]
    fn signed_attributes_require_unique_content_type_and_message_digest() {
        let content_type = attribute(known::CONTENT_TYPE, &tlv(TAG_OID, known::DATA.as_bytes()));
        let message_digest = attribute(
            known::MESSAGE_DIGEST,
            &tlv(TAG_OCTET_STRING, b"digest-bytes"),
        );

        let mut valid = content_type.clone();
        valid.extend_from_slice(&message_digest);
        let parsed = CmsHelpers::parse_attributes(&valid, true).expect("mandatory attrs present");
        assert_eq!(parsed, Some(known::DATA));

        assert!(matches!(
            CmsHelpers::parse_attributes(&content_type, true),
            Err(CmsError::UnexpectedStructure(
                "signedAttrs missing messageDigest"
            ))
        ));

        let mut duplicate = valid;
        duplicate.extend_from_slice(&message_digest);
        assert!(matches!(
            CmsHelpers::parse_attributes(&duplicate, true),
            Err(CmsError::UnexpectedStructure(
                "duplicate signed messageDigest attribute"
            ))
        ));
    }

    #[test]
    fn signed_attributes_reject_mismatched_content_type() {
        let mut attrs = attribute(known::CONTENT_TYPE, &tlv(TAG_OID, known::DATA.as_bytes()));
        attrs.extend_from_slice(&attribute(
            known::MESSAGE_DIGEST,
            &tlv(TAG_OCTET_STRING, b"digest-bytes"),
        ));

        let mut sid = tlv(TAG_SEQUENCE, b"");
        sid.extend_from_slice(&tlv(TAG_INTEGER, [SERIAL_ONE]));
        let mut signer = tlv(TAG_INTEGER, [VERSION_1]);
        signer.extend_from_slice(&tlv(TAG_SEQUENCE, sid));
        signer.extend_from_slice(&alg_id_no_params(known::SHA256));
        signer.extend_from_slice(&tlv(TAG_CONTEXT_0, attrs));
        signer.extend_from_slice(&alg_id_no_params(known::SHA256_WITH_RSA));
        signer.extend_from_slice(&tlv(TAG_OCTET_STRING, b"signature"));

        let encap = tlv(
            TAG_SEQUENCE,
            tlv(TAG_OID, known::ICAO_LDS_SECURITY_OBJECT.as_bytes()),
        );
        let mut body = tlv(TAG_INTEGER, [VERSION_1]);
        body.extend_from_slice(&tlv(TAG_SET, alg_id_no_params(known::SHA256)));
        body.extend_from_slice(&encap);
        body.extend_from_slice(&tlv(TAG_SET, tlv(TAG_SEQUENCE, signer)));

        assert!(matches!(
            SignedData::parse(&tlv(TAG_SEQUENCE, body)),
            Err(CmsError::UnexpectedStructure(
                "signed contentType does not match eContentType"
            ))
        ));
    }

    // ----- LdsSecurityObject::parse -----

    #[test]
    fn parses_lds_security_object_directly() {
        let der = unhex(RSA_CMS_HEX);
        let sd = SignedData::parse(&der).expect("parse");
        let lds = LdsSecurityObject::parse(sd.econtent_der.expect("attached")).expect("LDS parses");
        assert_eq!(lds.hash_algorithm, HashAlgorithm::Sha256);
        assert_eq!(lds.data_group_hashes.len(), EXPECTED_DG_COUNT);
        let mut dgs = lds.data_group_hashes.iter();
        let dg1 = dgs.next().expect("DG1");
        let dg2 = dgs.next().expect("DG2");
        assert_eq!(dg1.0, DG_NUMBER_1);
        assert_eq!(dg1.1, unhex(DG1_HASH_HEX).as_slice());
        assert_eq!(dg2.0, DG_NUMBER_2);
        assert_eq!(dg2.1, unhex(DG2_HASH_HEX).as_slice());
    }

    #[test]
    fn lds_rejects_unsupported_hash_algorithm() {
        let hash_alg = alg_id_no_params(known::SHA1);
        let dgh = tlv(TAG_SEQUENCE, b"");
        let mut body = tlv(TAG_INTEGER, [VERSION_0]);
        body.extend_from_slice(&hash_alg);
        body.extend_from_slice(&dgh);
        let lds = tlv(TAG_SEQUENCE, &body);
        assert!(matches!(
            LdsSecurityObject::parse(&lds),
            Err(CmsError::UnsupportedDigestAlgorithm)
        ));
    }

    // ----- OwnedSignedData -----

    #[test]
    fn owned_signed_data_roundtrips() {
        let der = unhex(RSA_CMS_HEX);
        let owned = OwnedSignedData::from_der(&der).expect("construct");
        assert_eq!(owned.as_der(), der.as_slice());
        let view = owned.view();
        assert_eq!(view.econtent_type_oid, known::ICAO_LDS_SECURITY_OBJECT);
        assert_eq!(view.certificates_der.len(), EXPECTED_EMBEDDED_CERTS);
    }

    #[test]
    fn owned_signed_data_rejects_invalid_der() {
        OwnedSignedData::from_der(b"not-cms-der").expect_err("non-DER bytes are rejected");
    }

    // ----- CmsError Display -----

    #[test]
    fn cms_error_display_strings() {
        assert_eq!(
            CmsError::from(crate::ber::BerError::Empty).to_string(),
            "CMS BER: BER: empty input"
        );
        assert_eq!(
            CmsError::UnexpectedStructure("bad shape").to_string(),
            "CMS: bad shape"
        );
        assert_eq!(
            CmsError::UnsupportedDigestAlgorithm.to_string(),
            "CMS: unsupported digest algorithm"
        );
    }
}
