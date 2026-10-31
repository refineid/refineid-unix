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

//! Verifying the `XAdES` signatures an `ASiC-E` or `BDOC` container
//! carries in `META-INF/*signatures*.xml`.
//!
//! Each `ds:Signature` is read once into the facts verification needs:
//! the canonical `ds:SignedInfo`, every `ds:Reference` with the octets
//! it digests, the signature value, the signer certificate and the
//! `SigningCertificate` digest that binds it, the signature timestamps
//! with the canonical `ds:SignatureValue` they imprint, and the
//! validation material in the unsigned properties. [`XadesSignature::verify`]
//! then judges them against the container's data files.
//!
//! Canonicalisation is [`crate::document::xml`]'s Exclusive XML
//! Canonicalization. [`crate::sign::xades`] writes its signed subtrees
//! already in that form; other producers do not, and are canonicalised
//! here before digesting. A signature whose `ds:SignedInfo` names
//! another canonicalisation is reported unsupported; a reference whose
//! transform is not exclusive canonicalisation cannot be recomputed and
//! leaves the document not intact.
//!
//! # Conformance
//!
//! - W3C XML Signature Syntax and Processing 1.1
//!   <https://www.w3.org/TR/xmldsig-core1/>: sec.3.2 core validation,
//!   sec.4.4 `SignedInfo`, sec.4.4.3 `Reference` and same-document
//!   URIs, sec.6.4 the `RSAwithSHA*` and `ECDSAwithSHA*` signature
//!   value forms.
//! - RFC 6931: the `xmldsig-more` digest and signature identifiers.
//! - `ETSI EN 319 132-1` V1.3.1: sec.4.3 the `SignedProperties`
//!   reference and its `Type`, sec.5.2.2 `SigningCertificateV2`,
//!   sec.5.3 `SignatureTimeStamp` over the canonicalised
//!   `ds:SignatureValue` element, sec.5.4 `CertificateValues` and
//!   `RevocationValues`, sec.5.5 `ArchiveTimeStamp`.
//! - `ETSI EN 319 162-1` V1.1.1 clause A.4: reference URIs resolve
//!   against the container root.

use crate::document::TimestampCheck;
use crate::document::asic::{AsicContainer, Entry, percent_decode};
use crate::document::xml::{Comments, ElementRef, XmlDocument, XmlError};
use crate::sign::asic::NAMESPACE_ASIC;
use crate::sign::cades::DigestAlgorithm;
use crate::sign::timestamp::{claimed_generation_time, verify_token};
use crate::sign::validation::ValidationMaterial;
use crate::sign::xades::NAMESPACE_DSIG;
use crate::x509::{DateTime, MessageSignatureAlgorithm, OwnedCert};

/// `XAdES` 1.3.2 namespace (`ETSI EN 319 132-1` sec.4.2).
const NAMESPACE_XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";

/// `XAdES` 1.4.1 namespace, home of `ArchiveTimeStamp` (`ETSI EN
/// 319 132-1` sec.4.2).
const NAMESPACE_XADES_141: &str = "http://uri.etsi.org/01903/v1.4.1#";

/// `Type` of the reference covering the signed properties (`ETSI EN
/// 319 132-1` sec.4.3.1).
const TYPE_SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";

/// Exclusive canonicalisation without comments (W3C xml-exc-c14n
/// sec.4).
const CANONICALIZATION_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Exclusive canonicalisation with comments (W3C xml-exc-c14n sec.4).
const CANONICALIZATION_EXCLUSIVE_COMMENTS: &str =
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

/// `SHA-1` digest identifier (XML Signature 1.1 sec.6.2.1), refused.
const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

/// `SHA-256` digest identifier (XML Signature 1.1 sec.6.2.2).
const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// `SHA-384` digest identifier (RFC 6931 sec.2.1.3).
const DIGEST_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";

/// `SHA-512` digest identifier (XML Signature 1.1 sec.6.2.4).
const DIGEST_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

/// RSA PKCS#1 v1.5 with SHA-256 (RFC 6931 sec.2.3.2).
const SIGNATURE_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// RSA PKCS#1 v1.5 with SHA-384 (RFC 6931 sec.2.3.2).
const SIGNATURE_RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

/// RSA PKCS#1 v1.5 with SHA-512 (RFC 6931 sec.2.3.2).
const SIGNATURE_RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

/// ECDSA with SHA-256 (RFC 6931 sec.2.3.6).
const SIGNATURE_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

/// ECDSA with SHA-384 (RFC 6931 sec.2.3.6).
const SIGNATURE_ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

/// ECDSA with SHA-512 (RFC 6931 sec.2.3.6).
const SIGNATURE_ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

/// The attribute every algorithm-naming element carries.
const ATTRIBUTE_ALGORITHM: &str = "Algorithm";

/// The identifier attribute of XML Signature and `XAdES` elements.
const ATTRIBUTE_ID: &str = "Id";

/// A reference's target.
const ATTRIBUTE_URI: &str = "URI";

/// A reference's declared type.
const ATTRIBUTE_TYPE: &str = "Type";

/// Marks a same-document reference (XML Signature 1.1 sec.4.4.3.3).
const FRAGMENT_MARK: char = '#';

/// The six bits one base64 character carries (RFC 4648 sec.4).
const BASE64_BITS: u32 = 6;

/// Bits in an octet.
const OCTET_BITS: u32 = 8;

/// The base64 alphabet (RFC 4648 sec.4 table 1).
const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The base64 pad character.
const BASE64_PAD: char = '=';

/// Characters in one base64 quantum.
const BASE64_QUANTUM: usize = 4;

/// The most pad characters a quantum ends with.
const BASE64_MAX_PADDING: usize = 2;

/// Why a signature file yielded no signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XadesReadError {
    /// The file is not XML this reader accepts.
    Xml(XmlError),
    /// The file holds no `ds:Signature`.
    NoSignature,
    /// A `ds:Signature` lacks a part every signature has.
    Malformed(&'static str),
}

impl core::fmt::Display for XadesReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Xml(error) => write!(f, "signature file: {error}"),
            Self::NoSignature => f.write_str("the signature file holds no signature"),
            Self::Malformed(what) => write!(f, "malformed XAdES signature: {what}"),
        }
    }
}

impl core::error::Error for XadesReadError {}

/// The digest algorithms a reference may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestMethod {
    /// `SHA-256`.
    Sha256,
    /// `SHA-384`.
    Sha384,
    /// `SHA-512`.
    Sha512,
}

impl DigestMethod {
    /// The method a `DigestMethod` `Algorithm` names; `None` for
    /// `SHA-1` and anything unknown.
    pub(crate) fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            DIGEST_SHA256 => Some(Self::Sha256),
            DIGEST_SHA384 => Some(Self::Sha384),
            DIGEST_SHA512 => Some(Self::Sha512),
            DIGEST_SHA1 => None,
            _ => None,
        }
    }

    /// The digest of `input`.
    pub(crate) fn digest(self, input: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Self::Sha256 => sha2::Sha256::digest(input).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(input).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(input).to_vec(),
        }
    }
}

/// The signature algorithm a `SignatureMethod` `Algorithm` names.
fn signature_method(uri: &str) -> Option<MessageSignatureAlgorithm> {
    match uri {
        SIGNATURE_RSA_SHA256 => Some(MessageSignatureAlgorithm::RsaPkcs1Sha256),
        SIGNATURE_RSA_SHA384 => Some(MessageSignatureAlgorithm::RsaPkcs1Sha384),
        SIGNATURE_RSA_SHA512 => Some(MessageSignatureAlgorithm::RsaPkcs1Sha512),
        SIGNATURE_ECDSA_SHA256 => Some(MessageSignatureAlgorithm::EcdsaSha256Raw),
        SIGNATURE_ECDSA_SHA384 => Some(MessageSignatureAlgorithm::EcdsaSha384Raw),
        SIGNATURE_ECDSA_SHA512 => Some(MessageSignatureAlgorithm::EcdsaSha512Raw),
        _ => None,
    }
}

/// The comment mode an exclusive canonicalisation identifier names;
/// `None` for every other canonicalisation.
fn exclusive_mode(uri: &str) -> Option<Comments> {
    match uri {
        CANONICALIZATION_EXCLUSIVE => Some(Comments::Omitted),
        CANONICALIZATION_EXCLUSIVE_COMMENTS => Some(Comments::Retained),
        _ => None,
    }
}

/// What a reference digests.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// A container entry, by its decoded name.
    DataFile(String),
    /// A same-document element, already canonicalised.
    Canonical(Vec<u8>),
    /// Nothing this verifier can recompute.
    Unresolvable,
}

/// One `ds:Reference`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reference {
    /// What it digests.
    target: Target,
    /// The digest algorithm, when one this verifier accepts.
    method: Option<DigestMethod>,
    /// The `DigestValue`.
    value: Vec<u8>,
    /// Whether it is the `SignedProperties` reference and resolves to
    /// this signature's own `xades:SignedProperties`.
    signed_properties: bool,
}

/// The `CertDigest` of `SigningCertificateV2` or `SigningCertificate`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CertDigest {
    /// The digest algorithm, when one this verifier accepts.
    method: Option<DigestMethod>,
    /// The `DigestValue`.
    value: Vec<u8>,
}

/// One `EncapsulatedTimeStamp` of a `SignatureTimeStamp`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SignatureTimestamp {
    /// The RFC 3161 token.
    token: Vec<u8>,
    /// The canonicalised `ds:SignatureValue` it must imprint; `None`
    /// when the timestamp names a canonicalisation other than
    /// exclusive.
    imprinted: Option<Vec<u8>>,
}

/// One `ds:Signature`, read into the facts verification needs.
#[derive(Debug, Clone)]
pub struct XadesSignature {
    /// The signer certificate.
    signer: OwnedCert,
    /// Every `X509Certificate` and `EncapsulatedX509Certificate`.
    embedded_certificates: Vec<Vec<u8>>,
    /// `CertificateValues` and `RevocationValues`.
    material: ValidationMaterial,
    /// Why the signature cannot be judged, when it cannot.
    unsupported: Option<&'static str>,
    /// The canonical `ds:SignedInfo`; empty when unsupported.
    signed_info: Vec<u8>,
    /// The signature algorithm, when one this verifier accepts.
    signature_method: Option<MessageSignatureAlgorithm>,
    /// The decoded `SignatureValue`.
    signature_value: Vec<u8>,
    /// Every `ds:Reference`, in order.
    references: Vec<Reference>,
    /// The `SigningCertificate` binding, when present.
    signing_certificate: Option<CertDigest>,
    /// Every `SignatureTimeStamp` token.
    signature_timestamps: Vec<SignatureTimestamp>,
    /// How many `ArchiveTimeStamp` elements are present.
    archive_timestamps: usize,
    /// The `SigningTime` signed property, when present and readable.
    signing_time: Option<DateTime>,
}

/// The verdict on one signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XadesVerdict {
    /// Every reference recomputed and matched, the `SignedProperties`
    /// reference among them, and every data file in the container
    /// covered by a reference.
    pub document_intact: bool,
    /// The signature value verifies over the canonical `ds:SignedInfo`
    /// under the signer certificate, and the signed properties carry a
    /// `SigningCertificateV2` or `SigningCertificate` whose digest
    /// matches that certificate. The property is mandatory at every
    /// baseline level (`ETSI EN 319 132-1` sec.5.2.2), so a signature
    /// without it is not valid.
    pub signature_valid: bool,
    /// Every `SignatureTimeStamp` token, checked against the canonical
    /// `ds:SignatureValue`, in document order.
    pub signature_timestamps: Vec<TimestampCheck>,
    /// How many `ArchiveTimeStamp` elements are present; they are not
    /// verified.
    pub archive_timestamps_present: usize,
}

/// Read every `ds:Signature` in a signature file: the root itself, or
/// the children of an `asic:XAdESSignatures` root.
///
/// # Errors
/// [`XadesReadError`] when the file is not accepted XML, holds no
/// signature, or a signature lacks `ds:SignedInfo`, a decodable
/// `ds:SignatureValue` or a parseable signer certificate.
pub fn signatures(file: &Entry) -> Result<Vec<XadesSignature>, XadesReadError> {
    let document = XmlDocument::parse(file.content.clone()).map_err(XadesReadError::Xml)?;
    let root = document.root();
    let elements: Vec<ElementRef<'_>> = if root.is(NAMESPACE_DSIG, "Signature") {
        vec![root]
    } else if root.is(NAMESPACE_ASIC, "XAdESSignatures") {
        root.children_named(NAMESPACE_DSIG, "Signature").collect()
    } else {
        Vec::new()
    };
    if elements.is_empty() {
        return Err(XadesReadError::NoSignature);
    }
    elements
        .into_iter()
        .map(|element| XadesSignature::read(&document, element))
        .collect()
}

impl XadesSignature {
    /// Read one `ds:Signature`.
    fn read(document: &XmlDocument, signature: ElementRef<'_>) -> Result<Self, XadesReadError> {
        let signed_info = signature
            .child(NAMESPACE_DSIG, "SignedInfo")
            .ok_or(XadesReadError::Malformed("no SignedInfo"))?;
        let signature_value_element = signature
            .child(NAMESPACE_DSIG, "SignatureValue")
            .ok_or(XadesReadError::Malformed("no SignatureValue"))?;
        let signature_value = decode_base64(&signature_value_element.text())
            .ok_or(XadesReadError::Malformed("SignatureValue is not base64"))?;

        let qualifying = signature
            .children_named(NAMESPACE_DSIG, "Object")
            .find_map(|object| object.child(NAMESPACE_XADES, "QualifyingProperties"));
        let signed_properties =
            qualifying.and_then(|properties| properties.child(NAMESPACE_XADES, "SignedProperties"));
        let unsigned = qualifying
            .and_then(|properties| properties.child(NAMESPACE_XADES, "UnsignedProperties"))
            .and_then(|properties| {
                properties.child(NAMESPACE_XADES, "UnsignedSignatureProperties")
            });

        let mut material = ValidationMaterial::default();
        let mut signature_timestamps = Vec::new();
        let mut archive_timestamps = 0_usize;
        if let Some(unsigned) = unsigned {
            read_unsigned(
                unsigned,
                signature_value_element,
                &mut material,
                &mut signature_timestamps,
            )?;
            archive_timestamps = unsigned
                .children()
                .filter(|child| {
                    child.is(NAMESPACE_XADES_141, "ArchiveTimeStamp")
                        || child.is(NAMESPACE_XADES, "ArchiveTimeStamp")
                })
                .count();
        }

        let signed_signature_properties = signed_properties
            .and_then(|properties| properties.child(NAMESPACE_XADES, "SignedSignatureProperties"));
        let signing_time = signed_signature_properties
            .and_then(|properties| properties.child(NAMESPACE_XADES, "SigningTime"))
            .and_then(|element| xml_date_time(&element.text()));
        let signing_certificate = signed_signature_properties
            .and_then(|properties| {
                properties
                    .child(NAMESPACE_XADES, "SigningCertificateV2")
                    .or_else(|| properties.child(NAMESPACE_XADES, "SigningCertificate"))
            })
            .map(read_cert_digest)
            .transpose()?;

        let key_info_certificates: Vec<Vec<u8>> = signature
            .child(NAMESPACE_DSIG, "KeyInfo")
            .into_iter()
            .flat_map(|key_info| key_info.children_named(NAMESPACE_DSIG, "X509Data"))
            .flat_map(|data| data.children_named(NAMESPACE_DSIG, "X509Certificate"))
            .map(|certificate| decode_base64(&certificate.text()))
            .collect::<Option<_>>()
            .ok_or(XadesReadError::Malformed("X509Certificate is not base64"))?;
        let signer = select_signer(
            &key_info_certificates,
            &material.certificates,
            signing_certificate.as_ref(),
        )?;
        let mut embedded_certificates = key_info_certificates;
        embedded_certificates.extend(material.certificates.iter().cloned());

        let method_of = |name: &'static str| {
            signed_info
                .child(NAMESPACE_DSIG, name)
                .and_then(|method| method.attribute(ATTRIBUTE_ALGORITHM))
        };
        let canonicalization = method_of("CanonicalizationMethod")
            .ok_or(XadesReadError::Malformed("no CanonicalizationMethod"))?;
        let signature_method = method_of("SignatureMethod").and_then(signature_method);
        let carries_prefix_list = signed_info
            .child(NAMESPACE_DSIG, "CanonicalizationMethod")
            .is_some_and(|method| method.children().next().is_some());
        let (unsupported, signed_info_bytes) = match exclusive_mode(canonicalization) {
            Some(_) if carries_prefix_list => (
                Some("InclusiveNamespaces PrefixList canonicalisation"),
                Vec::new(),
            ),
            Some(comments) => (None, signed_info.canonicalize(comments)),
            None => (Some("SignedInfo canonicalisation"), Vec::new()),
        };

        let references = signed_info
            .children_named(NAMESPACE_DSIG, "Reference")
            .map(|reference| read_reference(document, reference, signed_properties))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            signer,
            embedded_certificates,
            material,
            unsupported,
            signed_info: signed_info_bytes,
            signature_method,
            signature_value,
            references,
            signing_certificate,
            signature_timestamps,
            archive_timestamps,
            signing_time,
        })
    }

    /// The signer certificate: the `ds:KeyInfo` certificate the
    /// `SigningCertificate` digest names when one does, else the first
    /// `ds:KeyInfo` certificate.
    #[must_use]
    pub const fn signer_certificate(&self) -> &OwnedCert {
        &self.signer
    }

    /// The `SigningTime` signed property (`ETSI EN 319 132-1`
    /// sec.5.2.1), when present and readable.
    #[must_use]
    pub const fn signing_time(&self) -> Option<DateTime> {
        self.signing_time
    }

    /// Every `ds:X509Certificate`, then every `CertificateValues`
    /// certificate, as DER.
    #[must_use]
    pub fn embedded_certificates(&self) -> &[Vec<u8>] {
        &self.embedded_certificates
    }

    /// The `CertificateValues` certificates and the `RevocationValues`
    /// CRLs and OCSP responses.
    #[must_use]
    pub fn embedded_material(&self) -> ValidationMaterial {
        self.material.clone()
    }

    /// The profile feature this verifier does not implement, when the
    /// signature uses one; such a signature verifies as neither intact
    /// nor valid.
    #[must_use]
    pub const fn unsupported(&self) -> Option<&'static str> {
        self.unsupported
    }

    /// Judge the signature against `container`.
    #[must_use]
    pub fn verify(&self, container: &AsicContainer) -> XadesVerdict {
        let supported = self.unsupported.is_none();
        XadesVerdict {
            document_intact: supported && self.document_intact(container),
            signature_valid: supported && self.signature_valid(),
            signature_timestamps: self.timestamps(),
            archive_timestamps_present: self.archive_timestamps,
        }
    }

    /// Every reference matches, one covers the signed properties, and
    /// every data file is covered.
    fn document_intact(&self, container: &AsicContainer) -> bool {
        let every_reference_matches = !self.references.is_empty()
            && self.references.iter().all(|reference| {
                let Some(method) = reference.method else {
                    return false;
                };
                let computed = match &reference.target {
                    Target::DataFile(name) => match container.data_file(name) {
                        Some(entry) => method.digest(&entry.content),
                        None => return false,
                    },
                    Target::Canonical(octets) => method.digest(octets),
                    Target::Unresolvable => return false,
                };
                computed == reference.value
            });
        let properties_covered = self
            .references
            .iter()
            .any(|reference| reference.signed_properties);
        let files_covered = container.data_files().iter().all(|entry| {
            self.references
                .iter()
                .any(|reference| reference.target == Target::DataFile(entry.name.clone()))
        });
        every_reference_matches && properties_covered && files_covered
    }

    /// The signature verifies and the mandatory signer binding is
    /// present and holds (EN 319 132-1 sec.5.2.2).
    fn signature_valid(&self) -> bool {
        let Some(algorithm) = self.signature_method else {
            return false;
        };
        let verifies = self
            .signer
            .view()
            .spki
            .verify_message_signature(algorithm, &self.signed_info, &self.signature_value)
            .is_ok();
        let bound = self.signing_certificate.as_ref().is_some_and(|binding| {
            binding
                .method
                .is_some_and(|method| method.digest(self.signer.as_der()) == binding.value)
        });
        verifies && bound
    }

    /// Verify each `SignatureTimeStamp` token over the canonical
    /// `ds:SignatureValue`.
    fn timestamps(&self) -> Vec<TimestampCheck> {
        self.signature_timestamps
            .iter()
            .map(|timestamp| {
                timestamp
                    .imprinted
                    .as_deref()
                    .and_then(|imprinted| {
                        verify_token(&timestamp.token, |algorithm: DigestAlgorithm| {
                            algorithm.digest(imprinted)
                        })
                        .ok()
                    })
                    .map_or_else(
                        || TimestampCheck::Unverified {
                            claimed_at: claimed_generation_time(&timestamp.token),
                        },
                        TimestampCheck::Verified,
                    )
            })
            .collect()
    }
}

/// An `xsd:dateTime` (XML Schema Part 2 sec.3.2.7) with a time zone,
/// as UTC: `YYYY-MM-DDThh:mm:ss`, optional fractional seconds, then
/// `Z` or an offset `+hh:mm` / `-hh:mm`. Fractional seconds are
/// dropped; a value without a time zone names no instant and yields
/// `None`.
fn xml_date_time(text: &str) -> Option<DateTime> {
    /// Separator of date and time.
    const DATE_TIME_SEPARATOR: char = 'T';
    /// Separator of the date fields.
    const DATE_SEPARATOR: char = '-';
    /// Separator of the clock fields and of the offset's.
    const CLOCK_SEPARATOR: char = ':';
    /// Start of fractional seconds.
    const FRACTION_SEPARATOR: char = '.';
    /// The UTC time zone designator.
    const UTC_DESIGNATOR: char = 'Z';
    /// Seconds in a minute.
    const SECONDS_PER_MINUTE: u64 = 60;
    /// Minutes in an hour.
    const MINUTES_PER_HOUR: u64 = 60;

    /// Exactly three fields separated by `separator`.
    fn three<T: core::str::FromStr>(text: &str, separator: char) -> Option<(T, T, T)> {
        let mut fields = text.split(separator);
        let first = fields.next()?.parse().ok()?;
        let second = fields.next()?.parse().ok()?;
        let third = fields.next()?.parse().ok()?;
        fields.next().is_none().then_some((first, second, third))
    }

    let text = text.trim();
    let (date, time) = text.split_once(DATE_TIME_SEPARATOR)?;
    let (year, month, day): (u16, u16, u16) = three(date, DATE_SEPARATOR)?;
    let (month, day) = (u8::try_from(month).ok()?, u8::try_from(day).ok()?);
    let (clock, east_of_utc, offset) = if let Some(clock) = time.strip_suffix(UTC_DESIGNATOR) {
        (clock, true, None)
    } else {
        let at = time.rfind(['+', '-'])?;
        let (clock, zone) = time.split_at(at);
        let east = zone.starts_with('+');
        let (hours, minutes) = zone.get(1..)?.split_once(CLOCK_SEPARATOR)?;
        let hours: u64 = hours.parse().ok()?;
        let minutes: u64 = minutes.parse().ok()?;
        let seconds = hours
            .checked_mul(MINUTES_PER_HOUR)?
            .checked_add(minutes)?
            .checked_mul(SECONDS_PER_MINUTE)?;
        (clock, east, Some(core::time::Duration::from_secs(seconds)))
    };
    let whole = clock
        .split_once(FRACTION_SEPARATOR)
        .map_or(clock, |(whole, _fraction)| whole);
    let (hour, minute, second): (u8, u8, u8) = three(whole, CLOCK_SEPARATOR)?;
    let local = DateTime::new(year, month, day, hour, minute, second).ok()?;
    let Some(offset) = offset else {
        return Some(local);
    };
    let local = local.unix_duration();
    let utc = if east_of_utc {
        local.checked_sub(offset)?
    } else {
        local.checked_add(offset)?
    };
    DateTime::from_unix_duration(utc).ok()
}

/// Read `xades:UnsignedSignatureProperties`: the signature timestamps
/// and the validation material.
fn read_unsigned(
    unsigned: ElementRef<'_>,
    signature_value: ElementRef<'_>,
    material: &mut ValidationMaterial,
    timestamps: &mut Vec<SignatureTimestamp>,
) -> Result<(), XadesReadError> {
    /// Decode every child `name` of `parent` as base64.
    fn encapsulated(
        parent: ElementRef<'_>,
        name: &'static str,
    ) -> Result<Vec<Vec<u8>>, XadesReadError> {
        parent
            .children_named(NAMESPACE_XADES, name)
            .map(|value| decode_base64(&value.text()))
            .collect::<Option<_>>()
            .ok_or(XadesReadError::Malformed(
                "encapsulated value is not base64",
            ))
    }

    for timestamp in unsigned.children_named(NAMESPACE_XADES, "SignatureTimeStamp") {
        // Without a CanonicalizationMethod the XML Signature default,
        // inclusive Canonical XML 1.0, applies (EN 319 132-1 sec.5.3),
        // which this verifier does not compute.
        let method = timestamp.child(NAMESPACE_DSIG, "CanonicalizationMethod");
        let comments = method
            .filter(|method| method.children().next().is_none())
            .and_then(|method| method.attribute(ATTRIBUTE_ALGORITHM))
            .and_then(exclusive_mode);
        let imprinted = comments.map(|comments| signature_value.canonicalize(comments));
        for token in encapsulated(timestamp, "EncapsulatedTimeStamp")? {
            timestamps.push(SignatureTimestamp {
                token,
                imprinted: imprinted.clone(),
            });
        }
    }
    for values in unsigned.children_named(NAMESPACE_XADES, "CertificateValues") {
        material
            .certificates
            .extend(encapsulated(values, "EncapsulatedX509Certificate")?);
    }
    for values in unsigned.children_named(NAMESPACE_XADES, "RevocationValues") {
        for crls in values.children_named(NAMESPACE_XADES, "CRLValues") {
            material
                .crls
                .extend(encapsulated(crls, "EncapsulatedCRLValue")?);
        }
        for responses in values.children_named(NAMESPACE_XADES, "OCSPValues") {
            material
                .ocsp_responses
                .extend(encapsulated(responses, "EncapsulatedOCSPValue")?);
        }
    }
    Ok(())
}

/// Read the first `xades:Cert/xades:CertDigest` of a signing
/// certificate property: in `SigningCertificateV2` and
/// `SigningCertificate` alike the first `Cert` names the signer.
fn read_cert_digest(property: ElementRef<'_>) -> Result<CertDigest, XadesReadError> {
    let digest = property
        .child(NAMESPACE_XADES, "Cert")
        .and_then(|cert| cert.child(NAMESPACE_XADES, "CertDigest"))
        .ok_or(XadesReadError::Malformed(
            "SigningCertificate without CertDigest",
        ))?;
    let method = digest
        .child(NAMESPACE_DSIG, "DigestMethod")
        .and_then(|method| method.attribute(ATTRIBUTE_ALGORITHM))
        .and_then(DigestMethod::from_uri);
    let value = digest
        .child(NAMESPACE_DSIG, "DigestValue")
        .and_then(|value| decode_base64(&value.text()))
        .ok_or(XadesReadError::Malformed(
            "CertDigest without a DigestValue",
        ))?;
    Ok(CertDigest { method, value })
}

/// Pick the signer: the candidate the binding digest names, else the
/// first `ds:KeyInfo` certificate.
fn select_signer(
    key_info: &[Vec<u8>],
    certificate_values: &[Vec<u8>],
    binding: Option<&CertDigest>,
) -> Result<OwnedCert, XadesReadError> {
    let named = binding.and_then(|binding| {
        let method = binding.method?;
        key_info
            .iter()
            .chain(certificate_values)
            .find(|der| method.digest(der) == binding.value)
    });
    let der = named
        .or_else(|| key_info.first())
        .ok_or(XadesReadError::Malformed(
            "no signer certificate in KeyInfo",
        ))?;
    OwnedCert::from_der(der)
        .map_err(|_ignored| XadesReadError::Malformed("signer certificate does not parse"))
}

/// Read one `ds:Reference` into what it digests.
fn read_reference(
    document: &XmlDocument,
    reference: ElementRef<'_>,
    signed_properties: Option<ElementRef<'_>>,
) -> Result<Reference, XadesReadError> {
    let method = reference
        .child(NAMESPACE_DSIG, "DigestMethod")
        .and_then(|method| method.attribute(ATTRIBUTE_ALGORITHM))
        .and_then(DigestMethod::from_uri);
    let value = reference
        .child(NAMESPACE_DSIG, "DigestValue")
        .and_then(|value| decode_base64(&value.text()))
        .ok_or(XadesReadError::Malformed("Reference without a DigestValue"))?;
    let uri = reference.attribute(ATTRIBUTE_URI).unwrap_or_default();
    let claims_properties = reference.attribute(ATTRIBUTE_TYPE) == Some(TYPE_SIGNED_PROPERTIES);

    // Each transform must be exclusive canonicalisation without a
    // prefix list; anything else is not recomputed.
    let transforms: Vec<ElementRef<'_>> = reference
        .child(NAMESPACE_DSIG, "Transforms")
        .into_iter()
        .flat_map(|transforms| transforms.children())
        .collect();
    let transforms_exclusive = transforms.iter().all(|transform| {
        transform.is(NAMESPACE_DSIG, "Transform")
            && transform.children().next().is_none()
            && transform
                .attribute(ATTRIBUTE_ALGORITHM)
                .and_then(exclusive_mode)
                .is_some()
    });

    let mut resolves_to_properties = false;
    let target = if let Some(id) = uri.strip_prefix(FRAGMENT_MARK) {
        // A bare-name reference `#id` yields the element's subtree with
        // every comment node deleted (XML Signature 1.1 sec.4.4.3.3),
        // so a `WithComments` transform after it has no comment to
        // keep; only `#xpointer(id('id'))` retains them, and that form
        // does not resolve here. Without a transform the node set would
        // be serialised by inclusive Canonical XML.
        let mut matches = document
            .elements()
            .filter(|element| element.attribute(ATTRIBUTE_ID) == Some(id));
        match (matches.next(), matches.next()) {
            (Some(element), None) if !transforms.is_empty() && transforms_exclusive => {
                resolves_to_properties = signed_properties == Some(element);
                if claims_properties && !resolves_to_properties {
                    Target::Unresolvable
                } else {
                    Target::Canonical(element.canonicalize(Comments::Omitted))
                }
            }
            _ => Target::Unresolvable,
        }
    } else if uri.is_empty() || !transforms.is_empty() || claims_properties {
        Target::Unresolvable
    } else {
        Target::DataFile(percent_decode(uri).unwrap_or_else(|| uri.to_owned()))
    };
    Ok(Reference {
        target,
        method,
        value,
        signed_properties: claims_properties && resolves_to_properties,
    })
}

/// Decode `xsd:base64Binary` text: the RFC 4648 sec.4 alphabet with
/// padding, XML whitespace between characters allowed. `None` for any
/// other character, misplaced padding or a truncated quantum.
pub(crate) fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let characters: Vec<char> = text
        .chars()
        .filter(|character| !matches!(character, ' ' | '\t' | '\n' | '\r'))
        .collect();
    if !characters.len().is_multiple_of(BASE64_QUANTUM) {
        return None;
    }
    let padding = characters
        .iter()
        .rev()
        .take_while(|character| **character == BASE64_PAD)
        .count();
    if padding > BASE64_MAX_PADDING {
        return None;
    }
    let body = characters.get(..characters.len().saturating_sub(padding))?;
    let mut out = Vec::with_capacity(body.len());
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    for character in body {
        let value = BASE64_ALPHABET
            .iter()
            .position(|symbol| char::from(*symbol) == *character)?;
        accumulator = (accumulator << BASE64_BITS) | u32::try_from(value).ok()?;
        bits = bits.saturating_add(BASE64_BITS);
        if bits >= OCTET_BITS {
            bits = bits.saturating_sub(OCTET_BITS);
            out.push(u8::try_from((accumulator >> bits) & u32::from(u8::MAX)).ok()?);
        }
    }
    // The bits left over are padding and must be zero (RFC 4648
    // sec.3.5).
    if accumulator & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{
        CANONICALIZATION_EXCLUSIVE, NAMESPACE_DSIG, NAMESPACE_XADES, XadesSignature, XadesVerdict,
        decode_base64, signatures,
    };
    use crate::base64;
    use crate::ber::tlv;
    use crate::document::DocumentFile;
    use crate::document::TimestampCheck;
    use crate::document::asic::{AsicContainer, Entry};
    use crate::document::trust::testkit::{
        CONTEXT_0, CertificateSpec, Curve, INTEGER, NULL, OBJECT_IDENTIFIER, OCTET_STRING,
        SEQUENCE, SET, TestKey, bit_string, certificate, day, generalized_time, name,
        timestamping_extensions, utc_time,
    };
    use crate::document::xml::{Comments, XmlDocument};
    use crate::oid::known;
    use crate::sign::asic::{DataObject, xades_container};
    use crate::sign::cades::{DigestAlgorithm, SignatureAlgorithm, SignerParameters, SigningTime};
    use crate::sign::validation::ValidationMaterial;
    use crate::sign::xades::{SignaturePlan, ecdsa_signature_to_xml, plan};
    use crate::x509::{Certificate, DateTime};
    use ring::rand::SystemRandom;
    use ring::signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};

    /// A 2048-bit RSA key in PKCS#8, generated locally for these tests
    /// with `openssl genpkey -algorithm RSA`. It names no one.
    const RSA_TEST_KEY_PKCS8: &str = "\
        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDa83spMsbxaNMs\
        GACrb5eWWRbQGKi02RtTsM1bX8rzymVl6VbXTe6ZWIOtDTjV0FaXb6rktpGRcVQO\
        1B6PJ/6yGk/Z+Q9oUI1Ph6JhLmihw3fANUu+Nlt27tuRuS5trR1sXDgu52VW07iq\
        0n1rMsVnhcUlfyvhT9HaAGzl8Ap6vnQeTpug+Wx9YS1+D053ORcAN/+YUCMDQuC8\
        0u/QIurMBhMEvVDkZ19YdB0Yjdm7B4y7u1gCB99RYo8kwl/hct58tOO0EGgWx1wq\
        ghzbe9892yNyzqDz+u4MlEjynfo7OgelvcP5p77i8VoFEvgCa+rnAx54FmWQNo+E\
        +GhZrgP9AgMBAAECggEAJT1r6YAyL63DWxjTBlWi3AbXlznWefoCSJwF9aBnocr/\
        L5P+Of0Ok8TnEogw7kby72tmDuQRgsIaiLIh53nnO0433ixbJ0QqIMiCQRK2Z6sa\
        I1Y9RYMzz9kE/fZX8/4RhtRxluKzDQ9SNbW68MBwLHEnbL8CTN55ZCGV5A8NjT4m\
        TgEsF3UPTJuoO76Rk07m+6I1wjzNx7KAXIDhuMZfRWp3Lin55MbB1lnC7OV0uW04\
        uWk0PhFf7JXzMg/rOQ3inlDnISUA6vztX9jnyOFS1QoTKvrKeVLrIJltdenjTCXg\
        RT6gqn3GkhfdGv/IQ4Ed5GRz258Mp+R1VuEkjuXwSQKBgQD7YZGlxKjth0GOU7Nx\
        3yIgOzfTqW7jNauMWv+4qhiXvhmqtJK0mlHoKlMtKOFCGdNM6tWWtpNA8jia9Ruf\
        F++JKuKhbL85Ao2uytdq4zSuGxGPpEbXqHwqS0kMjXrbKGIWKRwSm+neP/aOhrwZ\
        T4tQbxqgmUgo9Zw51IWj2o/9WQKBgQDe+V6qBdWHPh+9fqlL/UkfGPvv0egKhuN3\
        qIbu7Wc3ad0fBNPZHZygJNed205HPR44mf4LTxrAZbNgwONKobirKzzFs80hvFqa\
        RtEHWiQST/43mfYflpj54uRy3n6qhMURHUz6Ul506Qo8Na6irl4B+MI08GTrEatR\
        mWbpodYzRQKBgB3rJuKL3W8nwe2mmJzc6brcUXCnocL5CEnUKstXs0WcIoHmq+9C\
        zqzLHMsrKmQrnrJw4KrnX+9C5OnMclUlDCVPLVn5D2lBnItJKQpXsFVoc1adPrE8\
        JEsEWtVboVukGsh4bBbq55LEGhwsfQamKPaRwqGKnMQDN2zKln1B7hFBAoGAYB/H\
        JKshM42fp1ScbYsC4+okam3mh+tA0swPZ59m+OelkQLGxXnTlOJtJbtukp2Rkrso\
        Xv26PalaXGKrWfhAIWKhb2WlEF8f/BR9dprwpAhiQtwX0+RbjJa4/6BVoPNd9ZPZ\
        JK0v1VzFsdE+uRlMo7L3HlVoXEKgxavJRv0i17UCgYA4GrKCC5yuSLy6jGm0q4sY\
        BT1tKFCMOchzFRdq8AH81MAA+Na4V7iAPrjWE99kJJQclZXrh3qfszBJgY3hybPx\
        GG4S8sTIENAHd/TIA0FNh8dK0UNsYOa4REwLuVId2ZBbbgpj3pjfbQmkJ584Dp7q\
        b9AP1fAjJJG2KN3U6mEzFw==\
    ";

    /// Field width of a P-256 coordinate (SEC 1 sec.2.3.5).
    const P256_COORDINATE_LEN: usize = 32;

    /// X.509 `Version` v3, INTEGER 2 (RFC 5280 sec.4.1).
    const X509_VERSION_3: u8 = 0x02;

    /// `TSTInfo` and `SignerInfo` version 1 (RFC 3161 sec.2.4.2, RFC
    /// 5652 sec.5.3).
    const VERSION_1: u8 = 0x01;

    /// `SignedData` version 3, for an `eContentType` other than
    /// `id-data` (RFC 5652 sec.5.1).
    const SIGNED_DATA_VERSION_3: u8 = 0x03;

    /// The timestamp policy of the synthetic authority: `anyPolicy`
    /// (RFC 5280 sec.4.2.1.4).
    const TEST_POLICY: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("2.5.29.32.0");

    /// Serial numbers of the synthetic certificates.
    const SIGNER_SERIAL: u8 = 0x11;
    /// See [`SIGNER_SERIAL`].
    const OTHER_SERIAL: u8 = 0x12;
    /// See [`SIGNER_SERIAL`].
    const TSA_SERIAL: u8 = 0x21;
    /// See [`SIGNER_SERIAL`].
    const TOKEN_SERIAL: u8 = 0x31;

    /// Day certificates start, day the timestamp is made, day they end.
    const FIRST_DAY: u8 = 1;
    /// See [`FIRST_DAY`].
    const STAMP_DAY: u8 = 15;
    /// See [`FIRST_DAY`].
    const LAST_DAY: u8 = 28;

    const SIGNER_NAME: &str = "Synthetic Signer";
    const OTHER_NAME: &str = "Synthetic Other Signer";
    const TSA_NAME: &str = "Synthetic Time Stamp Authority";

    /// A signing key, ECDSA from the shared test kit or the RSA key
    /// above.
    enum Signer {
        Ecdsa(TestKey),
        Rsa(RsaKeyPair),
    }

    impl Signer {
        fn rsa() -> Self {
            let der = decode_base64(RSA_TEST_KEY_PKCS8).expect("key fixture is base64");
            Self::Rsa(RsaKeyPair::from_pkcs8(&der).expect("key fixture loads"))
        }

        /// A signature in the XML Signature form.
        fn sign_xml(&self, message: &[u8]) -> Vec<u8> {
            match self {
                Self::Ecdsa(key) => ecdsa_signature_to_xml(&key.sign(message), P256_COORDINATE_LEN)
                    .expect("P-256 signature"),
                Self::Rsa(key) => rsa_sign(key, message),
            }
        }

        const fn algorithm(&self) -> SignatureAlgorithm {
            match self {
                Self::Ecdsa(_) => SignatureAlgorithm::EcdsaSha256,
                Self::Rsa(_) => SignatureAlgorithm::RsaPkcs1Sha256,
            }
        }

        /// A self-issued certificate for the key.
        fn certificate(&self, serial: u8, subject: &str) -> Vec<u8> {
            match self {
                Self::Ecdsa(key) => certificate(
                    &CertificateSpec {
                        serial,
                        subject,
                        issuer: subject,
                        not_before: day(FIRST_DAY),
                        not_after: day(LAST_DAY),
                        extensions: Vec::new(),
                    },
                    key,
                    key,
                ),
                Self::Rsa(key) => rsa_certificate(key, serial, subject),
            }
        }
    }

    fn rsa_sign(key: &RsaKeyPair, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0; key.public().modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            message,
            &mut signature,
        )
        .expect("RSA signs");
        signature
    }

    /// `AlgorithmIdentifier { oid, NULL }`.
    fn algorithm_with_null(oid: crate::oid::Oid<'_>) -> Vec<u8> {
        let mut body = tlv(OBJECT_IDENTIFIER, oid.as_bytes());
        body.extend_from_slice(&tlv(NULL, []));
        tlv(SEQUENCE, body)
    }

    fn rsa_certificate(key: &RsaKeyPair, serial: u8, subject: &str) -> Vec<u8> {
        let mut spki = algorithm_with_null(known::RSA_ENCRYPTION);
        spki.extend_from_slice(&bit_string(key.public_key().as_ref()));
        let mut tbs = tlv(CONTEXT_0, tlv(INTEGER, [X509_VERSION_3]));
        tbs.extend_from_slice(&tlv(INTEGER, [serial]));
        tbs.extend_from_slice(&algorithm_with_null(known::SHA256_WITH_RSA));
        tbs.extend_from_slice(&name(subject));
        let mut validity = utc_time(day(FIRST_DAY));
        validity.extend_from_slice(&utc_time(day(LAST_DAY)));
        tbs.extend_from_slice(&tlv(SEQUENCE, validity));
        tbs.extend_from_slice(&name(subject));
        tbs.extend_from_slice(&tlv(SEQUENCE, spki));
        let tbs = tlv(SEQUENCE, tbs);
        let mut body = tbs.clone();
        body.extend_from_slice(&algorithm_with_null(known::SHA256_WITH_RSA));
        body.extend_from_slice(&bit_string(&rsa_sign(key, &tbs)));
        tlv(SEQUENCE, body)
    }

    /// A Time Stamp Authority: its key and certificate.
    struct Tsa {
        key: TestKey,
        certificate: Vec<u8>,
    }

    impl Tsa {
        fn new() -> Self {
            let key = TestKey::generate(Curve::P256);
            let certificate = certificate(
                &CertificateSpec {
                    serial: TSA_SERIAL,
                    subject: TSA_NAME,
                    issuer: TSA_NAME,
                    not_before: day(FIRST_DAY),
                    not_after: day(LAST_DAY),
                    extensions: timestamping_extensions(),
                },
                &key,
                &key,
            );
            Self { key, certificate }
        }

        /// An RFC 3161 `TimeStampToken` over `imprinted`, made at
        /// `generated`: `TSTInfo` signed with `contentType`,
        /// `messageDigest` and `signingCertificateV2` (RFC 3161
        /// sec.2.4.2, RFC 5035 sec.3).
        fn token(&self, imprinted: &[u8], generated: DateTime) -> Vec<u8> {
            let digest = DigestAlgorithm::Sha256;
            let mut imprint = digest.algorithm_identifier();
            imprint.extend_from_slice(&tlv(OCTET_STRING, digest.digest(imprinted)));
            let mut tst_info = tlv(INTEGER, [VERSION_1]);
            tst_info.extend_from_slice(&tlv(OBJECT_IDENTIFIER, TEST_POLICY.as_bytes()));
            tst_info.extend_from_slice(&tlv(SEQUENCE, imprint));
            tst_info.extend_from_slice(&tlv(INTEGER, [TOKEN_SERIAL]));
            tst_info.extend_from_slice(&generalized_time(generated));
            let tst_info = tlv(SEQUENCE, tst_info);

            let attribute = |oid: crate::oid::Oid<'_>, value: Vec<u8>| {
                let mut body = tlv(OBJECT_IDENTIFIER, oid.as_bytes());
                body.extend_from_slice(&tlv(SET, value));
                tlv(SEQUENCE, body)
            };
            let ess_cert_id = tlv(
                SEQUENCE,
                tlv(OCTET_STRING, digest.digest(&self.certificate)),
            );
            let mut attributes = attribute(
                known::CONTENT_TYPE,
                tlv(OBJECT_IDENTIFIER, known::TST_INFO.as_bytes()),
            );
            attributes.extend_from_slice(&attribute(
                known::MESSAGE_DIGEST,
                tlv(OCTET_STRING, digest.digest(&tst_info)),
            ));
            attributes.extend_from_slice(&attribute(
                known::SIGNING_CERTIFICATE_V2,
                tlv(SEQUENCE, tlv(SEQUENCE, ess_cert_id)),
            ));

            let mut issuer_and_serial = name(TSA_NAME);
            issuer_and_serial.extend_from_slice(&tlv(INTEGER, [TSA_SERIAL]));
            let mut signer_info = tlv(INTEGER, [VERSION_1]);
            signer_info.extend_from_slice(&tlv(SEQUENCE, issuer_and_serial));
            signer_info.extend_from_slice(&digest.algorithm_identifier());
            signer_info.extend_from_slice(&tlv(CONTEXT_0, &attributes));
            signer_info.extend_from_slice(&self.key.algorithm_identifier());
            signer_info
                .extend_from_slice(&tlv(OCTET_STRING, self.key.sign(&tlv(SET, &attributes))));

            let mut encapsulated = tlv(OBJECT_IDENTIFIER, known::TST_INFO.as_bytes());
            encapsulated.extend_from_slice(&tlv(CONTEXT_0, tlv(OCTET_STRING, tst_info)));
            let mut signed_data = tlv(INTEGER, [SIGNED_DATA_VERSION_3]);
            signed_data.extend_from_slice(&tlv(SET, digest.algorithm_identifier()));
            signed_data.extend_from_slice(&tlv(SEQUENCE, encapsulated));
            signed_data.extend_from_slice(&tlv(CONTEXT_0, &self.certificate));
            signed_data.extend_from_slice(&tlv(SET, tlv(SEQUENCE, signer_info)));
            let mut content_info = tlv(OBJECT_IDENTIFIER, known::SIGNED_DATA.as_bytes());
            content_info.extend_from_slice(&tlv(CONTEXT_0, tlv(SEQUENCE, signed_data)));
            tlv(SEQUENCE, content_info)
        }
    }

    fn objects() -> Vec<DataObject> {
        vec![
            DataObject {
                name: "dossier.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: b"a declaration of a means of cryptology".to_vec(),
            },
            DataObject {
                name: "annex one.txt".to_owned(),
                mime_type: "text/plain".to_owned(),
                content: b"annex, completed and signed".to_vec(),
            },
        ]
    }

    fn signing_time() -> SigningTime {
        SigningTime {
            year: 2026,
            month: 6,
            day: STAMP_DAY,
            hour: 12,
            minute: 0,
            second: 0,
        }
    }

    /// What one signing produced.
    struct Signed {
        plan: SignaturePlan,
        signature: Vec<u8>,
        certificate: Vec<u8>,
    }

    impl Signed {
        /// Sign `objects` with `signer` through the repository's writer.
        fn new(signer: &Signer, objects: &[DataObject]) -> Self {
            let certificate = signer.certificate(SIGNER_SERIAL, SIGNER_NAME);
            let parsed = Certificate::from_der(&certificate).expect("certificate parses");
            let parameters = SignerParameters {
                certificate: &parsed,
                digest_algorithm: DigestAlgorithm::Sha256,
                signature_algorithm: signer.algorithm(),
                signing_time: Some(signing_time()),
            };
            let plan = plan(objects, &parameters).expect("plan");
            let signature = signer.sign_xml(plan.signed_info());
            Self {
                plan,
                signature,
                certificate,
            }
        }

        fn document(&self, timestamps: &[Vec<u8>]) -> String {
            String::from_utf8(self.plan.finish(
                &self.signature,
                timestamps,
                &ValidationMaterial::default(),
            ))
            .expect("utf-8")
        }
    }

    /// Put `signature_xml` into a container with `objects` and read
    /// back its one signature.
    fn container_and_signature(
        objects: &[DataObject],
        signature_xml: &str,
    ) -> (AsicContainer, XadesSignature) {
        let archive = xades_container(objects, signature_xml.as_bytes()).expect("fits");
        let container =
            AsicContainer::parse(&DocumentFile::from_file(archive)).expect("container reads");
        let [file] = container.xades_signature_files() else {
            panic!("one signature file");
        };
        let mut read = signatures(file).expect("signature file reads");
        assert_eq!(read.len(), 1);
        let signature = read.remove(0);
        (container, signature)
    }

    fn verdict(objects: &[DataObject], signature_xml: &str) -> XadesVerdict {
        let (container, signature) = container_and_signature(objects, signature_xml);
        signature.verify(&container)
    }

    #[test]
    fn an_xml_date_time_reads_as_utc() {
        /// Noon UTC on [`STAMP_DAY`].
        const UTC: &str = "2026-06-15T12:00:00Z";
        /// The same instant two hours east of UTC, with a fraction.
        const EAST: &str = "2026-06-15T14:00:00.250+02:00";
        /// The same instant three hours west of UTC.
        const WEST: &str = "2026-06-15T09:00:00-03:00";
        /// No time zone: no instant.
        const FLOATING: &str = "2026-06-15T12:00:00";
        let noon = day(STAMP_DAY);
        assert_eq!(super::xml_date_time(UTC), Some(noon));
        assert_eq!(super::xml_date_time(EAST), Some(noon));
        assert_eq!(super::xml_date_time(WEST), Some(noon));
        assert_eq!(super::xml_date_time(FLOATING), None);
    }

    #[test]
    fn our_rsa_signature_is_intact_and_valid() {
        let signed = Signed::new(&Signer::rsa(), &objects());
        let (container, signature) = container_and_signature(&objects(), &signed.document(&[]));
        assert_eq!(signature.unsupported(), None);
        assert_eq!(signature.signer_certificate().as_der(), signed.certificate);
        assert_eq!(
            signature.embedded_certificates(),
            core::slice::from_ref(&signed.certificate)
        );
        let verdict = signature.verify(&container);
        assert!(verdict.document_intact);
        assert!(verdict.signature_valid);
        assert!(verdict.signature_timestamps.is_empty());
        assert_eq!(verdict.archive_timestamps_present, 0);
    }

    #[test]
    fn our_ecdsa_signature_is_intact_and_valid() {
        let signer = Signer::Ecdsa(TestKey::generate(Curve::P256));
        let signed = Signed::new(&signer, &objects());
        let verdict = verdict(&objects(), &signed.document(&[]));
        assert!(verdict.document_intact);
        assert!(verdict.signature_valid);
    }

    #[test]
    fn a_modified_data_file_breaks_the_document() {
        let signed = Signed::new(&Signer::rsa(), &objects());
        let mut changed = objects();
        changed[0].content = b"a different declaration".to_vec();
        let verdict = verdict(&changed, &signed.document(&[]));
        assert!(!verdict.document_intact);
        assert!(verdict.signature_valid, "the signature itself is untouched");
    }

    #[test]
    fn an_unreferenced_data_file_breaks_the_document() {
        let signed = Signed::new(&Signer::rsa(), &objects());
        let mut extended = objects();
        extended.push(DataObject {
            name: "smuggled.txt".to_owned(),
            mime_type: "text/plain".to_owned(),
            content: b"not signed".to_vec(),
        });
        assert!(!verdict(&extended, &signed.document(&[])).document_intact);
    }

    #[test]
    fn removed_signed_properties_break_the_document() {
        let signed = Signed::new(&Signer::rsa(), &objects());
        let document = signed.document(&[]);
        let start = document
            .find("<xades:SignedProperties")
            .expect("signed properties");
        let end_tag = "</xades:SignedProperties>";
        let end = document.find(end_tag).expect("end tag") + end_tag.len();
        let stripped = format!("{}{}", &document[..start], &document[end..]);
        let verdict = verdict(&objects(), &stripped);
        assert!(!verdict.document_intact);
    }

    /// Rewrite `document`'s signed subtrees and sign again: `properties`
    /// edits the `SignedProperties` text, `signed_info` the `SignedInfo`
    /// text; the `SignedProperties` digest and the signature value are
    /// recomputed, so only the edits differ from a genuine signature.
    fn resign(
        document: &str,
        signer: &Signer,
        signature: &[u8],
        properties: impl Fn(&str) -> String,
        signed_info: impl Fn(&str) -> String,
    ) -> String {
        let element = |open: &str, close: &str| {
            let start = document.find(open).expect("element");
            let end = document.find(close).expect("end tag") + close.len();
            document[start..end].to_owned()
        };
        let old_properties = element("<xades:SignedProperties", "</xades:SignedProperties>");
        let old_signed_info = element("<ds:SignedInfo", "</ds:SignedInfo>");
        let new_properties = properties(&old_properties);
        let canonical_properties = XmlDocument::parse(new_properties.clone().into_bytes())
            .expect("properties parse")
            .root()
            .canonicalize(Comments::Omitted);
        let digest = |octets: &[u8]| base64::encode(&DigestAlgorithm::Sha256.digest(octets));
        let new_signed_info = signed_info(&old_signed_info.replace(
            &digest(old_properties.as_bytes()),
            &digest(&canonical_properties),
        ));
        let new_signature = signer.sign_xml(new_signed_info.as_bytes());
        document
            .replace(&old_properties, &new_properties)
            .replace(&old_signed_info, &new_signed_info)
            .replace(&base64::encode(signature), &base64::encode(&new_signature))
    }

    /// `SigningCertificateV2` is mandatory (EN 319 132-1 sec.5.2.2): a
    /// signature whose signed properties lack it is not valid, though
    /// its value verifies and every reference matches.
    #[test]
    fn a_signature_without_a_signing_certificate_is_not_valid() {
        let signer = Signer::rsa();
        let signed = Signed::new(&signer, &objects());
        let document = signed.document(&[]);
        let stripped = resign(
            &document,
            &signer,
            &signed.signature,
            |properties| {
                let start = properties
                    .find("<xades:SigningCertificateV2>")
                    .expect("property");
                let close = "</xades:SigningCertificateV2>\n";
                let end = properties.find(close).expect("end tag") + close.len();
                format!("{}{}", &properties[..start], &properties[end..])
            },
            str::to_owned,
        );
        assert!(!stripped.contains("SigningCertificate"));
        let verdict = verdict(&objects(), &stripped);
        assert!(verdict.document_intact, "the re-signed references hold");
        assert!(!verdict.signature_valid);
    }

    /// A bare-name reference drops comments before its transforms run
    /// (XML Signature 1.1 sec.4.4.3.3), so a `WithComments` transform
    /// over a `SignedProperties` holding a comment digests the
    /// comment-free form, and the signature is intact.
    #[test]
    fn a_with_comments_transform_on_a_bare_name_reference_digests_without_comments() {
        let signer = Signer::rsa();
        let signed = Signed::new(&signer, &objects());
        let document = signed.document(&[]);
        let open = "<xades:SignedSignatureProperties>";
        let with_comment = resign(
            &document,
            &signer,
            &signed.signature,
            |properties| properties.replacen(open, &format!("{open}<!-- a note -->"), 1),
            |signed_info| {
                signed_info.replace(
                    &format!("<ds:Transform Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\">"),
                    &format!(
                        "<ds:Transform Algorithm=\"{}\">",
                        super::CANONICALIZATION_EXCLUSIVE_COMMENTS
                    ),
                )
            },
        );
        assert!(with_comment.contains("<!-- a note -->"));
        assert!(with_comment.contains(super::CANONICALIZATION_EXCLUSIVE_COMMENTS));

        // The comment would change the digest if it were kept.
        let parsed = XmlDocument::parse(with_comment.clone().into_bytes()).expect("parses");
        let properties = parsed
            .elements()
            .find(|element| element.is(NAMESPACE_XADES, "SignedProperties"))
            .expect("properties");
        assert_ne!(
            properties.canonicalize(Comments::Retained),
            properties.canonicalize(Comments::Omitted)
        );

        let verdict = verdict(&objects(), &with_comment);
        assert!(verdict.document_intact);
        assert!(verdict.signature_valid);
    }

    #[test]
    fn a_flipped_signature_byte_invalidates_the_signature() {
        let mut signed = Signed::new(&Signer::rsa(), &objects());
        signed.signature[0] ^= 1;
        let verdict = verdict(&objects(), &signed.document(&[]));
        assert!(verdict.document_intact);
        assert!(!verdict.signature_valid);
    }

    /// The signer certificate is bound by `SigningCertificateV2`: a
    /// signature that verifies under a certificate the property does
    /// not name is not valid.
    #[test]
    fn a_certificate_the_binding_does_not_name_invalidates_the_signature() {
        let signer = Signer::rsa();
        let named =
            Signer::Ecdsa(TestKey::generate(Curve::P256)).certificate(OTHER_SERIAL, OTHER_NAME);
        let parsed = Certificate::from_der(&named).expect("parses");
        let parameters = SignerParameters {
            certificate: &parsed,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: signer.algorithm(),
            signing_time: Some(signing_time()),
        };
        let plan = plan(&objects(), &parameters).expect("plan");
        let signature = signer.sign_xml(plan.signed_info());
        let document =
            String::from_utf8(plan.finish(&signature, &[], &ValidationMaterial::default()))
                .expect("utf-8");
        let actual = signer.certificate(SIGNER_SERIAL, SIGNER_NAME);
        let swapped = document.replace(&base64::encode(&named), &base64::encode(&actual));
        let verdict = verdict(&objects(), &swapped);
        assert!(verdict.document_intact);
        assert!(!verdict.signature_valid);
    }

    /// The writer's `SignedInfo`, respelled as another producer might:
    /// declarations on an ancestor, an unused declaration, attributes
    /// reordered and single-quoted, self-closed elements, whitespace
    /// inside tags. Canonicalisation lands on the writer's bytes.
    #[test]
    fn a_respelled_signed_info_canonicalises_to_the_writers_bytes() {
        let signed = Signed::new(&Signer::rsa(), &objects());
        let canonical = core::str::from_utf8(signed.plan.signed_info()).expect("utf-8");
        let respelled = respell(canonical);
        assert!(respelled.contains(" />"), "self-closed elements");
        assert!(
            respelled.contains("URI='dossier.pdf'"),
            "reordered attributes"
        );
        assert!(
            !respelled.contains("xmlns:ds"),
            "declaration moved to an ancestor"
        );
        let wrapper = format!(
            "<outer xmlns:ds=\"{NAMESPACE_DSIG}\" xmlns:unused=\"urn:unused\">{respelled}</outer>"
        );
        let document = XmlDocument::parse(wrapper.into_bytes()).expect("parses");
        let signed_info = document.root().children().next().expect("SignedInfo");
        assert_eq!(
            signed_info.canonicalize(Comments::Omitted),
            signed.plan.signed_info()
        );

        // And a signature file carrying the respelling still verifies.
        let file = signed.document(&[]).replace(canonical, &respelled);
        let verdict = verdict(&objects(), &file);
        assert!(verdict.document_intact);
        assert!(verdict.signature_valid);
    }

    /// Respell canonical `SignedInfo` text without changing its
    /// canonical form.
    fn respell(canonical: &str) -> String {
        let declaration = format!(" xmlns:ds=\"{NAMESPACE_DSIG}\"");
        let mut text = canonical.replacen(&declaration, "", 1);
        for element in [
            "CanonicalizationMethod",
            "SignatureMethod",
            "DigestMethod",
            "Transform",
        ] {
            text = text.replace(&format!("></ds:{element}>"), " />");
        }
        text = text.replace(
            "<ds:Reference Id=\"SIG-1-REF-0\" URI=\"dossier.pdf\">",
            "<ds:Reference\n  URI='dossier.pdf'\tId = 'SIG-1-REF-0' >",
        );
        text.replace("<ds:SignedInfo>", "<ds:SignedInfo >")
    }

    /// A `SignatureTimeStamp` over the canonical `SignatureValue` is
    /// verified; a token over other data is counted but not verified;
    /// an `ArchiveTimeStamp` is counted apart and never verified.
    #[test]
    fn signature_timestamps_are_verified_and_archive_timestamps_only_counted() {
        let signed = Signed::new(&Signer::rsa(), &objects());
        let tsa = Tsa::new();
        let value_element = SignaturePlan::signature_value_element(&signed.signature);
        let generated = day(STAMP_DAY);
        let good = tsa.token(value_element.as_bytes(), generated);
        let elsewhere = tsa.token(b"some other data", generated);

        let document = signed.document(&[good.clone(), elsewhere]);
        let archive = format!(
            "<xades141:ArchiveTimeStamp xmlns:xades141=\"{}\"><ds:CanonicalizationMethod Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/><xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp></xades141:ArchiveTimeStamp>\n</xades:UnsignedSignatureProperties>",
            super::NAMESPACE_XADES_141,
            base64::encode(&good)
        );
        let with_archive = document.replace("</xades:UnsignedSignatureProperties>", &archive);
        assert!(with_archive.contains(NAMESPACE_XADES));

        let verdict = verdict(&objects(), &with_archive);
        assert!(verdict.document_intact);
        assert!(verdict.signature_valid);
        let [
            TimestampCheck::Verified(verified),
            TimestampCheck::Unverified { claimed_at },
        ] = verdict.signature_timestamps.as_slice()
        else {
            panic!("exactly the good token verifies");
        };
        assert_eq!(*claimed_at, Some(generated));
        assert_eq!(verified.generated_at, generated);
        assert_eq!(verified.signer_certificate, tsa.certificate);
        assert_eq!(verdict.archive_timestamps_present, 1);
    }

    #[test]
    fn validation_material_is_read_from_the_unsigned_properties() {
        let signed = Signed::new(&Signer::rsa(), &objects());
        let material = ValidationMaterial {
            certificates: vec![b"issuer certificate".to_vec()],
            ocsp_responses: vec![b"ocsp response".to_vec()],
            crls: vec![b"crl".to_vec()],
        };
        let document = String::from_utf8(signed.plan.finish(&signed.signature, &[], &material))
            .expect("utf-8");
        let file = Entry {
            name: "META-INF/signatures0.xml".to_owned(),
            content: document.into_bytes(),
        };
        let read = signatures(&file).expect("reads");
        assert_eq!(read[0].embedded_material(), material);
        assert_eq!(
            read[0].embedded_certificates(),
            [signed.certificate.clone(), b"issuer certificate".to_vec()]
        );
    }

    #[test]
    fn another_signed_info_canonicalisation_is_unsupported() {
        let signed = Signed::new(&Signer::rsa(), &objects());
        let inclusive = "http://www.w3.org/2006/12/xml-c14n11";
        let document = signed.document(&[]).replacen(
            &format!("<ds:CanonicalizationMethod Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\">"),
            &format!("<ds:CanonicalizationMethod Algorithm=\"{inclusive}\">"),
            1,
        );
        let (container, signature) = container_and_signature(&objects(), &document);
        assert!(signature.unsupported().is_some());
        let verdict = signature.verify(&container);
        assert!(!verdict.document_intact);
        assert!(!verdict.signature_valid);
    }

    #[test]
    fn a_file_without_a_signature_is_refused() {
        let file = Entry {
            name: "META-INF/signatures0.xml".to_owned(),
            content: b"<other/>".to_vec(),
        };
        assert_eq!(
            signatures(&file).err(),
            Some(super::XadesReadError::NoSignature)
        );
    }

    #[test]
    fn base64_decoding_is_strict() {
        assert_eq!(decode_base64("Zm9v\nYmFy").as_deref(), Some(&b"foobar"[..]));
        assert_eq!(decode_base64("Zg==").as_deref(), Some(&b"f"[..]));
        assert_eq!(decode_base64("Zh=="), None, "non-zero padding bits");
        assert_eq!(decode_base64("Zg="), None, "truncated quantum");
        assert_eq!(decode_base64("Z==="), None, "too much padding");
        assert_eq!(decode_base64("Zm9v!"), None);
    }
}
