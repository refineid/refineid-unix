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

//! Judging a signer certificate against the material a document
//! carries, fully offline.
//!
//! [`judge`] builds a path upward from the signer through the
//! certificates of a [`MaterialPool`], reports whether it ends in one
//! of the caller's [`TrustAnchors`], and reads the revocation status of
//! every certificate on that path below the anchor from the OCSP
//! responses and CRLs in the same pool. Path building reads only the
//! pool, so the caller adds its trusted root certificates to it with
//! [`MaterialPool::add_certificates`].
//!
//! # Conformance
//!
//! - `ETSI EN 319 102-1` clause 5.2.6: the signer certificate is
//!   validated by a path to a trust anchor at the validation time,
//!   with its revocation status.
//! - RFC 5280 section 6.1: each step's issuer name equals the
//!   subject name above it, the signature verifies under the issuer
//!   key, every certificate is valid at the validation time, and each
//!   issuer is a CA (basicConstraints `cA`, `keyCertSign` when Key
//!   Usage is present, `pathLenConstraint` honoured). Name Constraints
//!   are not enforced, so an issuer carrying them is not used.
//! - `ETSI EN 319 102-1` clause 5.2.5 (revocation freshness) and
//!   clause 5.6.2 (past certificate validation): a good answer counts
//!   when its validity window contains the validation time, or when it
//!   was issued at or after that time while the signer certificate was
//!   still valid. A verified revoked answer counts whatever its time.
//! - RFC 6960: an OCSP answer counts only when its signer is the
//!   issuer or a responder the issuer delegated
//!   ([`VerifiedOcspResponse::verify`]).
//! - RFC 5280 section 5: a CRL counts only when the issuer signed it
//!   ([`VerifiedCrl::verify`]).

use crate::crl::{OwnedCrl, VerifiedCrl};
use crate::crypto::digest::Sha256;
use crate::document::{Revocation, TrustAnchors};
use crate::ocsp::{CertStatus, OcspResponseStatus, OwnedOcspResponse, VerifiedOcspResponse};
use crate::revocation::{RevocationStatus, check_against_crl};
use crate::sign::validation::ValidationMaterial;
use crate::x509::{Certificate, DateTime, OwnedCert, path_extension_profile};

/// Most certificates searched above the signer before a path is
/// abandoned. RFC 5280 sets no bound; a FINEID path is signer,
/// intermediate, root.
const MAX_PATH_DEPTH: usize = 8;

/// Certificates and revocation answers gathered from one or more
/// documents and from the caller, each parsed once and held once.
///
/// Entries that do not parse are left out: the pool is evidence, and
/// an unreadable item proves nothing.
#[derive(Debug, Clone, Default)]
pub struct MaterialPool {
    /// Distinct certificates, by DER.
    certificates: Vec<OwnedCert>,
    /// Distinct `OCSPResponse` structures, by DER.
    ocsp_responses: Vec<OwnedOcspResponse>,
    /// Distinct CRLs, by DER.
    crls: Vec<OwnedCrl>,
}

/// What the pool says about one signer certificate.
#[derive(Debug, Clone)]
pub struct ChainVerdict {
    /// The certificate that verifiably issued the signer, when one
    /// in the pool did; the issuer on the anchored path when there is
    /// one.
    pub issuer: Option<OwnedCert>,
    /// Whether a path from the signer ends in a self-signed
    /// certificate whose SHA-256 fingerprint is a trust anchor, with
    /// every certificate on it valid at the validation time.
    pub anchored: bool,
    /// The revocation status of the anchored path (of the signer alone
    /// when there is none), from verified answers in the pool accepted
    /// at the validation time.
    pub revocation: Revocation,
}

/// A revocation answer that verified and applied to the signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Good, as of this production time.
    Good(DateTime),
    /// Revoked.
    Revoked,
}

impl MaterialPool {
    /// An empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the certificates, OCSP responses and CRLs of `material`.
    pub fn add_material(&mut self, material: &ValidationMaterial) {
        self.add_certificates(&material.certificates);
        for der in &material.ocsp_responses {
            if self
                .ocsp_responses
                .iter()
                .all(|known| known.as_der() != der.as_slice())
                && let Ok(response) = OwnedOcspResponse::from_der(der)
            {
                self.ocsp_responses.push(response);
            }
        }
        for der in &material.crls {
            if self
                .crls
                .iter()
                .all(|known| known.as_der() != der.as_slice())
                && let Ok(crl) = OwnedCrl::from_der(der)
            {
                self.crls.push(crl);
            }
        }
    }

    /// Add DER certificates: chain certificates a document embeds, or
    /// the caller's trusted roots.
    pub fn add_certificates(&mut self, ders: &[Vec<u8>]) {
        for der in ders {
            if self
                .certificates
                .iter()
                .all(|known| known.as_der() != der.as_slice())
                && let Ok(certificate) = OwnedCert::from_der(der)
            {
                self.certificates.push(certificate);
            }
        }
    }

    /// The pool certificates that issued `child`, valid at `at` and
    /// allowed to issue with `intermediates_below` CA certificates
    /// between them and the end entity.
    fn issuers_of(
        &self,
        child: Certificate<'_>,
        at: DateTime,
        intermediates_below: usize,
    ) -> Vec<&OwnedCert> {
        self.certificates
            .iter()
            .filter(|candidate| {
                let view = candidate.view();
                view.raw_der != child.raw_der
                    && view.subject == child.issuer
                    && valid_at(view, at)
                    && may_issue(view, intermediates_below)
                    && child.verify_signed_by(view).is_ok()
            })
            .collect()
    }

    /// Whether a path from `certificate` upward ends in a trust
    /// anchor. `path` holds the DER of the certificates below it,
    /// signer first, and `certificate` last.
    fn anchored_above(
        &self,
        certificate: &OwnedCert,
        anchors: TrustAnchors<'_>,
        at: DateTime,
        path: &mut Vec<Vec<u8>>,
    ) -> bool {
        let view = certificate.view();
        if is_self_signed(view) {
            return anchors.contains(Sha256::of(view.raw_der));
        }
        if path.len() > MAX_PATH_DEPTH {
            return false;
        }
        let intermediates_below = path.len().saturating_sub(1);
        for issuer in self.issuers_of(view, at, intermediates_below) {
            if path.iter().any(|seen| seen.as_slice() == issuer.as_der()) {
                continue;
            }
            path.push(issuer.as_der().to_vec());
            if self.anchored_above(issuer, anchors, at, path) {
                return true;
            }
            path.pop();
        }
        false
    }

    /// The revocation status of `certificate` from every verified
    /// OCSP answer and every CRL `issuer` signed: revoked when any says
    /// so, else good when any accepted answer says so.
    fn revocation_of(
        &self,
        certificate: Certificate<'_>,
        issuer: Certificate<'_>,
        at: DateTime,
    ) -> Revocation {
        let ocsp = self
            .ocsp_responses
            .iter()
            .filter_map(|response| self.ocsp_answer(response, certificate, issuer, at));
        let crl = self
            .crls
            .iter()
            .filter_map(|crl| crl_answer(crl, certificate, issuer, at));
        strongest(ocsp.chain(crl)).unwrap_or(Revocation::Unavailable)
    }

    /// The revocation status of a path, signer first and anchor last:
    /// every certificate below the anchor is checked against its
    /// issuer (RFC 5280 section 6.1.3 (a)(3), `ETSI EN 319 102-1`
    /// clause 5.2.6). Revoked when any is revoked, else unavailable
    /// when any is unanswered, else the signer's good answer.
    fn path_revocation(&self, path: &[Certificate<'_>], at: DateTime) -> Revocation {
        let mut signer = None;
        let mut unanswered = false;
        for step in path.windows(2) {
            let [certificate, issuer] = step else {
                continue;
            };
            let revocation = self.revocation_of(*certificate, *issuer, at);
            match revocation {
                Revocation::Revoked => return Revocation::Revoked,
                Revocation::Unavailable => unanswered = true,
                Revocation::Good { .. } => {}
            }
            signer.get_or_insert(revocation);
        }
        if unanswered {
            Revocation::Unavailable
        } else {
            signer.unwrap_or(Revocation::Unavailable)
        }
    }

    /// What one OCSP response says about `signer`, when its signer
    /// is `issuer` or a responder `issuer` delegated, and its answer
    /// was current at `at`.
    fn ocsp_answer(
        &self,
        response: &OwnedOcspResponse,
        signer: Certificate<'_>,
        issuer: Certificate<'_>,
        at: DateTime,
    ) -> Option<Answer> {
        let view = response.view();
        if view.status != OcspResponseStatus::Successful {
            return None;
        }
        let basic = view.basic.as_ref()?;
        let embedded = basic
            .embedded_cert_ders
            .iter()
            .filter_map(|der| Certificate::from_der(der).ok());
        let pooled = self.certificates.iter().map(OwnedCert::view);
        core::iter::once(issuer)
            .chain(embedded)
            .chain(pooled)
            .filter(|candidate| basic.responder_id.matches_certificate(*candidate))
            .find_map(|candidate| {
                let verified = VerifiedOcspResponse::verify(basic, candidate, issuer).ok()?;
                let single = verified.response_for(signer)?;
                match single.status {
                    CertStatus::Revoked { .. } => Some(Answer::Revoked),
                    CertStatus::Good => {
                        accepted_window(signer, single.this_update, single.next_update, at)
                            .then_some(Answer::Good(basic.produced_at))
                    }
                    CertStatus::Unknown => None,
                }
            })
    }
}

/// Judge `signer` against `pool` at the validation time `at`.
///
/// `issuer` is reported whenever a pool certificate verifiably issued
/// the signer, anchored or not; `anchored` additionally needs the
/// signer valid at `at` and a path ending in one of `anchors`. On an
/// anchored path every certificate below the anchor is checked for
/// revocation; without one only the signer is, against `issuer`. The
/// status is [`Revocation::Unavailable`] without an issuer: no
/// unverified answer is ever reported.
#[must_use]
pub fn judge(
    signer: &OwnedCert,
    pool: &MaterialPool,
    anchors: TrustAnchors<'_>,
    at: DateTime,
) -> ChainVerdict {
    let view = signer.view();
    let signer_valid = valid_at(view, at);
    if is_self_signed(view) {
        return ChainVerdict {
            issuer: None,
            anchored: signer_valid && anchors.contains(Sha256::of(view.raw_der)),
            revocation: Revocation::Unavailable,
        };
    }
    let candidates = pool.issuers_of(view, at, 0);
    let mut path = vec![view.raw_der.to_vec()];
    let anchored_issuer = candidates.iter().copied().find(|issuer| {
        path.truncate(1);
        path.push(issuer.as_der().to_vec());
        pool.anchored_above(issuer, anchors, at, &mut path)
    });
    let issuer = anchored_issuer.or_else(|| candidates.first().copied());
    let revocation = if anchored_issuer.is_some() {
        let anchored_path: Vec<Certificate<'_>> = path
            .iter()
            .filter_map(|der| Certificate::from_der(der).ok())
            .collect();
        pool.path_revocation(&anchored_path, at)
    } else {
        issuer.map_or(Revocation::Unavailable, |issuer| {
            pool.revocation_of(view, issuer.view(), at)
        })
    };
    ChainVerdict {
        issuer: issuer.cloned(),
        anchored: signer_valid && anchored_issuer.is_some(),
        revocation,
    }
}

/// What one CRL says about `signer`, when `issuer` signed it and it
/// was current at `at`.
fn crl_answer(
    crl: &OwnedCrl,
    signer: Certificate<'_>,
    issuer: Certificate<'_>,
    at: DateTime,
) -> Option<Answer> {
    let view = crl.view();
    let verified = VerifiedCrl::verify(&view, issuer).ok()?;
    // Read at the CRL's own `thisUpdate`, where it is never stale; the
    // acceptance window is applied below.
    match check_against_crl(signer, &verified, view.this_update) {
        RevocationStatus::Good => accepted_window(signer, view.this_update, view.next_update, at)
            .then_some(Answer::Good(view.this_update)),
        RevocationStatus::Revoked { .. } => Some(Answer::Revoked),
        RevocationStatus::Inapplicable(_) | RevocationStatus::Stale | RevocationStatus::Unknown => {
            None
        }
    }
}

/// Whether a good answer with this window speaks for `certificate` at
/// `at`: its window `thisUpdate..=nextUpdate` contains `at` (with
/// `nextUpdate` absent the window is `thisUpdate` alone), or it was
/// issued at or after `at` while the certificate was still valid
/// (`thisUpdate <= notAfter`). The second
/// case is evidence gathered right after signing, which a level-LT
/// document embeds; it shows the certificate was not revoked when the
/// signature already existed (`ETSI EN 319 102-1` clauses 5.2.5 and
/// 5.6.2).
fn accepted_window(
    certificate: Certificate<'_>,
    this_update: DateTime,
    next_update: Option<DateTime>,
    at: DateTime,
) -> bool {
    let contains_at = this_update <= at && at <= next_update.unwrap_or(this_update);
    let issued_after_at = at <= this_update && this_update <= certificate.not_after;
    contains_at || issued_after_at
}

/// A revoked answer outweighs any good one; among good answers the
/// latest production time is reported.
fn strongest(answers: impl Iterator<Item = Answer>) -> Option<Revocation> {
    let mut good: Option<DateTime> = None;
    for answer in answers {
        match answer {
            Answer::Revoked => return Some(Revocation::Revoked),
            Answer::Good(checked_at) => {
                good = Some(good.map_or(checked_at, |known| known.max(checked_at)));
            }
        }
    }
    good.map(|checked_at| Revocation::Good { checked_at })
}

/// Whether `at` lies inside the certificate's validity window
/// (RFC 5280 section 4.1.2.5, both ends inclusive).
fn valid_at(certificate: Certificate<'_>, at: DateTime) -> bool {
    certificate.not_before <= at && at <= certificate.not_after
}

/// Whether the certificate names itself as issuer and its signature
/// verifies under its own key.
fn is_self_signed(certificate: Certificate<'_>) -> bool {
    certificate.subject == certificate.issuer && certificate.verify_signed_by(certificate).is_ok()
}

/// Whether the certificate may issue a certificate with
/// `intermediates_below` CA certificates between it and the end
/// entity (RFC 5280 section 6.1.4 (k), (l), (n)).
fn may_issue(certificate: Certificate<'_>, intermediates_below: usize) -> bool {
    let Some(extensions) = certificate.extensions else {
        return false;
    };
    let Ok(profile) = path_extension_profile(extensions) else {
        return false;
    };
    let constraints = profile.basic_constraints;
    constraints.present
        && constraints.ca
        && !profile.name_constraints_present
        && profile
            .key_usage
            .is_none_or(|usage| usage.key_usage.key_cert_sign)
        && constraints.path_len.is_none_or(|limit| {
            usize::try_from(limit).is_ok_and(|limit| intermediates_below <= limit)
        })
}

/// Synthetic keys, certificates, CRLs and OCSP responses for the
/// document verifier's tests. Every key is generated per run; nothing
/// here is a real identity.
#[cfg(test)]
pub(crate) mod testkit {
    use crate::ber::tlv;
    use crate::crypto::digest::Sha256;
    use crate::ocsp::{IssuerKeyHash, IssuerNameHash};
    use crate::oid::{Oid, known};
    use crate::sign::cades::{DigestAlgorithm, SignatureAlgorithm};
    use crate::x509::{Certificate, DateTime, OwnedCert};
    use ring::rand::SystemRandom;
    use ring::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _,
    };

    /// Universal BOOLEAN.
    pub(crate) const BOOLEAN: u8 = 0x01;
    /// Universal INTEGER.
    pub(crate) const INTEGER: u8 = 0x02;
    /// Universal BIT STRING.
    pub(crate) const BIT_STRING: u8 = 0x03;
    /// Universal OCTET STRING.
    pub(crate) const OCTET_STRING: u8 = 0x04;
    /// Universal NULL.
    pub(crate) const NULL: u8 = 0x05;
    /// Universal OBJECT IDENTIFIER.
    pub(crate) const OBJECT_IDENTIFIER: u8 = 0x06;
    /// Universal ENUMERATED.
    pub(crate) const ENUMERATED: u8 = 0x0A;
    /// Universal `UTF8String`.
    pub(crate) const UTF8_STRING: u8 = 0x0C;
    /// Universal `PrintableString`.
    pub(crate) const PRINTABLE_STRING: u8 = 0x13;
    /// Universal `UTCTime`.
    pub(crate) const UTC_TIME: u8 = 0x17;
    /// Universal `GeneralizedTime`.
    pub(crate) const GENERALIZED_TIME: u8 = 0x18;
    /// Universal SEQUENCE.
    pub(crate) const SEQUENCE: u8 = 0x30;
    /// Universal SET.
    pub(crate) const SET: u8 = 0x31;
    /// Context-specific primitive `[0]`: OCSP `good` (RFC 6960 sec.4.2.1).
    pub(crate) const CONTEXT_0_PRIMITIVE: u8 = 0x80;
    /// Context-specific constructed `[0]`.
    pub(crate) const CONTEXT_0: u8 = 0xA0;
    /// Context-specific constructed `[1]`.
    pub(crate) const CONTEXT_1: u8 = 0xA1;
    /// Context-specific constructed `[3]`: TBS `extensions`.
    pub(crate) const CONTEXT_3: u8 = 0xA3;
    /// DER BOOLEAN TRUE (X.690 sec.11.1).
    pub(crate) const DER_TRUE: u8 = 0xFF;
    /// BIT STRING leading octet: no unused bits.
    pub(crate) const NO_UNUSED_BITS: u8 = 0x00;
    /// X.509 `Version` v3, encoded as INTEGER 2 (RFC 5280 sec.4.1).
    const X509_VERSION_3: u8 = 0x02;
    /// CRL `Version` v2, encoded as INTEGER 1 (RFC 5280 sec.5.1).
    const CRL_VERSION_2: u8 = 0x01;
    /// `OCSPResponseStatus` successful (RFC 6960 sec.4.2.1).
    const OCSP_SUCCESSFUL: u8 = 0x00;
    /// Key Usage `keyCertSign` and `cRLSign` (RFC 5280 sec.4.2.1.3):
    /// bits 5 and 6 of the first octet.
    const KEY_USAGE_CA: u8 = 0x06;
    /// Unused bits after `cRLSign`, the last named bit set.
    const KEY_USAGE_CA_UNUSED: u8 = 0x01;
    /// Octets of one P-256 coordinate (SEC 1 sec.2.3.5).
    const P256_COORDINATE_OCTETS: usize = 32;
    /// Octets of one P-384 coordinate.
    const P384_COORDINATE_OCTETS: usize = 48;
    /// Divisor for the two-digit `UTCTime` year.
    const CENTURY: u16 = 100;

    /// The year and month every fixture instant falls in.
    const FIXTURE_YEAR: u16 = 2026;
    /// See [`FIXTURE_YEAR`].
    const FIXTURE_MONTH: u8 = 6;
    /// Hour of every fixture instant.
    const FIXTURE_HOUR: u8 = 12;

    /// Noon on `day` of the fixture month.
    pub(crate) fn day(day: u8) -> DateTime {
        DateTime::new(FIXTURE_YEAR, FIXTURE_MONTH, day, FIXTURE_HOUR, 0, 0).expect("fixture day")
    }

    /// The two curves the document verifier accepts.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Curve {
        /// NIST P-256 with SHA-256.
        P256,
        /// NIST P-384 with SHA-384.
        P384,
    }

    /// A freshly generated ECDSA key.
    pub(crate) struct TestKey {
        /// The `ring` key pair.
        pair: EcdsaKeyPair,
        /// Which curve it is on.
        curve: Curve,
    }

    impl TestKey {
        /// Generate a key on `curve`.
        pub(crate) fn generate(curve: Curve) -> Self {
            let algorithm = match curve {
                Curve::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
                Curve::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            };
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(algorithm, &rng).expect("key generates");
            let pair =
                EcdsaKeyPair::from_pkcs8(algorithm, pkcs8.as_ref(), &rng).expect("key loads");
            Self { pair, curve }
        }

        /// The `SubjectPublicKeyInfo` DER.
        pub(crate) fn spki(&self) -> Vec<u8> {
            let curve = match self.curve {
                Curve::P256 => known::SECP256R1,
                Curve::P384 => known::SECP384R1,
            };
            let mut algorithm = tlv(OBJECT_IDENTIFIER, known::EC_PUBLIC_KEY.as_bytes());
            algorithm.extend_from_slice(&tlv(OBJECT_IDENTIFIER, curve.as_bytes()));
            let mut body = tlv(SEQUENCE, algorithm);
            body.extend_from_slice(&bit_string(self.pair.public_key().as_ref()));
            tlv(SEQUENCE, body)
        }

        /// A DER ECDSA signature over `message`.
        pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.pair
                .sign(&SystemRandom::new(), message)
                .expect("signature")
                .as_ref()
                .to_vec()
        }

        /// The signature over `message` as a card returns it: the raw
        /// `r || s` pair (FINEID S1 v4.2 sec.3.8.3).
        pub(crate) fn sign_raw(&self, message: &[u8]) -> Vec<u8> {
            let coordinate_octets = match self.curve {
                Curve::P256 => P256_COORDINATE_OCTETS,
                Curve::P384 => P384_COORDINATE_OCTETS,
            };
            crate::sign::xades::ecdsa_signature_to_xml(&self.sign(message), coordinate_octets)
                .expect("DER signature splits into coordinates")
        }

        /// The `AlgorithmIdentifier` of this key's signatures.
        pub(crate) fn algorithm_identifier(&self) -> Vec<u8> {
            tlv(
                SEQUENCE,
                tlv(OBJECT_IDENTIFIER, self.signature_oid().as_bytes()),
            )
        }

        /// The signature algorithm OID of this key's signatures.
        pub(crate) const fn signature_oid(&self) -> Oid<'static> {
            match self.curve {
                Curve::P256 => known::ECDSA_WITH_SHA256,
                Curve::P384 => known::ECDSA_WITH_SHA384,
            }
        }

        /// The `CAdES` writer's name for this key's signatures.
        pub(crate) const fn cades_algorithm(&self) -> SignatureAlgorithm {
            match self.curve {
                Curve::P256 => SignatureAlgorithm::EcdsaSha256,
                Curve::P384 => SignatureAlgorithm::EcdsaSha384,
            }
        }

        /// The digest this key's signatures are computed over.
        pub(crate) const fn digest_algorithm(&self) -> DigestAlgorithm {
            match self.curve {
                Curve::P256 => DigestAlgorithm::Sha256,
                Curve::P384 => DigestAlgorithm::Sha384,
            }
        }
    }

    /// A BIT STRING with no unused bits around `bits`.
    pub(crate) fn bit_string(bits: &[u8]) -> Vec<u8> {
        let mut body = vec![NO_UNUSED_BITS];
        body.extend_from_slice(bits);
        tlv(BIT_STRING, body)
    }

    /// A `Name` holding one common name.
    pub(crate) fn name(common_name: &str) -> Vec<u8> {
        name_of(&[(known::COMMON_NAME, UTF8_STRING, common_name)])
    }

    /// A `Name` with one RDN per `(type, string tag, value)`.
    pub(crate) fn name_of(attributes: &[(Oid<'_>, u8, &str)]) -> Vec<u8> {
        let mut rdns = Vec::new();
        for (oid, tag, value) in attributes {
            let mut attribute = tlv(OBJECT_IDENTIFIER, oid.as_bytes());
            attribute.extend_from_slice(&tlv(*tag, value.as_bytes()));
            rdns.extend_from_slice(&tlv(SET, tlv(SEQUENCE, attribute)));
        }
        tlv(SEQUENCE, rdns)
    }

    /// A minimal PDF: catalog, page tree, one page, a classic
    /// cross-reference table and a trailer, with offsets computed from
    /// the bytes (ISO 32000-1 sec.7.5).
    pub(crate) fn minimal_pdf() -> Vec<u8> {
        let bodies = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        ];
        let mut pdf = Vec::from("%PDF-1.7\n");
        let mut offsets = Vec::new();
        for (index, body) in bodies.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(
                format!("{} 0 obj\n{body}\nendobj\n", index.saturating_add(1)).as_bytes(),
            );
        }
        let xref_at = pdf.len();
        let size = bodies.len().saturating_add(1);
        pdf.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
        pdf.extend_from_slice(b"0000000000 65535 f \n");
        for offset in &offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n")
                .as_bytes(),
        );
        pdf
    }

    /// A `UTCTime` TLV (RFC 5280 sec.4.1.2.5.1).
    pub(crate) fn utc_time(time: DateTime) -> Vec<u8> {
        let text = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            time.year() % CENTURY,
            time.month(),
            time.day(),
            time.hour(),
            time.minutes(),
            time.seconds()
        );
        tlv(UTC_TIME, text.as_bytes())
    }

    /// A `GeneralizedTime` TLV.
    pub(crate) fn generalized_time(time: DateTime) -> Vec<u8> {
        let text = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            time.year(),
            time.month(),
            time.day(),
            time.hour(),
            time.minutes(),
            time.seconds()
        );
        tlv(GENERALIZED_TIME, text.as_bytes())
    }

    /// One `Extension`.
    pub(crate) fn extension(oid: Oid<'_>, critical: bool, value: &[u8]) -> Vec<u8> {
        let mut body = tlv(OBJECT_IDENTIFIER, oid.as_bytes());
        if critical {
            body.extend_from_slice(&tlv(BOOLEAN, [DER_TRUE]));
        }
        body.extend_from_slice(&tlv(OCTET_STRING, value));
        tlv(SEQUENCE, body)
    }

    /// The extensions of a CA: critical basicConstraints `cA`, and
    /// critical Key Usage `keyCertSign` + `cRLSign`.
    pub(crate) fn ca_extensions() -> Vec<Vec<u8>> {
        vec![
            extension(
                known::BASIC_CONSTRAINTS,
                true,
                &tlv(SEQUENCE, tlv(BOOLEAN, [DER_TRUE])),
            ),
            extension(
                known::KEY_USAGE,
                true,
                &tlv(BIT_STRING, [KEY_USAGE_CA_UNUSED, KEY_USAGE_CA]),
            ),
        ]
    }

    /// The extensions of a TSA: critical EKU `id-kp-timeStamping`
    /// alone (RFC 3161 sec.2.3).
    pub(crate) fn timestamping_extensions() -> Vec<Vec<u8>> {
        vec![extension(
            known::EXT_KEY_USAGE,
            true,
            &tlv(
                SEQUENCE,
                tlv(OBJECT_IDENTIFIER, known::KP_TIME_STAMPING.as_bytes()),
            ),
        )]
    }

    /// What one certificate says about itself.
    pub(crate) struct CertificateSpec<'a> {
        /// Serial number, below `0x80` so the INTEGER stays positive.
        pub(crate) serial: u8,
        /// Subject common name.
        pub(crate) subject: &'a str,
        /// Issuer common name.
        pub(crate) issuer: &'a str,
        /// Start of validity.
        pub(crate) not_before: DateTime,
        /// End of validity.
        pub(crate) not_after: DateTime,
        /// Complete `Extension` encodings; none for an end entity
        /// without extensions.
        pub(crate) extensions: Vec<Vec<u8>>,
    }

    /// A certificate for `subject_key`, signed by `issuer_key`.
    pub(crate) fn certificate(
        spec: &CertificateSpec<'_>,
        subject_key: &TestKey,
        issuer_key: &TestKey,
    ) -> Vec<u8> {
        certificate_named(spec, &name(spec.subject), subject_key, issuer_key)
    }

    /// A certificate whose subject is the `Name` DER `subject`, in
    /// place of `spec.subject`.
    pub(crate) fn certificate_named(
        spec: &CertificateSpec<'_>,
        subject: &[u8],
        subject_key: &TestKey,
        issuer_key: &TestKey,
    ) -> Vec<u8> {
        let mut tbs = tlv(CONTEXT_0, tlv(INTEGER, [X509_VERSION_3]));
        tbs.extend_from_slice(&tlv(INTEGER, [spec.serial]));
        tbs.extend_from_slice(&issuer_key.algorithm_identifier());
        tbs.extend_from_slice(&name(spec.issuer));
        let mut validity = utc_time(spec.not_before);
        validity.extend_from_slice(&utc_time(spec.not_after));
        tbs.extend_from_slice(&tlv(SEQUENCE, validity));
        tbs.extend_from_slice(subject);
        tbs.extend_from_slice(&subject_key.spki());
        if !spec.extensions.is_empty() {
            tbs.extend_from_slice(&tlv(CONTEXT_3, tlv(SEQUENCE, spec.extensions.concat())));
        }
        signed(&tlv(SEQUENCE, tbs), issuer_key)
    }

    /// `SEQUENCE { tbs, signatureAlgorithm, signature }`, the shape of a
    /// certificate, a CRL and a `BasicOCSPResponse` without certs.
    pub(crate) fn signed(tbs: &[u8], key: &TestKey) -> Vec<u8> {
        tlv(SEQUENCE, signed_body(tbs, key))
    }

    /// The contents of [`signed`].
    fn signed_body(tbs: &[u8], key: &TestKey) -> Vec<u8> {
        let mut body = tbs.to_vec();
        body.extend_from_slice(&key.algorithm_identifier());
        body.extend_from_slice(&bit_string(&key.sign(tbs)));
        body
    }

    /// A CRL from `issuer`, listing `revoked` serials as revoked on
    /// `revoked_on`.
    pub(crate) fn crl(
        issuer: &str,
        issuer_key: &TestKey,
        this_update: DateTime,
        next_update: Option<DateTime>,
        revoked: &[u8],
        revoked_on: DateTime,
    ) -> Vec<u8> {
        let mut tbs = tlv(INTEGER, [CRL_VERSION_2]);
        tbs.extend_from_slice(&issuer_key.algorithm_identifier());
        tbs.extend_from_slice(&name(issuer));
        tbs.extend_from_slice(&utc_time(this_update));
        if let Some(next_update) = next_update {
            tbs.extend_from_slice(&utc_time(next_update));
        }
        if !revoked.is_empty() {
            let mut entries = Vec::new();
            for serial in revoked {
                let mut entry = tlv(INTEGER, [*serial]);
                entry.extend_from_slice(&utc_time(revoked_on));
                entries.extend_from_slice(&tlv(SEQUENCE, entry));
            }
            tbs.extend_from_slice(&tlv(SEQUENCE, entries));
        }
        signed(&tlv(SEQUENCE, tbs), issuer_key)
    }

    /// What one OCSP response says.
    pub(crate) struct OcspSpec<'a> {
        /// The key that signs the response.
        pub(crate) responder_key: &'a TestKey,
        /// The responder's subject common name (`ResponderID` byName).
        pub(crate) responder: &'a str,
        /// The issuer of the certificate asked about.
        pub(crate) issuer: &'a OwnedCert,
        /// Serial of the certificate asked about.
        pub(crate) serial: u8,
        /// `Some(revocation time)` for a revoked answer, `None` for good.
        pub(crate) revoked: Option<DateTime>,
        /// `producedAt`.
        pub(crate) produced_at: DateTime,
        /// `thisUpdate`.
        pub(crate) this_update: DateTime,
        /// `nextUpdate`.
        pub(crate) next_update: Option<DateTime>,
        /// Certificates carried in `BasicOCSPResponse.certs`.
        pub(crate) embedded: Vec<Vec<u8>>,
    }

    /// A successful `OCSPResponse` (RFC 6960 sec.4.2.1).
    pub(crate) fn ocsp_response(spec: &OcspSpec<'_>) -> Vec<u8> {
        let issuer = spec.issuer.view();
        let mut hash_algorithm = tlv(OBJECT_IDENTIFIER, known::SHA1.as_bytes());
        hash_algorithm.extend_from_slice(&tlv(NULL, []));
        let mut cert_id = tlv(SEQUENCE, hash_algorithm);
        cert_id.extend_from_slice(&tlv(
            OCTET_STRING,
            IssuerNameHash::from_name(issuer.subject).as_bytes(),
        ));
        cert_id.extend_from_slice(&tlv(
            OCTET_STRING,
            IssuerKeyHash::from_subject_public_key(&issuer.spki).as_bytes(),
        ));
        cert_id.extend_from_slice(&tlv(INTEGER, [spec.serial]));

        let mut single = tlv(SEQUENCE, cert_id);
        match spec.revoked {
            None => single.extend_from_slice(&tlv(CONTEXT_0_PRIMITIVE, [])),
            Some(at) => single.extend_from_slice(&tlv(CONTEXT_1, generalized_time(at))),
        }
        single.extend_from_slice(&generalized_time(spec.this_update));
        if let Some(next_update) = spec.next_update {
            single.extend_from_slice(&tlv(CONTEXT_0, generalized_time(next_update)));
        }

        let mut response_data = tlv(CONTEXT_1, name(spec.responder));
        response_data.extend_from_slice(&generalized_time(spec.produced_at));
        response_data.extend_from_slice(&tlv(SEQUENCE, tlv(SEQUENCE, single)));
        let mut basic = signed_body(&tlv(SEQUENCE, response_data), spec.responder_key);
        if !spec.embedded.is_empty() {
            basic.extend_from_slice(&tlv(CONTEXT_0, tlv(SEQUENCE, spec.embedded.concat())));
        }

        let mut response_bytes = tlv(OBJECT_IDENTIFIER, known::BASIC_OCSP_RESPONSE.as_bytes());
        response_bytes.extend_from_slice(&tlv(OCTET_STRING, tlv(SEQUENCE, basic)));
        let mut response = tlv(ENUMERATED, [OCSP_SUCCESSFUL]);
        response.extend_from_slice(&tlv(CONTEXT_0, tlv(SEQUENCE, response_bytes)));
        tlv(SEQUENCE, response)
    }

    /// `TSTInfo` version 1 (RFC 3161 sec.2.4.2).
    pub(crate) const TST_INFO_VERSION: u8 = 0x01;
    /// `TSTInfo.serialNumber` of every fixture token.
    pub(crate) const TOKEN_SERIAL: u8 = 0x01;
    /// `SignerInfo` version 1: issuer and serial (RFC 5652 sec.5.3).
    pub(crate) const SIGNER_INFO_VERSION: u8 = 0x01;
    /// `SignedData` version 3: `eContentType` other than `id-data`
    /// (RFC 5652 sec.5.1).
    pub(crate) const SIGNED_DATA_VERSION: u8 = 0x03;
    /// A TSA policy under the documentation enterprise number 32473
    /// (RFC 5612).
    pub(crate) const TEST_POLICY: Oid<'static> =
        Oid::const_new(const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1").as_bytes());

    /// One `Attribute`.
    pub(crate) fn attribute(oid: Oid<'_>, value: &[u8]) -> Vec<u8> {
        let mut body = tlv(OBJECT_IDENTIFIER, oid.as_bytes());
        body.extend_from_slice(&tlv(SET, value));
        tlv(SEQUENCE, body)
    }

    /// The DER `SET OF Attribute` that is signed.
    pub(crate) fn attribute_set(attributes: &[Vec<u8>]) -> Vec<u8> {
        let mut sorted = attributes.to_vec();
        sorted.sort_unstable();
        tlv(SET, sorted.concat())
    }

    /// The parts of a hand-assembled `SignedData`.
    pub(crate) struct CmsParts<'a> {
        /// `eContentType`.
        pub(crate) econtent_type: Oid<'a>,
        /// `eContent`, when attached.
        pub(crate) econtent: Option<&'a [u8]>,
        /// `digestAlgorithm` `AlgorithmIdentifier`.
        pub(crate) digest_algorithm: Vec<u8>,
        /// Signed attributes in their signed `SET` form.
        pub(crate) signed_attributes: Vec<u8>,
        /// The signing key.
        pub(crate) key: &'a TestKey,
        /// The signer certificate.
        pub(crate) signer: &'a [u8],
        /// `SignedData.certificates`.
        pub(crate) certificates: Vec<Vec<u8>>,
        /// Unsigned attributes, each a DER `Attribute`; none when empty.
        pub(crate) unsigned_attributes: Vec<Vec<u8>>,
    }

    /// A `ContentInfo`-wrapped `SignedData` with one `SignerInfo`.
    pub(crate) fn cms(parts: &CmsParts<'_>) -> Vec<u8> {
        let signer = Certificate::from_der(parts.signer).expect("signer parses");
        let mut sid = signer.issuer.as_der().to_vec();
        sid.extend_from_slice(&tlv(INTEGER, signer.serial_der));
        let mut tagged = parts.signed_attributes.clone();
        if let Some(first) = tagged.first_mut() {
            *first = CONTEXT_0;
        }
        let mut signer_info = tlv(INTEGER, [SIGNER_INFO_VERSION]);
        signer_info.extend_from_slice(&tlv(SEQUENCE, sid));
        signer_info.extend_from_slice(&parts.digest_algorithm);
        signer_info.extend_from_slice(&tagged);
        signer_info.extend_from_slice(&parts.key.algorithm_identifier());
        signer_info.extend_from_slice(&tlv(OCTET_STRING, parts.key.sign(&parts.signed_attributes)));
        if !parts.unsigned_attributes.is_empty() {
            let mut unsigned = parts.unsigned_attributes.clone();
            unsigned.sort_unstable();
            signer_info.extend_from_slice(&tlv(CONTEXT_1, unsigned.concat()));
        }

        let mut encapsulated = tlv(OBJECT_IDENTIFIER, parts.econtent_type.as_bytes());
        if let Some(econtent) = parts.econtent {
            encapsulated.extend_from_slice(&tlv(CONTEXT_0, tlv(OCTET_STRING, econtent)));
        }
        let mut body = tlv(INTEGER, [SIGNED_DATA_VERSION]);
        body.extend_from_slice(&tlv(SET, parts.digest_algorithm.clone()));
        body.extend_from_slice(&tlv(SEQUENCE, encapsulated));
        if !parts.certificates.is_empty() {
            body.extend_from_slice(&tlv(CONTEXT_0, parts.certificates.concat()));
        }
        body.extend_from_slice(&tlv(SET, tlv(SEQUENCE, signer_info)));
        let mut content_info = tlv(OBJECT_IDENTIFIER, known::SIGNED_DATA.as_bytes());
        content_info.extend_from_slice(&tlv(CONTEXT_0, tlv(SEQUENCE, body)));
        tlv(SEQUENCE, content_info)
    }

    /// An RFC 3161 token over `imprint` (SHA-256) from the TSA `tsa`,
    /// generated at `generated`.
    pub(crate) fn timestamp_token(
        tsa: &[u8],
        tsa_key: &TestKey,
        imprint: &[u8],
        generated: DateTime,
    ) -> Vec<u8> {
        let mut message_imprint = DigestAlgorithm::Sha256.algorithm_identifier();
        message_imprint.extend_from_slice(&tlv(OCTET_STRING, imprint));
        let mut tst_info = tlv(INTEGER, [TST_INFO_VERSION]);
        tst_info.extend_from_slice(&tlv(OBJECT_IDENTIFIER, TEST_POLICY.as_bytes()));
        tst_info.extend_from_slice(&tlv(SEQUENCE, message_imprint));
        tst_info.extend_from_slice(&tlv(INTEGER, [TOKEN_SERIAL]));
        tst_info.extend_from_slice(&generalized_time(generated));
        let tst_info = tlv(SEQUENCE, tst_info);
        let ess = tlv(
            SEQUENCE,
            tlv(
                SEQUENCE,
                tlv(SEQUENCE, tlv(OCTET_STRING, Sha256::of(tsa).as_bytes())),
            ),
        );
        let attributes = attribute_set(&[
            attribute(
                known::CONTENT_TYPE,
                &tlv(OBJECT_IDENTIFIER, known::TST_INFO.as_bytes()),
            ),
            attribute(
                known::MESSAGE_DIGEST,
                &tlv(OCTET_STRING, Sha256::of(&tst_info).as_bytes()),
            ),
            attribute(known::SIGNING_CERTIFICATE_V2, &ess),
        ]);
        cms(&CmsParts {
            econtent_type: known::TST_INFO,
            econtent: Some(&tst_info),
            digest_algorithm: DigestAlgorithm::Sha256.algorithm_identifier(),
            signed_attributes: attributes,
            key: tsa_key,
            signer: tsa,
            certificates: vec![tsa.to_vec()],
            unsigned_attributes: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{
        CertificateSpec, Curve, OcspSpec, TestKey, ca_extensions, certificate, crl, day,
        ocsp_response,
    };
    use super::{MaterialPool, judge};
    use crate::document::{Revocation, TrustAnchors};
    use crate::sign::validation::ValidationMaterial;
    use crate::x509::OwnedCert;

    /// Root common name.
    const ROOT: &str = "Synthetic Root CA";
    /// Intermediate common name.
    const INTERMEDIATE: &str = "Synthetic Issuing CA";
    /// Signer common name.
    const SIGNER: &str = "Synthetic Signer";
    /// Root serial.
    const ROOT_SERIAL: u8 = 1;
    /// Intermediate serial.
    const INTERMEDIATE_SERIAL: u8 = 2;
    /// Signer serial.
    const SIGNER_SERIAL: u8 = 3;
    /// Day every certificate starts.
    const ISSUED: u8 = 1;
    /// A validation day before [`ENDED_EARLY`].
    const EARLY: u8 = 3;
    /// Day revocation answers are produced.
    const ANSWERED: u8 = 9;
    /// The validation day.
    const VALIDATED: u8 = 10;
    /// Day a short-lived certificate or answer ends, before
    /// [`VALIDATED`].
    const ENDED_EARLY: u8 = 5;
    /// Day long-lived certificates and answers end.
    const ENDS: u8 = 28;

    /// Root, intermediate and signer, each with its key.
    struct Chain {
        /// Root key.
        root_key: TestKey,
        /// Intermediate key.
        intermediate_key: TestKey,
        /// Self-signed root.
        root: Vec<u8>,
        /// Intermediate issued by the root.
        intermediate: Vec<u8>,
        /// Signer issued by the intermediate.
        signer: OwnedCert,
    }

    /// A two-step chain; `intermediate_ends` is the intermediate's
    /// last valid day.
    fn chain(intermediate_ends: u8) -> Chain {
        chain_with(intermediate_ends, ENDS)
    }

    /// A two-step chain with the intermediate's and the signer's last
    /// valid days.
    fn chain_with(intermediate_ends: u8, signer_ends: u8) -> Chain {
        let root_key = TestKey::generate(Curve::P384);
        let intermediate_key = TestKey::generate(Curve::P384);
        let signer_key = TestKey::generate(Curve::P256);
        let root = certificate(
            &CertificateSpec {
                serial: ROOT_SERIAL,
                subject: ROOT,
                issuer: ROOT,
                not_before: day(ISSUED),
                not_after: day(ENDS),
                extensions: ca_extensions(),
            },
            &root_key,
            &root_key,
        );
        let intermediate = certificate(
            &CertificateSpec {
                serial: INTERMEDIATE_SERIAL,
                subject: INTERMEDIATE,
                issuer: ROOT,
                not_before: day(ISSUED),
                not_after: day(intermediate_ends),
                extensions: ca_extensions(),
            },
            &intermediate_key,
            &root_key,
        );
        let signer = certificate(
            &CertificateSpec {
                serial: SIGNER_SERIAL,
                subject: SIGNER,
                issuer: INTERMEDIATE,
                not_before: day(ISSUED),
                not_after: day(signer_ends),
                extensions: Vec::new(),
            },
            &signer_key,
            &intermediate_key,
        );
        Chain {
            root_key,
            intermediate_key,
            root,
            intermediate,
            signer: OwnedCert::from_der(signer).expect("signer parses"),
        }
    }

    impl Chain {
        /// The pool a document carrying the intermediate, plus the
        /// caller's root, gives.
        fn pool(&self) -> MaterialPool {
            let mut pool = MaterialPool::new();
            pool.add_material(&ValidationMaterial {
                certificates: vec![self.intermediate.clone()],
                ocsp_responses: Vec::new(),
                crls: Vec::new(),
            });
            pool.add_certificates(core::slice::from_ref(&self.root));
            pool
        }

        /// An OCSP answer about the signer, signed by the intermediate.
        fn ocsp(&self, revoked: bool, next_update: u8) -> Vec<u8> {
            self.ocsp_on(revoked, ANSWERED, next_update)
        }

        /// An OCSP answer about the signer produced on `answered`.
        fn ocsp_on(&self, revoked: bool, answered: u8, next_update: u8) -> Vec<u8> {
            self.ocsp_until(revoked, answered, Some(next_update))
        }

        /// An OCSP answer about the intermediate, signed by the root.
        fn intermediate_ocsp(&self, revoked: bool) -> Vec<u8> {
            let issuer = OwnedCert::from_der(&self.root).expect("root parses");
            ocsp_response(&OcspSpec {
                responder_key: &self.root_key,
                responder: ROOT,
                issuer: &issuer,
                serial: INTERMEDIATE_SERIAL,
                revoked: revoked.then(|| day(ISSUED)),
                produced_at: day(ANSWERED),
                this_update: day(ANSWERED),
                next_update: Some(day(ENDS)),
                embedded: Vec::new(),
            })
        }

        /// An OCSP answer about the signer produced on `answered`, with
        /// `nextUpdate` on `next_update` when given.
        fn ocsp_until(&self, revoked: bool, answered: u8, next_update: Option<u8>) -> Vec<u8> {
            let issuer = OwnedCert::from_der(&self.intermediate).expect("intermediate parses");
            ocsp_response(&OcspSpec {
                responder_key: &self.intermediate_key,
                responder: INTERMEDIATE,
                issuer: &issuer,
                serial: SIGNER_SERIAL,
                revoked: revoked.then(|| day(ISSUED)),
                produced_at: day(answered),
                this_update: day(answered),
                next_update: next_update.map(day),
                embedded: Vec::new(),
            })
        }
    }

    #[test]
    fn a_two_step_path_to_a_trusted_root_is_anchored() {
        let chain = chain(ENDS);
        let anchors = [chain.root.as_slice()];
        let verdict = judge(
            &chain.signer,
            &chain.pool(),
            TrustAnchors::new(&anchors),
            day(VALIDATED),
        );
        assert!(verdict.anchored);
        assert_eq!(
            verdict.issuer.map(OwnedCert::into_der),
            Some(chain.intermediate.clone())
        );
        assert_eq!(verdict.revocation, Revocation::Unavailable);
    }

    #[test]
    fn a_root_outside_the_anchors_leaves_the_path_unanchored() {
        let chain = chain(ENDS);
        let verdict = judge(
            &chain.signer,
            &chain.pool(),
            TrustAnchors::new(&[]),
            day(VALIDATED),
        );
        assert!(!verdict.anchored);
        assert_eq!(
            verdict.issuer.map(OwnedCert::into_der),
            Some(chain.intermediate.clone())
        );
    }

    #[test]
    fn an_issuer_expired_at_the_validation_time_is_no_issuer() {
        let chain = chain(ENDED_EARLY);
        let anchors = [chain.root.as_slice()];
        let verdict = judge(
            &chain.signer,
            &chain.pool(),
            TrustAnchors::new(&anchors),
            day(VALIDATED),
        );
        assert!(!verdict.anchored);
        assert!(verdict.issuer.is_none());
        assert_eq!(verdict.revocation, Revocation::Unavailable);
    }

    #[test]
    fn a_signer_expired_at_the_validation_time_is_not_anchored() {
        let chain = chain_with(ENDS, ENDED_EARLY);
        let anchors = [chain.root.as_slice()];
        let verdict = judge(
            &chain.signer,
            &chain.pool(),
            TrustAnchors::new(&anchors),
            day(VALIDATED),
        );
        assert!(!verdict.anchored);
        assert_eq!(
            verdict.issuer.map(OwnedCert::into_der),
            Some(chain.intermediate.clone())
        );
    }

    #[test]
    fn a_verified_good_ocsp_answer_is_good_as_of_its_production() {
        let chain = chain(ENDS);
        let mut pool = chain.pool();
        pool.add_material(&ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses: vec![chain.ocsp(false, ENDS), chain.intermediate_ocsp(false)],
            crls: Vec::new(),
        });
        let anchors = [chain.root.as_slice()];
        let verdict = judge(
            &chain.signer,
            &pool,
            TrustAnchors::new(&anchors),
            day(VALIDATED),
        );
        assert_eq!(
            verdict.revocation,
            Revocation::Good {
                checked_at: day(ANSWERED)
            }
        );
    }

    #[test]
    fn a_verified_revoked_ocsp_answer_is_revoked() {
        let chain = chain(ENDS);
        let mut pool = chain.pool();
        pool.add_material(&ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses: vec![chain.ocsp(true, ENDS)],
            crls: Vec::new(),
        });
        let verdict = judge(&chain.signer, &pool, TrustAnchors::new(&[]), day(VALIDATED));
        assert_eq!(verdict.revocation, Revocation::Revoked);
    }

    /// A pool of the chain plus one OCSP answer.
    fn pool_with_ocsp(chain: &Chain, answer: Vec<u8>) -> MaterialPool {
        let mut pool = chain.pool();
        pool.add_material(&ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses: vec![answer],
            crls: Vec::new(),
        });
        pool
    }

    #[test]
    fn an_answer_that_expired_before_the_validation_time_is_unavailable() {
        let chain = chain(ENDS);
        let pool = pool_with_ocsp(&chain, chain.ocsp_on(false, ISSUED, ENDED_EARLY));
        let verdict = judge(&chain.signer, &pool, TrustAnchors::new(&[]), day(VALIDATED));
        assert_eq!(verdict.revocation, Revocation::Unavailable);
    }

    #[test]
    fn an_answer_produced_after_the_validation_time_within_the_signer_validity_is_good() {
        let chain = chain(ENDS);
        let pool = pool_with_ocsp(&chain, chain.ocsp(false, ENDS));
        let verdict = judge(
            &chain.signer,
            &pool,
            TrustAnchors::new(&[]),
            day(ENDED_EARLY),
        );
        assert_eq!(
            verdict.revocation,
            Revocation::Good {
                checked_at: day(ANSWERED)
            }
        );
    }

    #[test]
    fn an_answer_produced_after_the_signer_expired_is_unavailable() {
        let chain = chain_with(ENDS, ENDED_EARLY);
        let pool = pool_with_ocsp(&chain, chain.ocsp(false, ENDS));
        let verdict = judge(&chain.signer, &pool, TrustAnchors::new(&[]), day(EARLY));
        assert_eq!(verdict.revocation, Revocation::Unavailable);
    }

    #[test]
    fn a_revoked_answer_counts_whatever_its_time() {
        let chain = chain(ENDS);
        let pool = pool_with_ocsp(&chain, chain.ocsp_on(true, ISSUED, ENDED_EARLY));
        let verdict = judge(&chain.signer, &pool, TrustAnchors::new(&[]), day(VALIDATED));
        assert_eq!(verdict.revocation, Revocation::Revoked);
    }

    #[test]
    fn an_ocsp_answer_signed_by_a_stranger_is_unavailable() {
        let chain = chain(ENDS);
        let issuer = OwnedCert::from_der(&chain.intermediate).expect("intermediate parses");
        let forged = ocsp_response(&OcspSpec {
            responder_key: &chain.root_key,
            responder: INTERMEDIATE,
            issuer: &issuer,
            serial: SIGNER_SERIAL,
            revoked: None,
            produced_at: day(ANSWERED),
            this_update: day(ANSWERED),
            next_update: None,
            embedded: Vec::new(),
        });
        let mut pool = chain.pool();
        pool.add_material(&ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses: vec![forged],
            crls: Vec::new(),
        });
        let verdict = judge(&chain.signer, &pool, TrustAnchors::new(&[]), day(VALIDATED));
        assert_eq!(verdict.revocation, Revocation::Unavailable);
    }

    #[test]
    fn a_verified_crl_listing_the_signer_is_revoked_and_one_without_is_good() {
        let chain = chain(ENDS);
        let listing = crl(
            INTERMEDIATE,
            &chain.intermediate_key,
            day(ANSWERED),
            Some(day(ENDS)),
            &[SIGNER_SERIAL],
            day(ISSUED),
        );
        let mut pool = chain.pool();
        pool.add_material(&ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses: Vec::new(),
            crls: vec![listing],
        });
        let verdict = judge(&chain.signer, &pool, TrustAnchors::new(&[]), day(VALIDATED));
        assert_eq!(verdict.revocation, Revocation::Revoked);

        let clean = crl(
            INTERMEDIATE,
            &chain.intermediate_key,
            day(ANSWERED),
            Some(day(ENDS)),
            &[ROOT_SERIAL],
            day(ISSUED),
        );
        let mut pool = chain.pool();
        pool.add_material(&ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses: Vec::new(),
            crls: vec![clean],
        });
        let verdict = judge(&chain.signer, &pool, TrustAnchors::new(&[]), day(VALIDATED));
        assert_eq!(
            verdict.revocation,
            Revocation::Good {
                checked_at: day(ANSWERED)
            }
        );
    }

    /// A pool of the chain plus these OCSP answers and CRLs.
    fn pool_with(chain: &Chain, ocsp_responses: Vec<Vec<u8>>, crls: Vec<Vec<u8>>) -> MaterialPool {
        let mut pool = chain.pool();
        pool.add_material(&ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses,
            crls,
        });
        pool
    }

    #[test]
    fn a_crl_revocation_outweighs_an_ocsp_good() {
        let chain = chain(ENDS);
        let listing = crl(
            INTERMEDIATE,
            &chain.intermediate_key,
            day(ANSWERED),
            Some(day(ENDS)),
            &[SIGNER_SERIAL],
            day(ISSUED),
        );
        let pool = pool_with(
            &chain,
            vec![chain.ocsp(false, ENDS), chain.intermediate_ocsp(false)],
            vec![listing],
        );
        let anchors = [chain.root.as_slice()];
        let verdict = judge(
            &chain.signer,
            &pool,
            TrustAnchors::new(&anchors),
            day(VALIDATED),
        );
        assert!(verdict.anchored);
        assert_eq!(verdict.revocation, Revocation::Revoked);
    }

    #[test]
    fn a_revoked_intermediate_revokes_the_path() {
        let chain = chain(ENDS);
        let pool = pool_with(
            &chain,
            vec![chain.ocsp(false, ENDS), chain.intermediate_ocsp(true)],
            Vec::new(),
        );
        let anchors = [chain.root.as_slice()];
        let verdict = judge(
            &chain.signer,
            &pool,
            TrustAnchors::new(&anchors),
            day(VALIDATED),
        );
        assert_eq!(verdict.revocation, Revocation::Revoked);
    }

    #[test]
    fn an_unanswered_intermediate_leaves_the_path_unavailable() {
        let chain = chain(ENDS);
        let pool = pool_with(&chain, vec![chain.ocsp(false, ENDS)], Vec::new());
        let anchors = [chain.root.as_slice()];
        let verdict = judge(
            &chain.signer,
            &pool,
            TrustAnchors::new(&anchors),
            day(VALIDATED),
        );
        assert!(verdict.anchored);
        assert_eq!(verdict.revocation, Revocation::Unavailable);

        // The signer's own answer is good.
        let verdict = judge(&chain.signer, &pool, TrustAnchors::new(&[]), day(VALIDATED));
        assert_eq!(
            verdict.revocation,
            Revocation::Good {
                checked_at: day(ANSWERED)
            }
        );
    }

    #[test]
    fn an_answer_without_next_update_counts_only_when_produced_after_the_validation_time() {
        let chain = chain(ENDS);
        let early = pool_with(
            &chain,
            vec![chain.ocsp_until(false, ISSUED, None)],
            Vec::new(),
        );
        let verdict = judge(
            &chain.signer,
            &early,
            TrustAnchors::new(&[]),
            day(VALIDATED),
        );
        assert_eq!(verdict.revocation, Revocation::Unavailable);

        let later = pool_with(
            &chain,
            vec![chain.ocsp_until(false, ANSWERED, None)],
            Vec::new(),
        );
        let verdict = judge(&chain.signer, &later, TrustAnchors::new(&[]), day(EARLY));
        assert_eq!(
            verdict.revocation,
            Revocation::Good {
                checked_at: day(ANSWERED)
            }
        );
    }

    #[test]
    fn the_pool_holds_each_item_once_and_skips_unreadable_ones() {
        let chain = chain(ENDS);
        let mut pool = chain.pool();
        pool.add_certificates(&[chain.root.clone(), b"not a certificate".to_vec()]);
        assert_eq!(pool.certificates.len(), 2);
    }
}
