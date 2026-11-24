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

//! X.509 certificate parsing, verification, and extension helpers.
//!
//! Re-exports the shared X.509 parser and verifiers from
//! [`refineid_cms::x509`] alongside the platform helpers that produce
//! `refineid-lib-core` domain types ([`crate::text::Uri`],
//! [`crate::identity::EmailAddress`], [`crate::identity::CertSerial`],
//! [`crate::country::IsoAlpha2`]).

#![expect(
    clippy::pub_use,
    reason = "library-facade pattern: re-exports refineid_cms::x509 alongside local typed extractors"
)]

use crate::ber::{BerTlv, BerTlvAny, BerTlvIter, Sequence};
use crate::oid::{Oid, known};
use spki::der::asn1::AnyRef;
use spki::der::{Decode as _, Reader as _, SliceReader, Tag, TagNumber, Tagged as _};

pub use refineid_cms::x509::*;

/// `GeneralName` IMPLICIT `[1]` `rfc822Name` tag.
const TAG_GN_RFC822_NAME: u16 = 0x81;
/// `GeneralName` IMPLICIT `[6]` `uniformResourceIdentifier` tag.
const TAG_GN_URI: u16 = 0x86;
/// `DistributionPoint.distributionPoint` EXPLICIT `[0]` tag.
const TAG_DP_DISTRIBUTION_POINT_NAME: u16 = 0xA0;
/// `DistributionPointName.fullName` IMPLICIT `[0]` tag.
const TAG_DP_FULL_NAME: u16 = 0xA0;
/// `GeneralName.uniformResourceIdentifier` context tag number (RFC 5280).
const GN_URI_TAG_NUMBER: u32 = 6;

/// Extract a certificate's serial number as a typed [`crate::identity::CertSerial`].
#[must_use]
#[inline]
pub fn cert_serial(certificate: &Certificate<'_>) -> crate::identity::CertSerial {
    crate::identity::CertSerial::from_bytes(certificate.serial_der.as_bytes().iter().copied())
}

/// Extract `countryName` (OID 2.5.4.6) from a parsed [`Name`] as an ISO 3166-1 alpha-2 code.
#[must_use]
#[inline]
pub fn name_country(name: Name<'_>) -> Option<crate::country::IsoAlpha2> {
    crate::country::IsoAlpha2::new(name.dn_attribute(known::COUNTRY_NAME)?.trim()).ok()
}

/// Find the first extension whose OID matches `oid_value` and return the
/// wrapped `extnValue` OCTET STRING contents.
fn find_extension<'a>(extensions: &'a [u8], oid_value: Oid<'_>) -> Option<&'a [u8]> {
    let mut reader = SliceReader::new(extensions).ok()?;
    while !reader.is_finished() {
        let Ok(ext_bytes) = reader.tlv_bytes() else {
            break;
        };
        let Ok(ext) = AnyRef::from_der(ext_bytes) else {
            continue;
        };
        if ext.tag() != Tag::Sequence {
            continue;
        }
        let Ok(mut fields) = SliceReader::new(ext.value()) else {
            continue;
        };
        let Ok(oid_bytes) = fields.tlv_bytes() else {
            continue;
        };
        let Ok(oid) = AnyRef::from_der(oid_bytes) else {
            continue;
        };
        if oid.tag() != Tag::ObjectIdentifier || oid.value() != oid_value.as_bytes() {
            continue;
        }
        let Ok(mut next) = fields.tlv_bytes().and_then(AnyRef::from_der) else {
            return None;
        };
        if next.tag() == Tag::Boolean {
            let Ok(val) = fields.tlv_bytes().and_then(AnyRef::from_der) else {
                return None;
            };
            next = val;
        }
        if next.tag() != Tag::OctetString || !fields.is_finished() {
            return None;
        }
        return Some(next.value());
    }
    None
}

/// Extract HTTP(S) `GeneralName` URI entries from an Authority Information
/// Access extension matching `access_method`.
fn aia_urls_for(extensions: &[u8], access_method: Oid<'_>) -> Vec<crate::text::Uri> {
    const GN_URI: Tag = Tag::ContextSpecific {
        constructed: false,
        number: TagNumber(GN_URI_TAG_NUMBER),
    };

    let mut urls = Vec::new();
    let Some(extn_value) = find_extension(extensions, known::AUTHORITY_INFO_ACCESS) else {
        return urls;
    };
    let Ok(outer) = AnyRef::from_der(extn_value) else {
        return urls;
    };
    if outer.tag() != Tag::Sequence {
        return urls;
    }
    let Ok(mut reader) = SliceReader::new(outer.value()) else {
        return urls;
    };
    while !reader.is_finished() {
        let Ok(ad_bytes) = reader.tlv_bytes() else {
            break;
        };
        let Ok(ad) = AnyRef::from_der(ad_bytes) else {
            continue;
        };
        if ad.tag() != Tag::Sequence {
            continue;
        }
        let Ok(mut fields) = SliceReader::new(ad.value()) else {
            continue;
        };
        let Ok(oid) = fields.tlv_bytes().map(AnyRef::from_der) else {
            continue;
        };
        let Ok(oid) = oid else { continue };
        if oid.tag() != Tag::ObjectIdentifier || oid.value() != access_method.as_bytes() {
            continue;
        }
        let Ok(loc) = fields.tlv_bytes().and_then(AnyRef::from_der) else {
            continue;
        };
        if !fields.is_finished() {
            continue;
        }
        if loc.tag() == GN_URI
            && let Ok(s) = core::str::from_utf8(loc.value())
            && let Ok(url) = crate::text::Uri::parse(s.to_owned())
        {
            urls.push(url);
        }
    }
    urls
}

/// Extract CRL distribution-point URLs from a parsed extensions block.
#[must_use]
#[inline]
pub fn extract_crl_distribution_urls<B: AsRef<[u8]>>(extensions: B) -> Vec<crate::text::Uri> {
    let extensions = extensions.as_ref();
    let Some(extn_value) = find_extension(extensions, known::CRL_DISTRIBUTION_POINTS) else {
        return Vec::new();
    };
    let Ok(outer) = BerTlv::<Sequence>::parse(extn_value) else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    for dp in BerTlvIter::new(outer.value()) {
        let Ok(dp) = dp.and_then(BerTlvAny::expect::<Sequence>) else {
            continue;
        };
        for field in BerTlvIter::new(dp.value()) {
            let Ok(field) = field else { continue };
            if field.tag() != TAG_DP_DISTRIBUTION_POINT_NAME {
                continue;
            }
            for gn_wrap in BerTlvIter::new(field.value()) {
                let Ok(gn_wrap) = gn_wrap else { continue };
                if gn_wrap.tag() != TAG_DP_FULL_NAME {
                    continue;
                }
                for gn in BerTlvIter::new(gn_wrap.value()) {
                    let Ok(gn) = gn else { continue };
                    if gn.tag() == TAG_GN_URI
                        && let Ok(s) = core::str::from_utf8(gn.value())
                        && let Ok(url) = crate::text::Uri::parse(s.to_owned())
                    {
                        urls.push(url);
                    }
                }
            }
        }
    }
    urls
}

/// Extract OCSP responder URLs from the Authority Information Access extension.
#[must_use]
#[inline]
pub fn extract_ocsp_urls<B: AsRef<[u8]>>(extensions: B) -> Vec<crate::text::Uri> {
    aia_urls_for(extensions.as_ref(), known::AD_OCSP)
}

/// Extract `caIssuers` URLs from the Authority Information Access extension.
#[must_use]
#[inline]
pub fn extract_ca_issuers_urls<B: AsRef<[u8]>>(extensions: B) -> Vec<crate::text::Uri> {
    aia_urls_for(extensions.as_ref(), known::AD_CA_ISSUERS)
}

/// Extract email addresses from a `subjectAltName` extension's `rfc822Name`
/// entries.
#[must_use]
#[inline]
pub fn extract_subject_alt_emails<B: AsRef<[u8]>>(
    extensions: B,
) -> Vec<crate::identity::EmailAddress> {
    let extensions = extensions.as_ref();
    let Some(extn_value) = find_extension(extensions, known::SUBJECT_ALT_NAME) else {
        return Vec::new();
    };
    let Ok(outer) = BerTlv::<Sequence>::parse(extn_value) else {
        return Vec::new();
    };
    let mut emails = Vec::new();
    for gn in BerTlvIter::new(outer.value()) {
        let Ok(gn) = gn else { continue };
        if gn.tag() == TAG_GN_RFC822_NAME
            && let Ok(s) = core::str::from_utf8(gn.value())
            && let Ok(email) = crate::identity::EmailAddress::new(s)
        {
            emails.push(email);
        }
    }
    emails
}

#[cfg(test)]
mod tests {
    use super::{
        Name, TAG_DP_DISTRIBUTION_POINT_NAME, TAG_DP_FULL_NAME, TAG_GN_RFC822_NAME, TAG_GN_URI,
        extract_ca_issuers_urls, extract_crl_distribution_urls, extract_ocsp_urls,
        extract_subject_alt_emails, name_country,
    };
    use crate::oid::{Oid, known};

    const DER_TAG_SEQUENCE: u8 = 0x30;
    const DER_TAG_SET: u8 = 0x31;
    const DER_TAG_OCTET_STRING: u8 = 0x04;
    const DER_TAG_OID: u8 = 0x06;
    const DER_TAG_PRINTABLE_STRING: u8 = 0x13;
    const SHORT_FORM_LEN_MAX: usize = 0x7F;
    const LONG_FORM_ONE_BYTE_LEN: u8 = 0x81;

    // noinspection HttpUrlsUsage
    const TEST_CRL_URL: &str = "http://crl.example.com/example.crl";
    // noinspection HttpUrlsUsage
    const TEST_OCSP_URL: &str = "http://ocsp.example.com/";
    // noinspection HttpUrlsUsage
    const TEST_CA_ISSUERS_URL: &str = "http://ca.example.com/issuer.crt";

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() <= SHORT_FORM_LEN_MAX {
            out.push(u8::try_from(value.len()).expect("short-form length fits u8"));
        } else {
            out.push(LONG_FORM_ONE_BYTE_LEN);
            out.push(u8::try_from(value.len()).expect("one-byte long-form length fits u8"));
        }
        out.extend_from_slice(value);
        out
    }

    fn extension(oid: Oid<'_>, inner_der: &[u8]) -> Vec<u8> {
        let mut body = tlv(DER_TAG_OID, oid.as_bytes());
        body.extend_from_slice(&tlv(DER_TAG_OCTET_STRING, inner_der));
        tlv(DER_TAG_SEQUENCE, &body)
    }

    #[test]
    fn extracts_crl_distribution_urls() {
        let gn_uri_tag = u8::try_from(TAG_GN_URI).expect("tag fits u8");
        let dp_full_tag = u8::try_from(TAG_DP_FULL_NAME).expect("tag fits u8");
        let dp_name_tag = u8::try_from(TAG_DP_DISTRIBUTION_POINT_NAME).expect("tag fits u8");

        let gn = tlv(gn_uri_tag, TEST_CRL_URL.as_bytes());
        let dp_full = tlv(dp_full_tag, &gn);
        let dp_name = tlv(dp_name_tag, &dp_full);
        let dp = tlv(DER_TAG_SEQUENCE, &dp_name);
        let cdp_seq = tlv(DER_TAG_SEQUENCE, &dp);
        let ext = extension(known::CRL_DISTRIBUTION_POINTS, &cdp_seq);

        let urls = extract_crl_distribution_urls(&ext);
        let rendered: Vec<String> = urls.iter().map(ToString::to_string).collect();
        assert_eq!(rendered, vec![TEST_CRL_URL.to_owned()]);
    }

    #[test]
    fn extracts_ocsp_and_ca_issuers_urls() {
        let gn_uri_tag = u8::try_from(TAG_GN_URI).expect("tag fits u8");

        let mut ocsp_ad = tlv(DER_TAG_OID, known::AD_OCSP.as_bytes());
        ocsp_ad.extend_from_slice(&tlv(gn_uri_tag, TEST_OCSP_URL.as_bytes()));
        let mut issuers_ad = tlv(DER_TAG_OID, known::AD_CA_ISSUERS.as_bytes());
        issuers_ad.extend_from_slice(&tlv(gn_uri_tag, TEST_CA_ISSUERS_URL.as_bytes()));

        let mut aia_body = tlv(DER_TAG_SEQUENCE, &ocsp_ad);
        aia_body.extend_from_slice(&tlv(DER_TAG_SEQUENCE, &issuers_ad));
        let aia_seq = tlv(DER_TAG_SEQUENCE, &aia_body);
        let ext = extension(known::AUTHORITY_INFO_ACCESS, &aia_seq);

        let ocsp: Vec<String> = extract_ocsp_urls(&ext)
            .iter()
            .map(ToString::to_string)
            .collect();
        let issuers: Vec<String> = extract_ca_issuers_urls(&ext)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(ocsp, vec![TEST_OCSP_URL.to_owned()]);
        assert_eq!(issuers, vec![TEST_CA_ISSUERS_URL.to_owned()]);
    }

    #[test]
    fn extracts_subject_alt_emails() {
        let gn_email_tag = u8::try_from(TAG_GN_RFC822_NAME).expect("tag fits u8");
        let gn = tlv(gn_email_tag, b"holder@example.fi");
        let san_seq = tlv(DER_TAG_SEQUENCE, &gn);
        let ext = extension(known::SUBJECT_ALT_NAME, &san_seq);

        let emails = extract_subject_alt_emails(&ext);
        assert_eq!(emails, vec!["holder@example.fi"]);
    }

    #[test]
    fn extracts_country_from_name() {
        let mut atv_body = tlv(DER_TAG_OID, known::COUNTRY_NAME.as_bytes());
        atv_body.extend_from_slice(&tlv(DER_TAG_PRINTABLE_STRING, b"FI"));
        let rdn = tlv(DER_TAG_SET, &tlv(DER_TAG_SEQUENCE, &atv_body));
        let dn = tlv(DER_TAG_SEQUENCE, &rdn);
        let name = Name::try_from(dn.as_slice()).expect("valid DN parses");
        let country = name_country(name).expect("country attribute parses");
        assert_eq!(country.as_str(), "FI");
    }
}
