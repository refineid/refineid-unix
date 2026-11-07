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

//! The anchors a signing request's long-term material may end at:
//! `DocumentRequest::signer_anchors`.
//!
//! refineid-core ships no root and refuses an LT or LTA request that
//! names no anchor before the reader is opened
//! (`MaterialError::NoTrustAnchor`), so every request leaves here
//! with what this computer has: the card's issuing CA and root from
//! the CA cache ([`crate::ca_certificates`]), read from the card and
//! cached on a miss while a card is in a reader, and the
//! certificate-issuing anchors of the EU trusted lists
//! ([`crate::trusted_lists`]). The paired phone's card is not in a
//! reader here, so a phone request carries the cache and the lists.

use refineid_doc_sign::x509::DateTime;
use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _, ReaderFilter};
use refineid_lib_core::cert_state::CertDer;
use refineid_lib_core::pkcs15::{CertSlot, FineidReaderPicker as _, Pkcs15Ops as _};
use refineid_lib_pcsc::PcscBackend;

use crate::ca_certificates::CaCache;
use crate::trusted_lists::{AnchorSource, Refresh};

/// The anchors of one signing run and where the lists stood.
#[derive(Debug)]
pub struct SignerAnchors {
    /// The DER of every anchor, each once.
    pub ders: Vec<Vec<u8>>,
    /// Where the trusted lists' anchors came from.
    pub lists: AnchorSource,
}

impl SignerAnchors {
    /// Whether no anchor is at hand: core refuses a long-term
    /// request so.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ders.is_empty()
    }
}

/// The anchors for signing with the paired phone at `now`: the
/// cached CA certificates and the lists' certificate-issuing anchors.
#[must_use]
pub fn for_phone(now: DateTime) -> SignerAnchors {
    let cached = CaCache::user().map_or_else(Vec::new, |cache| cache.load(now));
    collect(cached, now)
}

/// The anchors for signing with the card in a reader at `now`: the
/// cached CA certificates, read from the card and cached when the
/// cache holds none, and the lists' certificate-issuing anchors.
/// `reader_filter` names the reader as the signing does.
#[must_use]
pub fn for_card(reader_filter: Option<&str>, now: DateTime) -> SignerAnchors {
    let cache = CaCache::user();
    let mut cached = cache
        .as_ref()
        .map_or_else(Vec::new, |cache| cache.load(now));
    if cached.is_empty() {
        let (issuing_ca, root) = read_card_ca_certificates(reader_filter);
        cached = crate::ca_certificates::admit(
            issuing_ca.as_ref().map(CertDer::as_bytes),
            root.as_ref().map(CertDer::as_bytes),
            now,
        );
        if let Some(cache) = &cache
            && let Err(error) = cache.store(&cached)
        {
            let kind = error.kind();
            refineid_dev_errors::report!(Cli, "CA certificates not cached", kind);
        }
    }
    collect(cached, now)
}

/// `certificates` and the lists' certificate-issuing anchors, each
/// DER once.
fn collect(certificates: Vec<refineid_doc_sign::x509::OwnedCert>, now: DateTime) -> SignerAnchors {
    let run = crate::trusted_lists::user_anchors(now, Refresh::WhenDue);
    let mut ders: Vec<Vec<u8>> = Vec::new();
    for der in certificates
        .iter()
        .map(|certificate| certificate.as_der().to_vec())
        .chain(crate::trusted_lists::certificate_issuing_ders(
            &run.anchors,
            now,
        ))
    {
        if !ders.contains(&der) {
            ders.push(der);
        }
    }
    SignerAnchors {
        ders,
        lists: run.source,
    }
}

/// The issuing CA (`EF.4336`) and root (`EF.4334`) of the card in the
/// reader `reader_filter` names, each when the card holds and serves
/// it. Both live under the MF, which a PACE channel cannot reach, so
/// a contactless card yields nothing and its anchors are the cache
/// and the lists.
fn read_card_ca_certificates(reader_filter: Option<&str>) -> (Option<CertDer>, Option<CertDer>) {
    let backend = PcscBackend;
    let filter = reader_filter.map(ReaderFilter::new);
    let pick = match backend.pick_fineid_reader(filter.as_ref()) {
        Ok(pick) => pick,
        Err(error) => {
            refineid_dev_errors::report!(Cli, "no card to read CA certificates from", error);
            return (None, None);
        }
    };
    let mut transport = match backend.open_session(&pick.reader_id, ReaderAccessCap::Read) {
        Ok(transport) => transport,
        Err(error) => {
            refineid_dev_errors::report!(Cli, "card not opened for CA certificates", error);
            return (None, None);
        }
    };
    if let Err(error) = transport.select_pkcs15_application() {
        refineid_dev_errors::report!(Cli, "PKCS#15 application not selected", error);
        return (None, None);
    }
    let issuing_ca = transport.read_certificate(CertSlot::IssuingCaEcc).ok();
    let root = transport.read_certificate(CertSlot::RootCa).ok();
    (issuing_ca, root)
}
