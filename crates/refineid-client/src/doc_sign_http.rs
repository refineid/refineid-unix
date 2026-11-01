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

//! This crate's HTTP and TLS stack as the transport of
//! `refineid_doc_sign`: timestamp requests, chain and revocation
//! fetches while signing, and the live revocation lookup of
//! `document verify`.
//!
//! Core vets every certificate-published URL before the transport is
//! called and hands over the addresses it checked; the first hop
//! connects to one of them, and a redirect connects only to what
//! `refineid_doc_sign::http::guard_destination` returns for its target.
//! Core resolves through [`HttpTransport::resolve`], which is this
//! crate's DNSSEC-first resolver.
//! Every request names this client with [`crate::user_agent::honest`].

use core::cell::Cell;
use std::net::SocketAddr;
use std::sync::Once;

use refineid_doc_sign::http::{self as core_http, HttpError as CoreError, HttpTransport};
use refineid_doc_sign::uri::Uri as CoreUri;
use refineid_lib_core::text::Uri;

use crate::http::{self, HttpError};
use crate::user_agent;

/// Register this crate's transport with `refineid_doc_sign`, once per
/// process. Every entry point that signs or verifies a document calls
/// it before the first request.
pub fn install() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| core_http::set_http_transport(Box::new(UnixTransport)));
}

/// The transport [`install`] registers.
#[derive(Debug, Clone, Copy)]
struct UnixTransport;

impl HttpTransport for UnixTransport {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, CoreError> {
        http::resolve_host(host, port).map_err(core_error)
    }

    fn get(
        &self,
        url: &CoreUri,
        addresses: &[SocketAddr],
        max_bytes: usize,
    ) -> Result<Vec<u8>, CoreError> {
        let first = Cell::new(addresses.first().copied());
        http::get_to(&unix_uri(url)?, max_bytes, user_agent::honest(), &|hop| {
            vetted(&first, hop)
        })
        .map_err(core_error)
    }

    fn post(
        &self,
        url: &CoreUri,
        addresses: &[SocketAddr],
        content_type: &str,
        body: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>, CoreError> {
        let first = Cell::new(addresses.first().copied());
        http::post_to(
            &unix_uri(url)?,
            content_type,
            body,
            max_bytes,
            user_agent::honest(),
            &|hop| vetted(&first, hop),
        )
        .map_err(core_error)
    }

    fn post_authority(
        &self,
        url: &CoreUri,
        content_type: &str,
        body: &[u8],
        max_bytes: usize,
        auth_header: Option<&str>,
    ) -> Result<Vec<u8>, CoreError> {
        http::post_authority(
            &unix_uri(url)?,
            content_type,
            body,
            max_bytes,
            user_agent::honest(),
            auth_header,
        )
        .map_err(core_error)
    }
}

/// Where one hop connects: the address core vetted for the first hop,
/// then for each redirect the first address `guard_destination`
/// returns for its target.
fn vetted(first: &Cell<Option<SocketAddr>>, hop: &Uri) -> Result<SocketAddr, HttpError> {
    if let Some(address) = first.take() {
        return Ok(address);
    }
    let target = CoreUri::parse(hop.to_string())
        .map_err(|error| HttpError::UnsafeRedirect(error.to_string()))?;
    core_http::guard_destination(&UnixTransport, &target)
        .map_err(|error| HttpError::UnsafeDestination(error.to_string()))?
        .into_iter()
        .next()
        .ok_or(HttpError::BadUrl("no address resolved"))
}

/// The same URL in this crate's type.
fn unix_uri(url: &CoreUri) -> Result<Uri, CoreError> {
    Uri::parse(url.to_string()).map_err(|_error| CoreError::BadUrl("URL does not parse"))
}

/// The same failure in core's type; the two enumerations name the same
/// cases.
fn core_error(error: HttpError) -> CoreError {
    match error {
        HttpError::BadUrl(detail) => CoreError::BadUrl(detail),
        HttpError::UnsupportedScheme(scheme) => CoreError::UnsupportedScheme(scheme),
        HttpError::Io(source) => CoreError::Io(source),
        HttpError::BadStatusLine(line) => CoreError::BadStatusLine(line),
        HttpError::HttpStatus {
            code,
            reason,
            location,
        } => CoreError::HttpStatus {
            code,
            reason,
            location,
        },
        HttpError::UnknownBodyLength => CoreError::UnknownBodyLength,
        HttpError::BadChunkSize(size) => CoreError::BadChunkSize(size),
        HttpError::BodyTooLarge {
            content_length,
            limit,
        } => CoreError::BodyTooLarge {
            content_length,
            limit,
        },
        HttpError::UnsafeDestination(detail) => CoreError::UnsafeDestination(detail),
        HttpError::UnsafeRedirect(detail) => CoreError::UnsafeRedirect(detail),
        HttpError::InsecureCredentials => CoreError::InsecureCredentials,
        HttpError::Https { detail, retryable } => CoreError::Https { detail, retryable },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check, check_true};
    use std::net::{IpAddr, Ipv4Addr};

    /// A synthetic vetted address, in TEST-NET-3.
    const VETTED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 80);

    #[test]
    fn the_first_hop_connects_where_core_vetted() -> TestResult {
        let first = Cell::new(Some(VETTED));
        let hop = Uri::parse("http://ocsp.example/".to_owned())?;
        check(&vetted(&first, &hop)?, &VETTED, "first hop")?;
        check(&first.get(), &None, "used once")
    }

    #[test]
    fn a_redirect_to_a_local_host_is_refused() -> TestResult {
        let first = Cell::new(None);
        let hop = Uri::parse("http://127.0.0.1/".to_owned())?;
        check_true(
            matches!(vetted(&first, &hop), Err(HttpError::UnsafeDestination(_))),
            "a loopback redirect target is refused",
        )
    }

    #[test]
    fn a_url_keeps_its_parts_across_the_two_types() -> TestResult {
        let core = CoreUri::parse("https://tsa.example:8443/path?q=1".to_owned())?;
        let unix = unix_uri(&core).map_err(|error| error.to_string())?;
        check(&unix.to_string(), &core.to_string(), "same URL")
    }
}
