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

//! Client certificate authentication using remote RAPP card readers over TLS.
//!
//! The certificate is offered only on a session the phone opened and on
//! which it reports a card (RAPP v26.10.18 section 8.4): the resolver
//! opens the session when the server asks for a certificate, the signer
//! signs on that same session, and the session closes with the handshake.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use refineid_lib_core::crypto::digest::Sha384;
use refineid_lib_core::sign::cades::ecdsa_signature_to_cms;
use refineid_lib_core::text::{Scheme, Uri};
use refineid_rapp_core::ids::PairId;
use refineid_rapp_core::operations::{
    CardKeyProfile, CardOperation, CardOperationResult, SignatureAlgorithm as CardAlgorithm,
};
use refineid_rapp_core::remote::{RemoteReader, RemoteSession};

use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use crate::simple_https::HttpsError;

/// How long the signer browses for the paired phone.
const REMOTE_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// The reader and the session the identity is offered on, shared by the
/// resolver that opens it and the signer that signs on it.
#[derive(Debug)]
struct OfferedIdentity {
    reader: RemoteReader,
    session: Option<RemoteSession>,
}

impl OfferedIdentity {
    /// Closes the session the identity was offered on, if one is open.
    fn withdraw(&mut self) {
        if let Some(session) = self.session.take() {
            self.reader.close_session(session);
        }
    }
}

/// Client certificate resolver backed by a paired RAPP remote card reader.
///
/// The certificate is offered only once the phone has opened a session
/// and reported a card on it; the session is held for the signer and
/// closed when the resolver is dropped.
#[derive(Debug)]
pub struct RappClientCertResolver {
    pair: PairId,
    cert_der: Vec<u8>,
    origin: String,
    offered: Arc<Mutex<OfferedIdentity>>,
}

impl RappClientCertResolver {
    /// Create a resolver over `reader` for the given active pair,
    /// authentication certificate, and origin.
    #[must_use]
    pub fn new(reader: RemoteReader, pair: PairId, cert_der: Vec<u8>, origin: String) -> Self {
        Self {
            pair,
            cert_der,
            origin,
            offered: Arc::new(Mutex::new(OfferedIdentity {
                reader,
                session: None,
            })),
        }
    }
}

impl Drop for RappClientCertResolver {
    fn drop(&mut self) {
        if let Ok(mut offered) = self.offered.lock() {
            offered.withdraw();
        }
    }
}

impl ResolvesClientCert for RappClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let mut offered = self.offered.lock().ok()?;
        offered.withdraw();
        let session = offered
            .reader
            .open_session(Some(self.pair), REMOTE_DISCOVERY_TIMEOUT)
            .ok()?;
        offered.session = Some(session);
        let cert = CertificateDer::from(self.cert_der.clone());
        let key = Arc::new(RappSigningKey {
            origin: self.origin.clone(),
            offered: Arc::clone(&self.offered),
        });
        Some(Arc::new(CertifiedKey::new(vec![cert], key)))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct RappSigningKey {
    origin: String,
    offered: Arc<Mutex<OfferedIdentity>>,
}

impl SigningKey for RappSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        for s in offered {
            if *s == SignatureScheme::ECDSA_NISTP384_SHA384 {
                return Some(Box::new(RappSigner {
                    origin: self.origin.clone(),
                    offered: Arc::clone(&self.offered),
                    scheme: *s,
                }));
            }
        }
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct RappSigner {
    origin: String,
    offered: Arc<Mutex<OfferedIdentity>>,
    scheme: SignatureScheme,
}

impl Signer for RappSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let digest = Sha384::of(message);
        let op = CardOperation::BrowserAuthenticate {
            origin: self.origin.clone(),
            key_profile: CardKeyProfile::EcdsaP384,
            algorithm: CardAlgorithm::EcdsaSha384,
            digest: digest.as_bytes().to_vec(),
        };
        let mut offered = self
            .offered
            .lock()
            .map_err(|_| rustls::Error::General("RAPP session lock poisoned".into()))?;
        let OfferedIdentity { reader, session } = &mut *offered;
        let session = session
            .as_mut()
            .ok_or_else(|| rustls::Error::General("no RAPP session offers this identity".into()))?;
        let res = reader
            .execute_on(session, &op)
            .map_err(|e| rustls::Error::General(format!("RAPP operation failed: {e}")))?;
        match res {
            CardOperationResult::Signature(signature_bytes) => {
                let der = ecdsa_signature_to_cms(&signature_bytes)
                    .ok_or_else(|| rustls::Error::General("DER conversion failed".into()))?;
                Ok(der)
            }
            _ => Err(rustls::Error::General("Unexpected RAPP result".into())),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Perform an HTTPS GET request using TLS client certificate authentication via a paired RAPP remote card reader.
///
/// # Errors
/// Returns [`HttpsError`] on network, TLS handshake, or RAPP signing errors.
pub fn get_with_rapp_client_auth(
    url: &Uri,
    pair: PairId,
    cert_der: &[u8],
) -> Result<String, HttpsError> {
    if url.scheme() != Scheme::Https {
        return Err(HttpsError::UnsupportedScheme);
    }
    let host = url.host().to_string();
    let port = url.port();
    let origin = format!("https://{host}");

    // Load CA roots
    let ca_path = "/etc/ssl/certs/ca-certificates.crt";
    let file = std::fs::File::open(ca_path)
        .map_err(|e| HttpsError::Tls(format!("open({ca_path}): {e}")))?;
    let mut reader = std::io::BufReader::new(file);
    let mut roots = rustls::RootCertStore::empty();
    for entry in CertificateDer::pem_reader_iter(&mut reader) {
        let cert = entry.map_err(|e| HttpsError::Tls(format!("{ca_path}: parse: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| HttpsError::Tls(format!("{ca_path}: root rejected: {e}")))?;
    }

    let versions: &[&rustls::SupportedProtocolVersion] =
        &[&rustls::version::TLS13, &rustls::version::TLS12];
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let reader =
        RemoteReader::open_local().map_err(|e| HttpsError::Tls(format!("RAPP reader: {e}")))?;
    let resolver = Arc::new(RappClientCertResolver::new(
        reader,
        pair,
        cert_der.to_vec(),
        origin,
    ));

    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| HttpsError::Tls(format!("protocol versions: {e}")))?
        .with_root_certificates(roots)
        .with_client_cert_resolver(resolver);

    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| HttpsError::Tls(format!("server name {host}: {e}")))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| HttpsError::Tls(format!("client connection: {e}")))?;

    let addr = format!("{host}:{port}");
    let mut sock = TcpStream::connect(&addr)
        .map_err(|e| HttpsError::Connect(format!("connect({addr}): {e}")))?;
    sock.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| HttpsError::Connect(e.to_string()))?;
    sock.set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| HttpsError::Connect(e.to_string()))?;

    let mut tls_stream = rustls::Stream::new(&mut conn, &mut sock);

    let path = url.path();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: refineid-client/1.0\r\nConnection: close\r\nAccept: text/html, */*\r\n\r\n"
    );
    tls_stream
        .write_all(req.as_bytes())
        .map_err(|e| HttpsError::Tls(format!("write request: {e}")))?;
    tls_stream
        .flush()
        .map_err(|e| HttpsError::Tls(format!("flush request: {e}")))?;

    let mut resp = Vec::new();
    let _ = tls_stream.read_to_end(&mut resp);

    let text = String::from_utf8_lossy(&resp).to_string();
    Ok(text)
}
