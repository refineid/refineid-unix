//! Client certificate authentication using remote RAPP card readers over TLS.
//!
//! The certificate is offered only on a session the phone opened and on
//! which it reports a card (RAPP v26.10.18 section 8.4). Each handshake
//! gets its own reader and session: the resolver opens them when the
//! server asks for a certificate, the signing key owns them, the signer
//! signs on that session and closes it, and a key dropped without
//! signing closes it on the way out.

extern crate alloc;

use crate::policy::TransportPolicy;
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

/// The one signature scheme the phone's authentication key signs under.
const SUPPORTED_SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP384_SHA384;

/// Whether the server's offered schemes include the one the phone signs
/// under; without it the handshake cannot use the certificate and no
/// session is worth opening.
fn offers_supported_scheme(offered: &[SignatureScheme]) -> bool {
    offered.contains(&SUPPORTED_SCHEME)
}

/// The reader and the session one handshake's identity is offered on.
#[derive(Debug)]
struct OfferedSession {
    reader: RemoteReader,
    session: RemoteSession,
}

impl OfferedSession {
    fn close(mut self) {
        self.reader.close_session(self.session);
    }
}

/// Client certificate resolver backed by a paired RAPP remote card reader.
///
/// The certificate is offered only once the phone has opened a session
/// and reported a card on it; that session belongs to the handshake's
/// signing key.
#[derive(Debug)]
pub struct RappClientCertResolver {
    pair: PairId,
    cert_der: Vec<u8>,
    origin: String,
}

impl RappClientCertResolver {
    /// Create a resolver for the given active pair, authentication
    /// certificate, and origin.
    #[must_use]
    pub fn new(pair: PairId, cert_der: Vec<u8>, origin: String) -> Self {
        Self {
            pair,
            cert_der,
            origin,
        }
    }
}

impl ResolvesClientCert for RappClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        if !offers_supported_scheme(sigschemes) {
            return None;
        }
        let mut reader = RemoteReader::open_local().ok()?;
        let session = reader
            .open_session(Some(self.pair), REMOTE_DISCOVERY_TIMEOUT)
            .ok()?;
        let cert = CertificateDer::from(self.cert_der.clone());
        let key = Arc::new(RappSigningKey {
            origin: self.origin.clone(),
            offered: Arc::new(Mutex::new(Some(OfferedSession { reader, session }))),
        });
        Some(Arc::new(CertifiedKey::new(vec![cert], key)))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// One handshake's signing key: it owns the session its identity was
/// offered on until the signer takes it or the key is dropped.
#[derive(Debug)]
struct RappSigningKey {
    origin: String,
    offered: Arc<Mutex<Option<OfferedSession>>>,
}

impl Drop for RappSigningKey {
    fn drop(&mut self) {
        if let Some(offered) = self.offered.lock().ok().and_then(|mut slot| slot.take()) {
            offered.close();
        }
    }
}

impl SigningKey for RappSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offers_supported_scheme(offered).then(|| {
            Box::new(RappSigner {
                origin: self.origin.clone(),
                offered: Arc::clone(&self.offered),
                scheme: SUPPORTED_SCHEME,
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct RappSigner {
    origin: String,
    offered: Arc<Mutex<Option<OfferedSession>>>,
    scheme: SignatureScheme,
}

impl Signer for RappSigner {
    /// Signs once on the handshake's session and closes it; a second
    /// signature on the same key finds no session.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let digest = Sha384::of(message);
        let op = CardOperation::BrowserAuthenticate {
            origin: self.origin.clone(),
            key_profile: CardKeyProfile::EcdsaP384,
            algorithm: CardAlgorithm::EcdsaSha384,
            digest: digest.as_bytes().to_vec(),
        };
        let OfferedSession {
            mut reader,
            mut session,
        } = self
            .offered
            .lock()
            .map_err(|_| rustls::Error::General("RAPP session lock poisoned".into()))?
            .take()
            .ok_or_else(|| rustls::Error::General("no RAPP session offers this identity".into()))?;
        let res = reader.execute_on(&mut session, &op);
        reader.close_session(session);
        match res.map_err(|e| rustls::Error::General(format!("RAPP operation failed: {e}")))? {
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

    // The CA roots come from the same bundle every other HTTPS client
    // in this crate reads, found by the transport policy.
    let ca_path = crate::simple_https::ca_bundle_path(&TransportPolicy::client_auth())?;
    let file = std::fs::File::open(&ca_path)
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
    let resolver = Arc::new(RappClientCertResolver::new(pair, cert_der.to_vec(), origin));

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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;

    use rustls::SignatureScheme;
    use rustls::sign::{Signer as _, SigningKey as _};

    use super::{RappSigner, RappSigningKey, offers_supported_scheme};

    #[test]
    fn only_the_phones_scheme_is_worth_a_session() {
        assert!(offers_supported_scheme(&[
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
        ]));
        assert!(!offers_supported_scheme(&[
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]));
        assert!(!offers_supported_scheme(&[]));
    }

    #[test]
    fn a_key_without_a_session_chooses_the_scheme_but_signs_nothing() {
        let key = RappSigningKey {
            origin: "https://example.test".into(),
            offered: Arc::new(Mutex::new(None)),
        };
        assert!(
            key.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_none()
        );
        let signer = key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP384_SHA384])
            .unwrap();
        assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP384_SHA384);
        assert!(signer.sign(b"transcript").is_err());
    }

    #[test]
    fn signing_takes_the_session_so_a_second_signature_finds_none() {
        let signer = RappSigner {
            origin: "https://example.test".into(),
            offered: Arc::new(Mutex::new(None)),
            scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
        };
        assert!(signer.sign(b"transcript").is_err());
        assert!(signer.offered.lock().unwrap().is_none());
    }
}
