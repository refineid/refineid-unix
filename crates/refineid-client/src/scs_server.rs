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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The localhost SCS listener: TLS on 127.0.0.1:53952, one request
//! per connection, dispatched to the protocol crate.
//!
//! Connections are served one at a time, in arrival order: a sign
//! blocks the loop while the operator answers the PIN prompt, so one
//! prompt is ever on screen. A failed connection is closed and the
//! loop goes on; only the listener itself failing ends the server.

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use refineid_scs::http::{Assembly, assemble};
use refineid_scs::{SigningBackend, TransactionManager};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::exit_status::ExitStatus;
use crate::scs_backend::{self, ScsBackend};
use crate::scs_identity;

/// The loopback address the server binds.
const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// Bytes read per chunk from a connection.
const READ_CHUNK_LENGTH: usize = 8_192;

/// How long one connection may take between bytes before it is
/// closed.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Serve the SCS on the loopback address until the listener fails.
///
/// Returns the process exit status. Errors on single connections are
/// reported under `verbose` and the loop goes on; a listener that
/// cannot bind or accept ends the server with its reason.
#[must_use]
pub fn serve(verbose: bool) -> std::process::ExitCode {
    let obtained = match scs_identity::obtain() {
        Ok(obtained) => obtained,
        Err(error) => {
            eprintln!("scs: {error}");
            return ExitStatus::RuntimeFailure.into();
        }
    };
    if obtained.generated {
        eprintln!(
            "scs: new localhost identity in {}",
            obtained.directory.display()
        );
        eprintln!(
            "scs: certificate fingerprint (SHA-256): {}",
            scs_identity::fingerprint_hex(&obtained.identity.cert_der)
        );
    }
    let config = match server_config(&obtained.identity) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("scs: {error}");
            return ExitStatus::RuntimeFailure.into();
        }
    };
    let address = SocketAddr::new(IpAddr::V4(LOOPBACK), refineid_scs::values::PORT);
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("scs: cannot listen on {address} (another SCS already running?): {error}");
            return ExitStatus::RuntimeFailure.into();
        }
    };
    if verbose {
        eprintln!("scs: listening on https://{address}");
    }
    let backend = ScsBackend::with_prompt(
        refineid_lib_pcsc::PcscBackend,
        Box::new(scs_backend::prompt_pin),
    );
    let manager = TransactionManager::new();
    run_listener(&listener, &config, &backend, &manager, verbose, None)
}

/// Accept and serve connections until `limit` connections have been
/// served, or forever when `None`.
fn run_listener(
    listener: &TcpListener,
    config: &Arc<rustls::ServerConfig>,
    backend: &dyn SigningBackend,
    manager: &TransactionManager,
    verbose: bool,
    limit: Option<u64>,
) -> std::process::ExitCode {
    let mut served = 0_u64;
    loop {
        if limit.is_some_and(|allowed| served >= allowed) {
            return ExitStatus::Ok.into();
        }
        let (stream, _) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("scs: accept failed: {error}");
                return ExitStatus::RuntimeFailure.into();
            }
        };
        served += 1;
        let outcome = serve_one(stream, config, backend, manager, verbose);
        if verbose && let Err(error) = outcome {
            eprintln!("scs: connection failed: {error}");
        }
    }
}

/// Serve one connection: the TLS handshake, one request, one answer,
/// close.
fn serve_one(
    stream: TcpStream,
    config: &Arc<rustls::ServerConfig>,
    backend: &dyn SigningBackend,
    manager: &TransactionManager,
    verbose: bool,
) -> std::io::Result<()> {
    let mut stream = stream;
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
    let mut connection = rustls::ServerConnection::new(config.clone())
        .map_err(|error| std::io::Error::other(format!("TLS accept: {error}")))?;
    let mut tls = rustls::Stream::new(&mut connection, &mut stream);
    serve_exchange(&mut tls, backend, manager, verbose)
}

/// Read one request from the stream, dispatch it, and write the
/// answer back.
fn serve_exchange(
    tls: &mut rustls::Stream<'_, rustls::ServerConnection, TcpStream>,
    backend: &dyn SigningBackend,
    manager: &TransactionManager,
    verbose: bool,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; READ_CHUNK_LENGTH];
    loop {
        let read = tls.read(&mut chunk)?;
        if read == 0 {
            return Err(std::io::Error::other(
                "connection closed before the request",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        match assemble(&buffer) {
            Assembly::Complete(exchange) => {
                if verbose {
                    eprintln!("scs: {} {}", exchange.request.method, exchange.request.path);
                }
                let answer = refineid_scs::dispatch(
                    &exchange.request,
                    &exchange.body,
                    std::time::SystemTime::now(),
                    backend,
                    manager,
                );
                tls.write_all(&answer)?;
                tls.conn.send_close_notify();
                tls.flush()?;
                return Ok(());
            }
            Assembly::Invalid => {
                return Err(std::io::Error::other("malformed request"));
            }
            Assembly::NeedMoreData => {}
        }
    }
}

/// The TLS server configuration for `identity`.
fn server_config(
    identity: &scs_identity::ScsIdentity,
) -> Result<Arc<rustls::ServerConfig>, String> {
    use pkcs8::EncodePrivateKey as _;
    let provider = rustls::crypto::ring::default_provider();
    let encoded = identity
        .key
        .to_pkcs8_der()
        .map_err(|_| "encode identity key".to_owned())?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(encoded.as_bytes().to_vec()));
    rustls::ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("configure TLS: {error}"))?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(identity.cert_der.clone())], key)
        .map(Arc::new)
        .map_err(|error| format!("configure TLS: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{run_listener, server_config};
    use crate::test_util::{TestResult, check_true};
    use refineid_scs::{BackendFailure, KeyAlgorithm, SignPurpose, SignRequest, SigningBackend};
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::Arc;

    /// A canned signing backend answering a fixed signature.
    struct ScriptedBackend {
        signature: Vec<u8>,
    }

    /// A verifier pinning the exact server certificate and checking
    /// its handshake signatures: the test's trust-on-first-use.
    #[derive(Debug)]
    struct PinVerifier {
        pinned: Vec<u8>,
        verifying_key: p256::ecdsa::VerifyingKey,
    }

    impl rustls::client::danger::ServerCertVerifier for PinVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            if end_entity.as_ref() == self.pinned.as_slice() {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            self.verify_handshake(message, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            self.verify_handshake(message, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
        }
    }

    impl PinVerifier {
        /// Check the handshake signature against the pinned key.
        fn verify_handshake(
            &self,
            message: &[u8],
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            use p256::ecdsa::signature::Verifier as _;
            if dss.scheme != rustls::SignatureScheme::ECDSA_NISTP256_SHA256 {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadSignature,
                ));
            }
            // TLS carries ECDSA signatures in DER, not JWS raw form.
            let signature = p256::ecdsa::Signature::from_der(dss.signature()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
            })?;
            self.verifying_key
                .verify(message, &signature)
                .map(|()| rustls::client::danger::HandshakeSignatureValid::assertion())
                .map_err(|_| {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
                })
        }
    }

    impl SigningBackend for ScriptedBackend {
        fn certificate_chain(&self, _purpose: SignPurpose) -> Vec<Vec<u8>> {
            vec![b"leaf".to_vec()]
        }

        fn key_algorithm(&self, _purpose: SignPurpose) -> KeyAlgorithm {
            KeyAlgorithm::Rsa
        }

        fn sign(&self, _request: SignRequest) -> Result<Vec<u8>, BackendFailure> {
            Ok(self.signature.clone())
        }
    }

    /// Serve one request on an ephemeral loopback port and answer it
    /// over real TLS.
    fn round_trip(request: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
        let directory = crate::test_util::TempDir::new("scs-server")?;
        let obtained = crate::scs_identity::obtain_in(directory.path())?;
        let config = server_config(&obtained.identity)?;
        let backend = ScriptedBackend {
            signature: b"signature".to_vec(),
        };
        let manager = refineid_scs::TransactionManager::new();
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let answer = std::thread::scope(|scope| -> Result<Vec<u8>, Box<dyn core::error::Error>> {
            let server = scope
                .spawn(|| run_listener(&listener, &config, &backend, &manager, false, Some(1)));
            let provider = rustls::crypto::ring::default_provider();
            let verifier = Arc::new(PinVerifier {
                pinned: obtained.identity.cert_der.clone(),
                verifying_key: *obtained.identity.key.verifying_key(),
            });
            let client = rustls::ClientConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from("localhost")?.to_owned();
            let mut connection = rustls::ClientConnection::new(Arc::new(client), name)?;
            let mut socket = std::net::TcpStream::connect(address)?;
            let mut tls = rustls::Stream::new(&mut connection, &mut socket);
            tls.write_all(request)?;
            tls.flush()?;
            let mut answer = Vec::new();
            tls.read_to_end(&mut answer)?;
            let status = server.join().map_err(|_| "server thread")?;
            check_true(
                status == crate::exit_status::ExitStatus::Ok.into(),
                "server exits ok",
            )?;
            Ok(answer)
        })?;
        Ok(answer)
    }

    /// A version request round-trips over TLS.
    #[test]
    fn version_round_trip() -> TestResult {
        let answer = round_trip(b"GET /version HTTP/1.1\r\nContent-Length: 0\r\n\r\n")?;
        let text = core::str::from_utf8(&answer).map_err(|_| "response is text")?;
        check_true(text.starts_with("HTTP/1.1 200 OK\r\n"), "status")?;
        check_true(text.contains("\"version\":\"1.3\""), "version")
    }

    /// A JSON sign round-trips over TLS with the scripted backend.
    #[test]
    fn sign_round_trip() -> TestResult {
        let body = "{\"content\":\"eA==\",\"contentType\":\"data\",\"selector\":{\"keyusages\":[\"nonRepudiation\"]}}";
        let request = format!(
            "POST /sign HTTP/1.1\r\nOrigin: https://example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let answer = round_trip(request.as_bytes())?;
        let text = core::str::from_utf8(&answer).map_err(|_| "response is text")?;
        check_true(text.starts_with("HTTP/1.1 200 OK\r\n"), "status")?;
        check_true(text.contains("\"status\":\"ok\""), "signed")?;
        check_true(
            text.contains("\"signatureAlgorithm\":\"SHA256withRSA\""),
            "algorithm",
        )
    }
}
