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

//! The production SCS signing backend: one card session per
//! operation, the retry floor before any credential, and the
//! operator's own PIN prompt.
//!
//! Every sign prompts: a remembered PIN is never used, on either
//! slot. The prompt names the requesting origin verbatim and the
//! digest the card is about to sign, so the operator sees which site
//! wants a signature and what it is about to sign before typing.

use std::sync::Mutex;

use refineid_lib_core::auth::{
    PinOps as _, PinReferenceScheme, PinSlot, VerifyOutcome, check_retry_floor,
};
use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend, ReaderBackendOps as _};
use refineid_lib_core::crypto::digest::{Sha256, Sha384, Sha512};
use refineid_lib_core::identity::{TokenSerial, render_token_serial};
use refineid_lib_core::pin::PinBytes;
use refineid_lib_core::pkcs15::{CertSlot, Pkcs15Ops as _};
use refineid_lib_core::sign::{KeyRef, SignError, SignOps as _};
use refineid_lib_core::transport::CardTransport;
use refineid_lib_core::x509::{Certificate, EcCurve, OwnedCert, PublicKeyAlgorithm};
use refineid_scs::{
    BackendFailure, HashAlg, KeyAlgorithm, SignPurpose, SignRequest, SigningBackend,
};

use crate::pin_source::PinEntryError;
use crate::scs_identity::grouped_hex;

/// Ask the operator for the slot's PIN, naming the request.
///
/// `origin` is the request's Origin header as it arrived, `digest`
/// the bytes the card is about to sign, `hash_name` the protocol's
/// digest spelling. Cancellation or prompt failure ends without a
/// PIN; the card is never touched.
pub type PromptFn =
    Box<dyn FnMut(PinSlot, Option<&str>, &[u8], &str) -> Result<PinBytes, PinEntryError> + Send>;

/// The SCS signing backend over one reader backend.
pub struct ScsBackend<B> {
    backend: B,
    auth_leaf: Mutex<Option<Vec<u8>>>,
    qualified_leaf: Mutex<Option<Vec<u8>>>,
    prompt: Mutex<PromptFn>,
}

impl<B> core::fmt::Debug for ScsBackend<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ScsBackend").finish_non_exhaustive()
    }
}

impl<B> ScsBackend<B> {
    /// A backend prompting through `prompt`.
    pub fn with_prompt(backend: B, prompt: PromptFn) -> Self {
        Self {
            backend,
            auth_leaf: Mutex::new(None),
            qualified_leaf: Mutex::new(None),
            prompt: Mutex::new(prompt),
        }
    }

    /// Run the prompt; a poisoned prompt refuses without touching
    /// the card.
    fn ask(
        &self,
        slot: PinSlot,
        origin: Option<&str>,
        digest: &[u8],
        hash_name: &str,
    ) -> Result<PinBytes, BackendFailure> {
        self.prompt
            .lock()
            .ok()
            .and_then(|mut prompt| prompt(slot, origin, digest, hash_name).ok())
            .ok_or_else(|| BackendFailure::CredentialRefused("PIN entry was cancelled".to_owned()))
    }

    /// The cached leaf for `purpose`, read from the card on first
    /// use. Holder certificates stay in memory only.
    fn leaf(&self, purpose: SignPurpose) -> Result<Vec<u8>, BackendFailure>
    where
        B: ReaderBackend,
        B::Transport: CardTransport,
    {
        let slot = match purpose {
            SignPurpose::Authentication => &self.auth_leaf,
            SignPurpose::Qualified => &self.qualified_leaf,
        };
        if let Some(leaf) = slot.lock().ok().and_then(|held| held.clone()) {
            return Ok(leaf);
        }
        let leaf = self.read_leaf(purpose)?;
        if let Ok(mut held) = slot.lock() {
            *held = Some(leaf.clone());
        }
        Ok(leaf)
    }

    /// Read the slot's leaf in a short session.
    fn read_leaf(&self, purpose: SignPurpose) -> Result<Vec<u8>, BackendFailure>
    where
        B: ReaderBackend,
        B::Transport: CardTransport,
    {
        let mut transport = self.open_card()?;
        if transport.select_pkcs15_application().is_err() {
            return Err(BackendFailure::SigningUnavailable(
                "select application".to_owned(),
            ));
        }
        let slot = match purpose {
            SignPurpose::Authentication => CertSlot::Authentication,
            SignPurpose::Qualified => CertSlot::Signature,
        };
        transport
            .read_certificate(slot)
            .or_else(|_| {
                let alt = match slot {
                    CertSlot::Authentication => CertSlot::AuthenticationAlt,
                    CertSlot::Signature => CertSlot::SignatureAlt,
                    other => other,
                };
                transport.read_certificate(alt)
            })
            .map(|cert| cert.as_bytes().to_vec())
            .map_err(|_| {
                BackendFailure::SigningUnavailable("card certificate unavailable".to_owned())
            })
    }

    /// Open a card session on the single reader.
    fn open_card(&self) -> Result<B::Transport, BackendFailure>
    where
        B: ReaderBackend,
        B::Transport: CardTransport,
    {
        let reader = self
            .backend
            .pick_single_reader(None)
            .map_err(|_| BackendFailure::SigningUnavailable("no card session".to_owned()))?;
        self.backend
            .open_session(&reader, ReaderAccessCap::Read)
            .map_err(|_| BackendFailure::SigningUnavailable("no card session".to_owned()))
    }
}

impl<B> SigningBackend for ScsBackend<B>
where
    B: ReaderBackend + Send + Sync,
    B::Transport: CardTransport,
{
    fn certificate_chain(&self, purpose: SignPurpose) -> Vec<Vec<u8>> {
        self.leaf(purpose)
            .map(|leaf| vec![leaf])
            .unwrap_or_default()
    }

    fn key_algorithm(&self, purpose: SignPurpose) -> KeyAlgorithm {
        let Ok(leaf) = self.leaf(purpose) else {
            return KeyAlgorithm::Rsa;
        };
        let Ok(owned) = OwnedCert::from_der(&leaf) else {
            return KeyAlgorithm::Rsa;
        };
        match owned.view().spki.algorithm() {
            PublicKeyAlgorithm::Rsa { .. } => KeyAlgorithm::Rsa,
            PublicKeyAlgorithm::Ec(_) => KeyAlgorithm::Ecdsa,
            PublicKeyAlgorithm::EcExplicit { .. } | PublicKeyAlgorithm::Other => KeyAlgorithm::Rsa,
        }
    }

    fn sign(&self, request: SignRequest) -> Result<Vec<u8>, BackendFailure> {
        self.sign_inner(request).map_err(report_sign_failure)
    }
}

impl<B> ScsBackend<B>
where
    B: ReaderBackend,
    B::Transport: CardTransport,
{
    /// Run one sign ceremony.
    fn sign_inner(&self, request: SignRequest) -> Result<Vec<u8>, BackendFailure> {
        let planned = plan_hash(request.hash, &request.data)?;
        let mut transport = self.open_card()?;
        if transport.select_pkcs15_application().is_err() {
            return Err(BackendFailure::SigningUnavailable(
                "select application".to_owned(),
            ));
        }
        let scheme = transport
            .resolve_pin_reference_scheme()
            .map_err(|_| BackendFailure::SigningUnavailable("sign chain failed".to_owned()))?;
        if request.purpose == SignPurpose::Qualified
            && scheme == PinReferenceScheme::Organizational
            && !transport
                .select_esign_directory()
                .is_ok_and(|status| status.is_success())
        {
            return Err(BackendFailure::SigningUnavailable(
                "signature directory unavailable".to_owned(),
            ));
        }
        let slot = match request.purpose {
            SignPurpose::Authentication => PinSlot::Pin1,
            SignPurpose::Qualified => PinSlot::Pin2,
        };
        let status = transport
            .pin_status_with_scheme(slot, scheme)
            .map_err(|_| BackendFailure::SigningUnavailable("sign chain failed".to_owned()))?;
        if check_retry_floor(slot, status).is_err() {
            return Err(BackendFailure::CredentialRefused(
                "credential retry state refuses the sign".to_owned(),
            ));
        }
        // A signature always reads what it signs with from the card;
        // the cache is refreshed, never trusted blindly.
        let leaf = self.refresh_leaf(&mut transport, request.purpose)?;
        let bound = live_token_serial(&mut transport)?;
        let pin = self.ask(
            slot,
            request.origin.as_deref(),
            &planned.digest,
            planned.name,
        )?;
        if live_token_serial(&mut transport)? != bound {
            return Err(BackendFailure::SigningUnavailable(
                crate::card_sign::CARD_CHANGED_DURING_PROMPT.to_owned(),
            ));
        }
        match transport
            .verify_pin_with_scheme(slot, scheme, pin)
            .map_err(|_| BackendFailure::SigningUnavailable("sign chain failed".to_owned()))?
        {
            VerifyOutcome::Ok => {}
            VerifyOutcome::WrongPin { retries_left } => {
                return Err(BackendFailure::CredentialRefused(format!(
                    "PIN rejected; {retries_left} attempts left"
                )));
            }
            VerifyOutcome::Locked => {
                return Err(BackendFailure::CredentialRefused(
                    "credential blocked".to_owned(),
                ));
            }
            VerifyOutcome::Other(_) => {
                return Err(BackendFailure::SigningUnavailable(
                    "sign chain failed".to_owned(),
                ));
            }
        }
        let owned = OwnedCert::from_der(&leaf).map_err(|_| {
            BackendFailure::SigningUnavailable("card certificate unavailable".to_owned())
        })?;
        let cert = owned.view();
        sign_with_cert(&mut transport, request, &cert, scheme, &planned)
    }
}

/// A hashed request, ready for the card.
struct PlannedHash {
    /// The digest bytes the prompt shows and the card signs over.
    digest: Vec<u8>,
    /// The protocol's digest spelling, for the prompt.
    name: &'static str,
    /// The hash value the card chains take.
    value: HashValue,
}

/// The hash as the signing chains take it.
enum HashValue {
    /// SHA-256.
    Sha256(Sha256),
    /// SHA-384.
    Sha384(Sha384),
    /// SHA-512.
    Sha512(Sha512),
}

/// Hash the request data; digests the card does not serve are
/// refused before any session opens.
fn plan_hash(hash: HashAlg, data: &[u8]) -> Result<PlannedHash, BackendFailure> {
    let unsupported = || BackendFailure::SigningUnavailable("unsupported digest".to_owned());
    match hash {
        HashAlg::Sha256 => {
            let digest = Sha256::of(data);
            Ok(PlannedHash {
                digest: digest.as_bytes().to_vec(),
                name: "SHA256",
                value: HashValue::Sha256(digest),
            })
        }
        HashAlg::Sha384 => {
            let digest = Sha384::of(data);
            Ok(PlannedHash {
                digest: digest.as_bytes().to_vec(),
                name: "SHA384",
                value: HashValue::Sha384(digest),
            })
        }
        HashAlg::Sha512 => {
            let digest = Sha512::of(data);
            Ok(PlannedHash {
                digest: digest.as_bytes().to_vec(),
                name: "SHA512",
                value: HashValue::Sha512(digest),
            })
        }
        HashAlg::Sha1 => Err(unsupported()),
    }
}

impl<B> ScsBackend<B>
where
    B: ReaderBackend,
    B::Transport: CardTransport,
{
    /// Read the slot's leaf in the ceremony session and refresh the
    /// cache.
    fn refresh_leaf(
        &self,
        transport: &mut B::Transport,
        purpose: SignPurpose,
    ) -> Result<Vec<u8>, BackendFailure> {
        let slot = match purpose {
            SignPurpose::Authentication => CertSlot::Authentication,
            SignPurpose::Qualified => CertSlot::Signature,
        };
        let leaf = transport
            .read_certificate(slot)
            .or_else(|_| {
                let alt = match slot {
                    CertSlot::Authentication => CertSlot::AuthenticationAlt,
                    CertSlot::Signature => CertSlot::SignatureAlt,
                    other => other,
                };
                transport.read_certificate(alt)
            })
            .map(|cert| cert.as_bytes().to_vec())
            .map_err(|_| {
                BackendFailure::SigningUnavailable("card certificate unavailable".to_owned())
            })?;
        let cache = match purpose {
            SignPurpose::Authentication => &self.auth_leaf,
            SignPurpose::Qualified => &self.qualified_leaf,
        };
        if let Ok(mut held) = cache.lock() {
            *held = Some(leaf.clone());
        }
        Ok(leaf)
    }
}

/// The serial of the card in the reader, as EF.TokenInfo names it.
fn live_token_serial<T: CardTransport>(
    transport: &mut T,
) -> Result<Option<TokenSerial>, BackendFailure> {
    let token = transport.read_token_info().map_err(|_| {
        BackendFailure::SigningUnavailable("cannot re-read EF.TokenInfo".to_owned())
    })?;
    Ok(token.serial_number_hex.map(render_token_serial))
}

/// Sign the planned digest with the slot key named by `cert`,
/// verified locally before it is handed back.
fn sign_with_cert<T: CardTransport>(
    transport: &mut T,
    request: SignRequest,
    cert: &Certificate<'_>,
    scheme: PinReferenceScheme,
    planned: &PlannedHash,
) -> Result<Vec<u8>, BackendFailure> {
    let key_ref = match request.purpose {
        SignPurpose::Authentication => KeyRef::Auth,
        SignPurpose::Qualified => KeyRef::Sign(scheme),
    };
    match cert.spki.algorithm() {
        PublicKeyAlgorithm::Rsa { .. } => {
            sign_rsa(transport, request, key_ref, scheme, planned, cert)
        }
        PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => sign_p384(transport, key_ref, planned, cert),
        PublicKeyAlgorithm::Ec(_) => Err(BackendFailure::SigningUnavailable(
            "unsupported key".to_owned(),
        )),
        PublicKeyAlgorithm::EcExplicit { .. } | PublicKeyAlgorithm::Other => Err(
            BackendFailure::SigningUnavailable("unsupported key".to_owned()),
        ),
    }
}

/// RSA sign over `planned`, verified against the SPKI.
fn sign_rsa<T: CardTransport>(
    transport: &mut T,
    request: SignRequest,
    key_ref: KeyRef,
    scheme: PinReferenceScheme,
    planned: &PlannedHash,
    cert: &Certificate<'_>,
) -> Result<Vec<u8>, BackendFailure> {
    use refineid_lib_core::crypto::container::{
        RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512, Signature,
    };
    use refineid_lib_core::sign::commands::ExternalHashValue;
    let raw: Vec<u8> = if scheme == PinReferenceScheme::Organizational {
        let HashValue::Sha256(digest) = &planned.value else {
            return Err(BackendFailure::SigningUnavailable(
                "unsupported digest".to_owned(),
            ));
        };
        transport
            .sign_pre_hashed_sha256_rsa_hash_in_command(key_ref, *digest)
            .map_err(sign_failure)?
            .into_bytes()
    } else {
        let hash = match &planned.value {
            HashValue::Sha256(digest) => ExternalHashValue::Sha256(*digest.as_bytes()),
            HashValue::Sha384(digest) => ExternalHashValue::Sha384(*digest.as_bytes()),
            HashValue::Sha512(digest) => ExternalHashValue::Sha512(*digest.as_bytes()),
        };
        transport
            .sign_pre_hashed_rsa_pkcs1(key_ref, hash)
            .map_err(sign_failure)?
            .into_bytes()
    };
    let public =
        refineid_lib_core::x509::extract_rsa_public_key(cert.spki.as_der()).ok_or_else(|| {
            BackendFailure::SigningUnavailable("card certificate unavailable".to_owned())
        })?;
    let verified = match &planned.value {
        HashValue::Sha256(_) => public
            .verify_pkcs1v15_sha256(
                &request.data,
                &Signature::<RsaPkcs1Sha256>::new(raw.clone()),
            )
            .is_ok(),
        HashValue::Sha384(_) => public
            .verify_pkcs1v15_sha384(
                &request.data,
                &Signature::<RsaPkcs1Sha384>::new(raw.clone()),
            )
            .is_ok(),
        HashValue::Sha512(_) => public
            .verify_pkcs1v15_sha512(
                &request.data,
                &Signature::<RsaPkcs1Sha512>::new(raw.clone()),
            )
            .is_ok(),
    };
    if !verified {
        return Err(BackendFailure::SigningUnavailable(
            "signature failed local verification".to_owned(),
        ));
    }
    Ok(raw)
}

/// P-384 ECDSA sign over `planned`, verified against the SPKI.
fn sign_p384<T: CardTransport>(
    transport: &mut T,
    key_ref: KeyRef,
    planned: &PlannedHash,
    cert: &Certificate<'_>,
) -> Result<Vec<u8>, BackendFailure> {
    let point = cert.spki.ec_public_key_point().ok_or_else(|| {
        BackendFailure::SigningUnavailable("card certificate unavailable".to_owned())
    })?;
    let signature = match &planned.value {
        HashValue::Sha256(digest) => {
            let signature = transport
                .sign_pre_hashed_sha256_ecdsa_p384(key_ref, *digest)
                .map_err(sign_failure)?;
            if point
                .verify_p384_sha256_raw(signature.clone(), *digest)
                .is_err()
            {
                return Err(BackendFailure::SigningUnavailable(
                    "signature failed local verification".to_owned(),
                ));
            }
            signature.into_bytes()
        }
        HashValue::Sha384(digest) => {
            let signature = transport
                .sign_pre_hashed_sha384_ecdsa_p384(key_ref, *digest)
                .map_err(sign_failure)?;
            if point
                .verify_p384_sha384_raw(signature.clone(), *digest)
                .is_err()
            {
                return Err(BackendFailure::SigningUnavailable(
                    "signature failed local verification".to_owned(),
                ));
            }
            signature.into_bytes()
        }
        HashValue::Sha512(digest) => {
            let signature = transport
                .sign_pre_hashed_sha512_ecdsa_p384(key_ref, *digest)
                .map_err(sign_failure)?;
            if point
                .verify_p384_sha512_raw(signature.clone(), *digest)
                .is_err()
            {
                return Err(BackendFailure::SigningUnavailable(
                    "signature failed local verification".to_owned(),
                ));
            }
            signature.into_bytes()
        }
    };
    Ok(signature)
}

/// A card sign chain failure, without the wire detail.
fn sign_failure<TE: core::fmt::Display>(_: SignError<TE>) -> BackendFailure {
    BackendFailure::SigningUnavailable("sign chain failed".to_owned())
}

/// Report a refused sign on stderr and pass it through. The browser
/// page shows its own error; the operator needs to see that a card
/// is missing, a prompt was cancelled, or a chain failed.
fn report_sign_failure(failure: BackendFailure) -> BackendFailure {
    eprintln!("scs: sign failed: {failure}");
    failure
}

/// The production PIN prompt: consent lines on stderr, echo-off
/// entry.
///
/// Prints the origin verbatim and the digest the card is about to
/// sign, then reads one line without echo. A request that carried no
/// Origin says so in as many words: a browser always sends Origin on
/// a CORS request, so its absence means the requester is not a page.
pub fn prompt_pin(
    slot: PinSlot,
    origin: Option<&str>,
    digest: &[u8],
    hash_name: &str,
) -> Result<PinBytes, PinEntryError> {
    let label = match slot {
        PinSlot::Pin1 => "Basic PIN 1",
        PinSlot::Pin2 => "Signature PIN 2",
    };
    eprintln!("SCS signature request");
    match origin {
        Some(origin) => eprintln!("Origin: {origin}"),
        None => eprintln!("Origin: (none - the request sent no Origin header)"),
    }
    eprintln!("Digest ({hash_name}): {}", grouped_hex(digest));
    crate::cli::util::read_pin(&format!("{label}: ")).map_err(|message| {
        eprintln!("scs: {message}");
        PinEntryError {
            status: crate::exit_status::ExitStatus::RuntimeFailure,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{PromptFn, ScsBackend};
    use crate::pin_source::PinEntryError;
    use crate::test_card::{SyntheticBackend, SyntheticCard, TRIES_BELOW_FLOOR, TRIES_SERVED};
    use crate::test_util::{TestResult, check};
    use refineid_lib_core::pin::PinBytes;
    use refineid_scs::{
        BackendFailure, HashAlg, KeyAlgorithm, SignPurpose, SignRequest, SigningBackend,
    };
    use std::sync::{Arc, Mutex};

    /// Synthetic message to sign.
    const MESSAGE: &[u8] = b"synthetic message";

    /// The test origin.
    const ORIGIN: &str = "https://example.com";

    /// A synthetic PIN, in the shape every PIN slot accepts.
    const SYNTHETIC_PIN: &str = "123456";

    /// One recorded prompt: slot label, origin, digest, hash name.
    type Prompted = (String, Option<String>, Vec<u8>, String);

    /// A prompt answering the synthetic PIN and recording its calls.
    fn answering_prompt() -> (PromptFn, Arc<Mutex<Vec<Prompted>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&calls);
        let prompt: PromptFn = Box::new(
            move |slot, origin: Option<&str>, digest: &[u8], hash_name: &str| {
                if let Ok(mut held) = recorded.lock() {
                    held.push((
                        format!("{slot:?}"),
                        origin.map(str::to_owned),
                        digest.to_vec(),
                        hash_name.to_owned(),
                    ));
                }
                PinBytes::new(SYNTHETIC_PIN.as_bytes().to_vec()).map_err(|_| PinEntryError {
                    status: crate::exit_status::ExitStatus::RuntimeFailure,
                })
            },
        );
        (prompt, calls)
    }

    /// A prompt refusing every call.
    fn refusing_prompt() -> PromptFn {
        Box::new(|_, _, _, _| {
            Err(PinEntryError {
                status: crate::exit_status::ExitStatus::RuntimeFailure,
            })
        })
    }

    /// Prompts the recorder saw.
    fn prompts(calls: &Arc<Mutex<Vec<Prompted>>>) -> usize {
        calls.lock().map(|held| held.len()).unwrap_or(usize::MAX)
    }

    /// An authentication sign request over the synthetic message.
    fn request() -> SignRequest {
        SignRequest {
            purpose: SignPurpose::Authentication,
            hash: HashAlg::Sha256,
            data: MESSAGE.to_vec(),
            origin: Some(ORIGIN.to_owned()),
        }
    }

    /// No reader fails before the prompt is asked.
    #[test]
    fn no_reader_fails_before_the_prompt() -> TestResult {
        let backend = ScsBackend::with_prompt(
            SyntheticBackend {
                readers: Vec::new(),
                card: SyntheticCard::with_tries(TRIES_SERVED)?,
            },
            refusing_prompt(),
        );
        check(
            &SigningBackend::sign(&backend, request()),
            &Err(BackendFailure::SigningUnavailable(
                "no card session".to_owned(),
            )),
            "no session",
        )
    }

    /// The retry floor refuses before the prompt is asked.
    #[test]
    fn retry_floor_refuses_before_the_prompt() -> TestResult {
        let (prompt, calls) = answering_prompt();
        let backend = ScsBackend::with_prompt(
            SyntheticBackend::one_reader(true, SyntheticCard::with_tries(TRIES_BELOW_FLOOR)?),
            prompt,
        );
        check(
            &SigningBackend::sign(&backend, request()),
            &Err(BackendFailure::CredentialRefused(
                "credential retry state refuses the sign".to_owned(),
            )),
            "floor",
        )?;
        check(&prompts(&calls), &0, "prompts")
    }

    /// A served card prompts once, naming the origin and the digest,
    /// then runs the chain. The synthetic card cannot make a
    /// signature that verifies, so the flow ends at local verify.
    #[test]
    fn served_card_prompts_once_then_verifies() -> TestResult {
        let (prompt, calls) = answering_prompt();
        let backend = ScsBackend::with_prompt(
            SyntheticBackend::one_reader(true, SyntheticCard::with_tries(TRIES_SERVED)?),
            prompt,
        );
        check(
            &SigningBackend::sign(&backend, request()),
            &Err(BackendFailure::SigningUnavailable(
                "signature failed local verification".to_owned(),
            )),
            "local verify",
        )?;
        check(&prompts(&calls), &1, "prompts")?;
        let held = calls.lock().map_err(|_| "prompt lock")?;
        let [only] = held.as_slice() else {
            return Err("one prompt".into());
        };
        check(&only.1, &Some(ORIGIN.to_owned()), "origin")?;
        check(&only.3, &"SHA256".to_owned(), "hash name")?;
        check(
            &only.2,
            &refineid_lib_core::crypto::digest::Sha256::of(MESSAGE)
                .as_bytes()
                .to_vec(),
            "digest",
        )
    }

    /// A cancelled prompt refuses without running the chain.
    #[test]
    fn cancelled_prompt_refuses() -> TestResult {
        let backend = ScsBackend::with_prompt(
            SyntheticBackend::one_reader(true, SyntheticCard::with_tries(TRIES_SERVED)?),
            refusing_prompt(),
        );
        check(
            &SigningBackend::sign(&backend, request()),
            &Err(BackendFailure::CredentialRefused(
                "PIN entry was cancelled".to_owned(),
            )),
            "cancelled",
        )
    }

    /// A digest the card does not serve is refused before any
    /// session opens.
    #[test]
    fn unsupported_digest_refuses_before_the_prompt() -> TestResult {
        let (prompt, calls) = answering_prompt();
        let backend = ScsBackend::with_prompt(
            SyntheticBackend::one_reader(true, SyntheticCard::with_tries(TRIES_SERVED)?),
            prompt,
        );
        let request = SignRequest {
            hash: HashAlg::Sha1,
            ..request()
        };
        check(
            &SigningBackend::sign(&backend, request),
            &Err(BackendFailure::SigningUnavailable(
                "unsupported digest".to_owned(),
            )),
            "sha1",
        )?;
        check(&prompts(&calls), &0, "prompts")
    }

    /// The chain serves the synthetic certificate; its RSA key reads
    /// as RSA.
    #[test]
    fn chain_and_algorithm_serve_the_card() -> TestResult {
        let backend = ScsBackend::with_prompt(
            SyntheticBackend::one_reader(true, SyntheticCard::with_tries(TRIES_SERVED)?),
            refusing_prompt(),
        );
        check(
            &SigningBackend::certificate_chain(&backend, SignPurpose::Authentication),
            &vec![crate::test_card::CERTIFICATE.to_vec()],
            "chain",
        )?;
        check(
            &SigningBackend::key_algorithm(&backend, SignPurpose::Authentication),
            &KeyAlgorithm::Rsa,
            "algorithm",
        )
    }
}
