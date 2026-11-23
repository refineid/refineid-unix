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

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use refineid_lib_core::auth::{
    PinOps as _, PinReferenceScheme, PinSlot, VerifyOutcome, check_retry_floor,
};
use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend, ReaderBackendOps as _};
use refineid_lib_core::crypto::digest::{Sha256, Sha384, Sha512};
use refineid_lib_core::identity::{TokenSerial, render_token_serial};
use refineid_lib_core::pin::PinBytes;
use refineid_lib_core::pkcs15::{CertSlot, Pkcs15Ops as _};
use refineid_lib_core::sign::{KeyRef, QualifiedSignScheme, SignError, SignOps as _};
use refineid_lib_core::transport::CardTransport;
use refineid_lib_core::x509::{Certificate, EcCurve, OwnedCert, PublicKeyAlgorithm};
use refineid_scs::{
    BackendFailure, HashAlg, KeyAlgorithm, SignPurpose, SignRequest, SigningBackend,
};

use crate::pin_source::PinEntryError;
use crate::scs_identity::grouped_hex;

/// Sliding-window length for per-origin prompt throttling (60s).
pub const PROMPT_WINDOW_SECONDS: u64 = 60;
/// Maximum PIN prompts one origin may trigger inside one window.
pub const PROMPT_MAXIMUM_PER_WINDOW: usize = 5;
/// Cooldown imposed on an origin after a cancelled or refused PIN prompt (10s).
pub const PROMPT_REFUSAL_COOLDOWN_SECONDS: u64 = 10;
/// Maximum distinct origin buckets held in the prompt rate limiter.
pub const PROMPT_MAX_TRACKED_ORIGINS: usize = 128;
/// Maximum characters displayed for an Origin in the consent prompt.
pub const MAX_ORIGIN_DISPLAY_CHARACTERS: usize = 96;
/// Maximum duration permitted for entering a PIN before timing out.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-origin timestamps and refusal cooldown tracking.
#[derive(Debug)]
struct OriginBucket {
    timestamps: Vec<Instant>,
    cooldown_until: Option<Instant>,
    last_touched: Instant,
}

/// Sliding-window rate limiter and post-refusal cooldown guarding the SCS PIN prompt.
#[derive(Debug)]
pub struct ScsPromptRateLimiter {
    window: Duration,
    max_per_window: usize,
    refusal_cooldown: Duration,
    buckets: Mutex<HashMap<String, OriginBucket>>,
}

impl Default for ScsPromptRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ScsPromptRateLimiter {
    /// Creates a rate limiter with standard policy: 60s window, 5 prompts max, 10s cooldown.
    #[must_use]
    pub fn new() -> Self {
        Self::with_bounds(
            Duration::from_secs(PROMPT_WINDOW_SECONDS),
            PROMPT_MAXIMUM_PER_WINDOW,
            Duration::from_secs(PROMPT_REFUSAL_COOLDOWN_SECONDS),
        )
    }

    /// Creates a rate limiter with explicit parameters.
    #[must_use]
    pub fn with_bounds(
        window: Duration,
        max_per_window: usize,
        refusal_cooldown: Duration,
    ) -> Self {
        Self {
            window,
            max_per_window,
            refusal_cooldown,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Checks if a prompt is permitted for `origin` at `now`, recording it if allowed.
    pub fn check_and_record_prompt(
        &self,
        origin: Option<&str>,
        now: Instant,
    ) -> Result<(), &'static str> {
        let key = origin.unwrap_or("(no-origin)");
        let mut state = self.buckets.lock().map_err(|_| "limiter lock poisoned")?;
        self.prune(&mut state, now);
        let bucket = state.entry(key.to_owned()).or_insert_with(|| OriginBucket {
            timestamps: Vec::new(),
            cooldown_until: None,
            last_touched: now,
        });
        if let Some(cooldown_until) = bucket.cooldown_until
            && now < cooldown_until
        {
            return Err("signature prompt is cooling down after a cancelled or refused PIN");
        }
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        bucket.timestamps.retain(|&ts| ts > cutoff);
        if bucket.timestamps.len() >= self.max_per_window {
            return Err("too many signature prompts from this origin; wait before retrying");
        }
        bucket.timestamps.push(now);
        bucket.cooldown_until = None;
        bucket.last_touched = now;
        Ok(())
    }

    /// Records a PIN refusal or cancellation, imposing the post-refusal cooldown.
    pub fn record_refusal(&self, origin: Option<&str>, now: Instant) {
        let key = origin.unwrap_or("(no-origin)");
        let until = now + self.refusal_cooldown;
        if let Ok(mut state) = self.buckets.lock() {
            self.prune(&mut state, now);
            let bucket = state.entry(key.to_owned()).or_insert_with(|| OriginBucket {
                timestamps: Vec::new(),
                cooldown_until: None,
                last_touched: now,
            });
            bucket.cooldown_until = Some(until);
            bucket.last_touched = now;
        }
    }

    fn prune(&self, state: &mut HashMap<String, OriginBucket>, now: Instant) {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        state.retain(|_, bucket| {
            bucket.timestamps.retain(|&ts| ts > cutoff);
            let cooled_down = bucket.cooldown_until.is_none_or(|until| now >= until);
            !(bucket.timestamps.is_empty() && cooled_down)
        });
        while state.len() >= PROMPT_MAX_TRACKED_ORIGINS {
            if let Some(oldest_key) = state
                .iter()
                .min_by_key(|(_, b)| b.last_touched)
                .map(|(k, _)| k.clone())
            {
                state.remove(&oldest_key);
            } else {
                break;
            }
        }
    }
}

/// A cached card leaf set, bound strictly to the card's EF.TokenInfo serial.
#[derive(Debug, Clone)]
struct CachedCard {
    serial: Option<TokenSerial>,
    auth_leaf: Option<Vec<u8>>,
    qualified_leaf: Option<Vec<u8>>,
}

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
    cached_card: Mutex<Option<CachedCard>>,
    prompt: Mutex<PromptFn>,
    rate_limiter: ScsPromptRateLimiter,
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
            cached_card: Mutex::new(None),
            prompt: Mutex::new(prompt),
            rate_limiter: ScsPromptRateLimiter::new(),
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

    /// The cached leaf for `purpose`, validated against the live card's
    /// EF.TokenInfo serial on every call. Swapped or removed cards invalidate
    /// the cache immediately so Card A's certificate is never mixed with Card B's
    /// signature.
    fn leaf(&self, purpose: SignPurpose) -> Result<Vec<u8>, BackendFailure>
    where
        B: ReaderBackend,
        B::Transport: CardTransport,
    {
        let mut transport = match self.open_card() {
            Ok(t) => t,
            Err(e) => {
                if let Ok(mut held) = self.cached_card.lock() {
                    *held = None;
                }
                return Err(e);
            }
        };
        if transport.select_pkcs15_application().is_err() {
            if let Ok(mut held) = self.cached_card.lock() {
                *held = None;
            }
            return Err(BackendFailure::SigningUnavailable(
                "select application".to_owned(),
            ));
        }
        let live_serial = match live_token_serial(&mut transport) {
            Ok(serial) => serial,
            Err(e) => {
                if let Ok(mut held) = self.cached_card.lock() {
                    *held = None;
                }
                return Err(e);
            }
        };

        if let Ok(mut held) = self.cached_card.lock() {
            if let Some(cached) = held.as_mut()
                && live_serial.is_some()
                && cached.serial == live_serial
            {
                let cached_leaf = match purpose {
                    SignPurpose::Authentication => cached.auth_leaf.clone(),
                    SignPurpose::Qualified => cached.qualified_leaf.clone(),
                };
                if let Some(leaf) = cached_leaf {
                    return Ok(leaf);
                }
                let leaf = read_card_leaf(&mut transport, purpose)?;
                match purpose {
                    SignPurpose::Authentication => cached.auth_leaf = Some(leaf.clone()),
                    SignPurpose::Qualified => cached.qualified_leaf = Some(leaf.clone()),
                }
                return Ok(leaf);
            }
            let leaf = read_card_leaf(&mut transport, purpose)?;
            if live_serial.is_some() {
                let mut new_cached = CachedCard {
                    serial: live_serial,
                    auth_leaf: None,
                    qualified_leaf: None,
                };
                match purpose {
                    SignPurpose::Authentication => new_cached.auth_leaf = Some(leaf.clone()),
                    SignPurpose::Qualified => new_cached.qualified_leaf = Some(leaf.clone()),
                }
                *held = Some(new_cached);
            } else {
                *held = None;
            }
            Ok(leaf)
        } else {
            read_card_leaf(&mut transport, purpose)
        }
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

/// Read the slot's leaf from `transport`.
fn read_card_leaf<T: CardTransport>(
    transport: &mut T,
    purpose: SignPurpose,
) -> Result<Vec<u8>, BackendFailure> {
    match purpose {
        SignPurpose::Authentication => transport
            .read_certificate(CertSlot::Authentication)
            .or_else(|_| transport.read_certificate(CertSlot::EstonianAuthentication))
            .or_else(|_| transport.read_certificate(CertSlot::AuthenticationAlt)),
        SignPurpose::Qualified => transport
            .read_certificate(CertSlot::Signature)
            .or_else(|_| transport.read_certificate(CertSlot::SignatureAlt)),
    }
    .map(|cert| cert.as_bytes().to_vec())
    .map_err(|_| BackendFailure::SigningUnavailable("card certificate unavailable".to_owned()))
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
        let now = Instant::now();
        if let Err(reason) = self
            .rate_limiter
            .check_and_record_prompt(request.origin.as_deref(), now)
        {
            return Err(BackendFailure::CredentialRefused(reason.to_owned()));
        }
        let origin = request.origin.clone();
        let outcome = self.sign_inner(request);
        if let Err(BackendFailure::CredentialRefused(_)) = &outcome {
            self.rate_limiter
                .record_refusal(origin.as_deref(), Instant::now());
        }
        outcome.map_err(report_sign_failure)
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
        let key_ref = match request.purpose {
            SignPurpose::Authentication => KeyRef::Auth,
            SignPurpose::Qualified => QualifiedSignScheme::try_from(scheme)
                .map(KeyRef::Sign)
                .map_err(|_| {
                    BackendFailure::SigningUnavailable(
                        "qualified signing is not supported for this card".to_owned(),
                    )
                })?,
        };
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
        if check_retry_floor(slot, status, scheme).is_err() {
            return Err(BackendFailure::CredentialRefused(
                "credential retry state refuses the sign".to_owned(),
            ));
        }
        // A signature always reads what it signs with from the card;
        // the cache is refreshed, never trusted blindly.
        let leaf = self.refresh_leaf(&mut transport, request.purpose)?;
        let bound = live_token_serial(&mut transport)?;
        let prompt_digest = request.effective_digest();
        let pin = self.ask(
            slot,
            request.origin.as_deref(),
            &prompt_digest,
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
                eprintln!("scs: PIN rejected; {retries_left} attempts left");
                return Err(BackendFailure::CredentialRefused("PIN rejected".to_owned()));
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
        sign_with_cert(&mut transport, request, key_ref, &cert, scheme, &planned)
    }
}

/// A hashed request, ready for the card.
struct PlannedHash {
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
                name: "SHA256",
                value: HashValue::Sha256(digest),
            })
        }
        HashAlg::Sha384 => {
            let digest = Sha384::of(data);
            Ok(PlannedHash {
                name: "SHA384",
                value: HashValue::Sha384(digest),
            })
        }
        HashAlg::Sha512 => {
            let digest = Sha512::of(data);
            Ok(PlannedHash {
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
        let leaf = read_card_leaf(transport, purpose)?;
        let live_serial = live_token_serial(transport)?;
        if let Ok(mut held) = self.cached_card.lock() {
            if let Some(cached) = held.as_mut()
                && live_serial.is_some()
                && cached.serial == live_serial
            {
                match purpose {
                    SignPurpose::Authentication => cached.auth_leaf = Some(leaf.clone()),
                    SignPurpose::Qualified => cached.qualified_leaf = Some(leaf.clone()),
                }
                return Ok(leaf);
            }
            if live_serial.is_some() {
                let mut new_cached = CachedCard {
                    serial: live_serial,
                    auth_leaf: None,
                    qualified_leaf: None,
                };
                match purpose {
                    SignPurpose::Authentication => new_cached.auth_leaf = Some(leaf.clone()),
                    SignPurpose::Qualified => new_cached.qualified_leaf = Some(leaf.clone()),
                }
                *held = Some(new_cached);
            } else {
                *held = None;
            }
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
    key_ref: KeyRef,
    cert: &Certificate<'_>,
    scheme: PinReferenceScheme,
    planned: &PlannedHash,
) -> Result<Vec<u8>, BackendFailure> {
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

/// Sanitize an origin string before printing to a terminal.
///
/// Strips or replaces non-ASCII-printable, tab, C1, and bidi characters,
/// and truncates length to prevent terminal escape sequences, line overwrites,
/// or visual domain spoofing.
#[must_use]
pub fn sanitize_origin(origin: &str) -> String {
    let mut out = String::with_capacity(origin.len().min(MAX_ORIGIN_DISPLAY_CHARACTERS));
    for c in origin.chars() {
        if out.chars().count() >= MAX_ORIGIN_DISPLAY_CHARACTERS {
            out.push_str("...");
            break;
        }
        if c.is_ascii_graphic() || c == ' ' {
            out.push(c);
        } else {
            out.push('?');
        }
    }
    out
}

/// The production PIN prompt: consent lines on stderr, echo-off
/// entry with a bounded timeout.
///
/// Prints the sanitized origin and the digest the card is about to
/// sign, then reads one line without echo within [`PROMPT_TIMEOUT`]. A request that carried no
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
        Some(origin) => eprintln!("Origin: {}", sanitize_origin(origin)),
        None => eprintln!("Origin: (none - the request sent no Origin header)"),
    }
    eprintln!("Digest ({hash_name}): {}", grouped_hex(digest));
    prompt_pin_with_timeout(&format!("{label}: "), PROMPT_TIMEOUT)
}

fn prompt_pin_with_timeout(prompt: &str, timeout: Duration) -> Result<PinBytes, PinEntryError> {
    let prompt_text = prompt.to_owned();
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = std::thread::spawn(move || {
        let result = crate::cli::util::read_pin(&prompt_text);
        let _ = tx.send(result);
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => result.map_err(|message| {
            eprintln!("scs: {message}");
            PinEntryError {
                status: crate::exit_status::ExitStatus::RuntimeFailure,
            }
        }),
        Err(_) => {
            eprintln!("\nscs: PIN entry timed out");
            Err(PinEntryError {
                status: crate::exit_status::ExitStatus::RuntimeFailure,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_ORIGIN_DISPLAY_CHARACTERS, PromptFn, ScsBackend, ScsPromptRateLimiter, sanitize_origin,
    };
    use crate::pin_source::PinEntryError;
    use crate::test_card::{
        ALT_CERTIFICATE, CERTIFICATE, SwappableBackend, SyntheticBackend, SyntheticCard,
        TRIES_BELOW_FLOOR, TRIES_SERVED,
    };
    use crate::test_util::{TestResult, check, check_true};
    use refineid_lib_core::pin::PinBytes;
    use refineid_scs::{
        BackendFailure, HashAlg, KeyAlgorithm, SignOperation, SignPurpose, SignRequest,
        SigningBackend,
    };
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

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
            operation: SignOperation::AuthenticationChallenge,
            consent_digest: None,
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
            &vec![CERTIFICATE.to_vec()],
            "chain",
        )?;
        check(
            &SigningBackend::key_algorithm(&backend, SignPurpose::Authentication),
            &KeyAlgorithm::Rsa,
            "algorithm",
        )
    }

    /// Swapping cards invalidates the cached leaf so Card B's certificate is returned,
    /// and removing the card clears the cache.
    #[test]
    fn card_swap_invalidates_leaf_cache() -> TestResult {
        let card_a = SyntheticCard::with_tries(TRIES_SERVED)?;
        let card_b = SyntheticCard::card_b(TRIES_SERVED)?;
        let backend_mock = SwappableBackend::new(card_a);
        let scs_backend = ScsBackend::with_prompt(backend_mock.clone(), refusing_prompt());

        // 1. Initial read caches Card A's leaf.
        let chain_a = SigningBackend::certificate_chain(&scs_backend, SignPurpose::Authentication);
        check(&chain_a, &vec![CERTIFICATE.to_vec()], "card a chain")?;

        // 2. Swap to Card B.
        backend_mock.swap_card(card_b);

        // 3. certificate_chain must detect the new serial and return Card B's leaf!
        let chain_b = SigningBackend::certificate_chain(&scs_backend, SignPurpose::Authentication);
        check(&chain_b, &vec![ALT_CERTIFICATE.to_vec()], "card b chain")?;

        // 4. Remove card.
        backend_mock.remove_card();

        // 5. certificate_chain must return empty vec and cache must be cleared.
        let chain_empty =
            SigningBackend::certificate_chain(&scs_backend, SignPurpose::Authentication);
        check(
            &chain_empty,
            &Vec::<Vec<u8>>::new(),
            "empty chain on card removal",
        )?;

        // 6. Re-insert Card A.
        let card_a_again = SyntheticCard::with_tries(TRIES_SERVED)?;
        backend_mock.swap_card(card_a_again);
        let chain_a_again =
            SigningBackend::certificate_chain(&scs_backend, SignPurpose::Authentication);
        check(
            &chain_a_again,
            &vec![CERTIFICATE.to_vec()],
            "card a reinserted",
        )
    }

    /// Origin sanitization strips tabs, newlines, C1 control codes, and Unicode bidi overrides,
    /// and truncates long origins.
    #[test]
    fn origin_sanitization_removes_dangerous_characters_and_bounds_length() -> TestResult {
        // Normal ASCII origin passes through untouched.
        check(
            &sanitize_origin("https://example.com"),
            &"https://example.com".to_owned(),
            "normal origin",
        )?;

        // Tabs and newlines are sanitized to '?'.
        check(
            &sanitize_origin("https://example.com\t\nadmin"),
            &"https://example.com??admin".to_owned(),
            "tabs and newlines",
        )?;

        // C1 control character (\u{009B} CSI) is replaced with '?'.
        check(
            &sanitize_origin("https://example.com\u{009B}1A"),
            &"https://example.com?1A".to_owned(),
            "C1 CSI",
        )?;

        // Unicode bidi overrides (U+202E RLO, U+202C PDF) are replaced with '?'.
        check(
            &sanitize_origin("https://example.com\u{202E}txt.exe\u{202C}"),
            &"https://example.com?txt.exe?".to_owned(),
            "bidi overrides",
        )?;

        // Length is bounded at MAX_ORIGIN_DISPLAY_CHARACTERS (96) and appends "...".
        let long_origin = format!("https://{}.example.com", "a".repeat(120));
        let sanitized = sanitize_origin(&long_origin);
        check_true(
            sanitized.len() <= MAX_ORIGIN_DISPLAY_CHARACTERS + 3,
            "bounded length",
        )?;
        check_true(sanitized.ends_with("..."), "ends with ellipsis")
    }

    /// The per-origin rate limiter enforces window limits and refusal cooldown.
    #[test]
    fn rate_limiter_enforces_window_cap_and_refusal_cooldown() -> TestResult {
        let limiter =
            ScsPromptRateLimiter::with_bounds(Duration::from_secs(60), 3, Duration::from_secs(10));
        let now = Instant::now();

        // 3 prompts allowed.
        check_true(
            limiter
                .check_and_record_prompt(Some("https://a.example"), now)
                .is_ok(),
            "prompt 1",
        )?;
        check_true(
            limiter
                .check_and_record_prompt(Some("https://a.example"), now)
                .is_ok(),
            "prompt 2",
        )?;
        check_true(
            limiter
                .check_and_record_prompt(Some("https://a.example"), now)
                .is_ok(),
            "prompt 3",
        )?;

        // 4th prompt within window throttled.
        let fourth = limiter.check_and_record_prompt(Some("https://a.example"), now);
        check(
            &fourth,
            &Err("too many signature prompts from this origin; wait before retrying"),
            "prompt 4 throttled",
        )?;

        // Other origin unaffected.
        check_true(
            limiter
                .check_and_record_prompt(Some("https://b.example"), now)
                .is_ok(),
            "other origin prompt 1",
        )?;

        // Refusal imposes cooldown on other origin.
        limiter.record_refusal(Some("https://b.example"), now);
        let in_cooldown = limiter
            .check_and_record_prompt(Some("https://b.example"), now + Duration::from_secs(5));
        check(
            &in_cooldown,
            &Err("signature prompt is cooling down after a cancelled or refused PIN"),
            "in cooldown",
        )?;

        // Cooldown expires after 10s.
        check_true(
            limiter
                .check_and_record_prompt(Some("https://b.example"), now + Duration::from_secs(11))
                .is_ok(),
            "after cooldown",
        )
    }

    /// A wrong PIN reports attempts to stderr for the operator and returns
    /// a constant "PIN rejected" string, leaking no retry count to the caller.
    #[test]
    fn wrong_pin_returns_constant_refusal_string() -> TestResult {
        let (prompt, calls) = answering_prompt();
        let card = SyntheticCard::with_wrong_pin(3)?;
        let backend = ScsBackend::with_prompt(SyntheticBackend::one_reader(true, card), prompt);
        let outcome = SigningBackend::sign(&backend, request());
        check(
            &outcome,
            &Err(BackendFailure::CredentialRefused("PIN rejected".to_owned())),
            "constant PIN rejected string",
        )?;
        check(&prompts(&calls), &1, "prompts once")
    }

    #[test]
    fn estonian_qualified_sign_fails_closed_before_prompting() -> TestResult {
        let (prompt, calls) = answering_prompt();
        let card = SyntheticCard::estonian(
            refineid_lib_core::auth::PinReferenceScheme::Estonian.pin_retry_limit(),
        )?;
        let backend =
            ScsBackend::with_prompt(SyntheticBackend::one_reader(true, card.clone()), prompt);
        let mut req = request();
        req.purpose = SignPurpose::Qualified;
        let outcome = SigningBackend::sign(&backend, req);
        check_true(
            matches!(outcome, Err(BackendFailure::SigningUnavailable(_))),
            "Estonian qualified sign refused",
        )?;
        check(&prompts(&calls), &0, "never prompts for PIN2")?;
        check(
            &card.credential_or_sign_apdu_count(),
            &0,
            "zero credential or signing APDUs sent",
        )
    }
}
