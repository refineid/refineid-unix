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

//! The paired phone as a token source.
//!
//! One thread holds the session to the phone: it reads the pairing
//! record another program keeps, dials while the record is usable, and
//! keeps the session open, answering the phone's pings and reading its
//! card reports (RAPP v26.10.21 sections 8.3 and 8.4). The slot's token is
//! the authentication certificate the record caches, confirmed against
//! the fingerprint the phone reports for its card and read from the card
//! afresh when the record lacks it or the phone serves another card. A
//! signature asked for by the browser is handed to that thread and
//! answered on the same session; that is the one thing the phone does.
//! A pairing forgotten on this computer is told to the phone by that
//! thread, on the session it holds or on the next one (section 4.6).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use refineid_lib_core::x509::{MessageSignatureAlgorithm, OwnedCert};
use refineid_pkcs11::remote::{
    RemoteOffer, RemoteSignError, RemoteTokenSource, SessionCertificate,
};
use refineid_pkcs11::slot_kind::RemoteSlotId;
use refineid_rapp::ResultError;
use refineid_rapp_core::engine::OperationOutcome;
use refineid_rapp_core::ids::{CertificateFingerprint, PairId};
use refineid_rapp_core::operations::{
    CardKeyProfile, CardOperation, CardOperationResult, SignatureAlgorithm,
};
use refineid_rapp_core::remote::{
    PairSummary, RemoteError, RemoteReader, RemoteSession, local_host_name,
};
use refineid_rapp_core::store::PairingState;
use refineid_remote::{DisplayText, RemoteKeyProfile, RemoteSignatureAlgorithm, SignatureRequest};

/// How long one dial browses for the phone and waits for its card.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// The pause after a dial that found no phone or no card.
const REDIAL_PAUSE: Duration = Duration::from_secs(10);

/// The pause while another program holds the phone session.
const BUSY_PAUSE: Duration = Duration::from_secs(5);

/// The pause while no usable pairing record exists.
const UNPAIRED_PAUSE: Duration = Duration::from_secs(3);

/// How long a held session waits for a browser request, and then for the
/// phone's traffic, in turn: the phone's pings and card reports are read
/// within one step.
const SERVICE_STEP: Duration = Duration::from_millis(250);

/// Between readings of the record another program keeps, which may have
/// forgotten the held pairing.
const RECORD_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// How long the first slot refresh waits for the thread's first word,
/// so a host that lists the slots once at load sees the phone's slot.
const FIRST_WORD_WAIT: Duration = Duration::from_secs(2);

/// A signature request from the browser, answered on the held session.
struct SignRequest {
    pair_id: RemoteSlotId,
    request: SignatureRequest,
    context: DisplayText,
    deadline: Duration,
    asked_at: Instant,
    reply: SyncSender<Result<Vec<u8>, RemoteSignError>>,
}

impl SignRequest {
    /// Whether the browser has stopped waiting for the answer.
    fn expired(&self) -> bool {
        self.asked_at.elapsed() >= self.deadline
    }
}

/// What the session thread shares with the module's calls.
struct Shared {
    offer: Mutex<Option<RemoteOffer>>,
    requests: Mutex<Option<Sender<SignRequest>>>,
    stop: AtomicBool,
    /// A request is waiting while no session is held: the thread dials
    /// at once instead of pausing out its round.
    wanted: AtomicBool,
    context: DisplayText,
    spoken: (Mutex<bool>, Condvar),
}

impl Shared {
    fn publish(&self, offer: Option<RemoteOffer>) {
        if let Ok(mut slot) = self.offer.lock() {
            *slot = offer;
        }
        let (spoken, word) = &self.spoken;
        if let Ok(mut spoken) = spoken.lock() {
            *spoken = true;
            word.notify_all();
        }
    }

    /// Waits until the thread has published once, or `limit` passed.
    fn await_first_word(&self, limit: Duration) {
        let (spoken, word) = &self.spoken;
        if let Ok(guard) = spoken.lock() {
            let _ = word.wait_timeout_while(guard, limit, |spoken| !*spoken);
        }
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn wanted(&self) -> bool {
        self.wanted.load(Ordering::Acquire)
    }
}

/// The paired phone, offered to the module as a slot.
pub struct PhoneSource {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl core::fmt::Debug for PhoneSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PhoneSource")
            .field("stopped", &self.shared.stopped())
            .finish_non_exhaustive()
    }
}

impl Default for PhoneSource {
    fn default() -> Self {
        Self::new()
    }
}

impl PhoneSource {
    /// A source that starts its session thread at the first slot
    /// refresh.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                offer: Mutex::new(None),
                requests: Mutex::new(None),
                stop: AtomicBool::new(false),
                wanted: AtomicBool::new(false),
                context: computer_context(),
                spoken: (Mutex::new(false), Condvar::new()),
            }),
            worker: Mutex::new(None),
        }
    }

    fn ensure_started(&self) {
        let Ok(mut worker) = self.worker.lock() else {
            return;
        };
        if worker.is_some() || self.shared.stopped() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        if let Ok(mut requests) = self.shared.requests.lock() {
            *requests = Some(sender);
        }
        let shared = Arc::clone(&self.shared);
        *worker = thread::Builder::new()
            .name("refineid-phone".to_owned())
            .spawn(move || serve(&shared, &receiver))
            .ok();
        drop(worker);
        self.shared.await_first_word(FIRST_WORD_WAIT);
    }
}

impl RemoteTokenSource for PhoneSource {
    fn offered(&self) -> Option<RemoteOffer> {
        self.ensure_started();
        self.shared
            .offer
            .lock()
            .ok()
            .and_then(|offer| offer.clone())
    }

    fn sign(
        &self,
        pair_id: &RemoteSlotId,
        request: &SignatureRequest,
        context: &DisplayText,
        deadline: Duration,
    ) -> Result<Vec<u8>, RemoteSignError> {
        let (reply, answer) = mpsc::sync_channel(1);
        let sender = self
            .shared
            .requests
            .lock()
            .ok()
            .and_then(|requests| requests.clone())
            .ok_or(RemoteSignError::Unreachable)?;
        self.shared.wanted.store(true, Ordering::Release);
        sender
            .send(SignRequest {
                pair_id: *pair_id,
                request: request.clone(),
                context: context.clone(),
                deadline,
                asked_at: Instant::now(),
                reply,
            })
            .map_err(|_| RemoteSignError::Unreachable)?;
        match answer.recv_timeout(deadline) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(RemoteSignError::Expired),
            Err(RecvTimeoutError::Disconnected) => Err(RemoteSignError::Unreachable),
        }
    }

    fn stop(&self) {
        self.shared.stop.store(true, Ordering::Release);
        if let Ok(mut requests) = self.shared.requests.lock() {
            *requests = None;
        }
        let handle = self.worker.lock().ok().and_then(|mut worker| worker.take());
        if let Some(handle) = handle {
            let _ = handle.join();
        }
        self.shared.publish(None);
        // A host that initialises the module again starts the thread
        // again at its first slot refresh.
        if let Ok(mut spoken) = self.shared.spoken.0.lock() {
            *spoken = false;
        }
        self.shared.stop.store(false, Ordering::Release);
    }
}

/// The context every request carries: this computer, by name, and
/// nothing the module cannot know (PKCS#11 carries no relying party).
fn computer_context() -> DisplayText {
    DisplayText::new(local_host_name()).unwrap_or_else(|_| {
        DisplayText::new("RefineID".to_owned())
            .unwrap_or_else(|_| unreachable!("a short name fits"))
    })
}

/// The session thread: read the record, dial, read the certificate,
/// hold, answer.
fn serve(shared: &Shared, requests: &Receiver<SignRequest>) {
    while !shared.stopped() {
        // A connected card reader with a card overrides RAPP.
        // When a physical card is present in an attached reader, withdraw the phone slot.
        if refineid_lib_pcsc::presence_signature()
            .is_ok_and(|sig| sig.iter().any(|(_, present)| *present))
        {
            unpaired(shared, requests);
            pause(shared, REDIAL_PAUSE);
            continue;
        }

        let Ok(mut reader) = RemoteReader::open_local_without_sweep() else {
            unpaired(shared, requests);
            continue;
        };
        let Some(phone) = reader.phone() else {
            unpaired(shared, requests);
            reader.deliver_revocation_notices();
            continue;
        };
        let Some(slot) = slot_id(&phone) else {
            unpaired(shared, requests);
            continue;
        };
        // The slot stands while the pairing does, and so does its token
        // when the record carries the certificate: a browser that asks
        // before the session is open is given the identity, and its
        // signature waits for the phone within the browser's deadline. A
        // browser that was given no certificate once keeps resuming that
        // handshake and never asks again.
        shared.publish(Some(offer(slot, &phone, shared, phone.auth_cert.clone())));
        // A phone this computer forgot is told so on a session of its own
        // when it is in sight (section 4.6 item 2).
        reader.deliver_revocation_notices();
        // A request that woke the pause has this dial; one that arrives
        // during the dial makes a failed dial try once more at once,
        // and the pause follows only when no request arrived.
        shared.wanted.store(false, Ordering::Release);
        match reader.open_session(Some(phone.pair_id), DIAL_TIMEOUT) {
            Ok(session) => match hold(shared, requests, &mut reader, session, &phone, slot) {
                After::Keep(certificate) => {
                    shared.publish(Some(offer(slot, &phone, shared, Some(certificate))));
                }
                After::Withdraw => shared.publish(Some(offer(slot, &phone, shared, None))),
            },
            Err(RemoteError::Busy) => pause(shared, BUSY_PAUSE),
            Err(_) if shared.wanted() => {}
            Err(_) => pause(shared, REDIAL_PAUSE),
        }
    }
    shared.publish(None);
}

/// No pairing to serve: the slot goes, requests that wait are told the
/// token is withdrawn, and the thread pauses before looking again.
fn unpaired(shared: &Shared, requests: &Receiver<SignRequest>) {
    shared.publish(None);
    shared.wanted.store(false, Ordering::Release);
    while let Ok(request) = requests.try_recv() {
        let _ = request.reply.send(Err(RemoteSignError::Withdrawn));
    }
    pause(shared, UNPAIRED_PAUSE);
}

/// What the token does once a held session has ended.
enum After {
    /// The token stays, on this certificate, until the next session.
    Keep(Vec<u8>),
    /// The token goes until a session reads the card again.
    Withdraw,
}

/// The phone's slot, with its token when a certificate was read on the
/// open session.
fn offer(
    slot: RemoteSlotId,
    phone: &PairSummary,
    shared: &Shared,
    certificate: Option<Vec<u8>>,
) -> RemoteOffer {
    RemoteOffer::new(
        slot,
        phone.peer_display_name.clone(),
        shared.context.clone(),
        certificate.map(SessionCertificate::new),
    )
}

/// Keeps `session` while the record stays usable, answering the browser's
/// requests on it and serving it between them.
fn hold(
    shared: &Shared,
    requests: &Receiver<SignRequest>,
    reader: &mut RemoteReader,
    mut session: RemoteSession,
    phone: &PairSummary,
    slot: RemoteSlotId,
) -> After {
    // The identity is the one whose fingerprint the phone reports on this
    // session (section 8.4 item 2): the cached certificate when it is that
    // one, and otherwise the card's, read once and cached.
    let (mut certificate, mut confirmed) = match confirm(reader, &mut session) {
        Some(confirmed) => confirmed,
        None => {
            reader.close_session(session);
            pause(shared, REDIAL_PAUSE);
            return After::Withdraw;
        }
    };
    shared.publish(Some(offer(slot, phone, shared, Some(certificate.clone()))));
    let mut record_checked = Instant::now();
    loop {
        if shared.stopped() {
            reader.close_session(session);
            return After::Keep(certificate);
        }
        match requests.recv_timeout(SERVICE_STEP) {
            // The browser gave up while the session was being opened;
            // the card is not asked for a signature nobody will read.
            Ok(request) if request.expired() => {}
            Ok(request) if request.pair_id != slot => {
                let _ = request.reply.send(Err(RemoteSignError::Withdrawn));
            }
            Ok(request) => {
                let signed = sign(reader, &mut session, &request);
                match checked(signed, &certificate, &request.request) {
                    Ok(signature) => {
                        let _ = request.reply.send(Ok(signature));
                    }
                    // A signature the cached certificate does not verify
                    // says the card on the phone is not the one cached:
                    // the token goes, the cache goes, and the next session
                    // reads the card again.
                    Err(Failure::Mismatch) => {
                        let _ = request.reply.send(Err(RemoteSignError::Ambiguous));
                        let _ = reader.forget_auth_cert(phone.pair_id);
                        reader.close_session(session);
                        return After::Withdraw;
                    }
                    Err(Failure::Sign(error)) => {
                        let _ = request.reply.send(Err(error));
                        if matches!(
                            error,
                            RemoteSignError::Unreachable | RemoteSignError::Withdrawn
                        ) {
                            reader.close_session(session);
                            return After::Keep(certificate);
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                reader.close_session(session);
                return After::Keep(certificate);
            }
        }
        if record_checked.elapsed() >= RECORD_CHECK_INTERVAL {
            record_checked = Instant::now();
            if forgotten_here(phone.pair_id) {
                reader.revoke_in_session(session);
                return After::Withdraw;
            }
        }
        match reader.service(&mut session, SERVICE_STEP) {
            Ok(()) => {}
            // The phone forgot this computer: the pairing and its token go.
            Err(RemoteError::RevokedByPhone) => return After::Withdraw,
            Err(_) => return After::Keep(certificate),
        }
        // The phone serves another card: the identity offered is not its
        // until the card's certificate is read and confirmed.
        if session
            .card_fingerprint()
            .is_some_and(|reported| reported != confirmed)
        {
            match confirm(reader, &mut session) {
                Some((read, fingerprint)) => {
                    certificate = read;
                    confirmed = fingerprint;
                    shared.publish(Some(offer(slot, phone, shared, Some(certificate.clone()))));
                }
                None => {
                    reader.close_session(session);
                    return After::Withdraw;
                }
            }
        }
    }
}

/// The certificate of the card the phone reports on `session`, with the
/// fingerprint the phone confirmed it by.
fn confirm(
    reader: &mut RemoteReader,
    session: &mut RemoteSession,
) -> Option<(Vec<u8>, CertificateFingerprint)> {
    let certificate = reader.confirmed_auth_cert(session).ok()?;
    let fingerprint = CertificateFingerprint::of_certificate(&certificate);
    Some((certificate, fingerprint))
}

/// Whether this computer's user forgot the held pairing, as the record
/// another program keeps says (RAPP v26.10.21 section 4.6): forgotten
/// here, or superseded by a new pairing. Only that word revokes; a store
/// that cannot be read, or a record that does not decode, concludes
/// nothing (section 10.1).
fn forgotten_here(pair_id: PairId) -> bool {
    RemoteReader::open_local_without_sweep().is_ok_and(|reader| {
        reader
            .pairs()
            .iter()
            .any(|pair| pair.pair_id == pair_id && pair.state == PairingState::Revoking)
    })
}

/// Why a request yielded no signature for the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// The phone answered with a signature the cached certificate does
    /// not verify: the card on the phone is not the one cached.
    Mismatch,
    /// The phone gave no signature, for the reason the module reports.
    Sign(RemoteSignError),
}

/// Runs one signature request on the session.
fn sign(
    reader: &mut RemoteReader,
    session: &mut RemoteSession,
    request: &SignRequest,
) -> Result<Vec<u8>, RemoteSignError> {
    let operation = authentication_operation(&request.request, &request.context);
    match reader.execute_on_with_lifetime(session, &operation, request.deadline) {
        Ok(CardOperationResult::Signature(signature)) => Ok(signature),
        Ok(_) => Err(RemoteSignError::Unsupported),
        Err(error) => Err(sign_error(&error)),
    }
}

/// The signature as it may be handed on: checked under the public key
/// of the certificate the token carries, which this computer does
/// alone. A profile the module cannot check is reported unsupported and
/// the cache kept; a signature that does not verify is a mismatch.
fn checked(
    signed: Result<Vec<u8>, RemoteSignError>,
    certificate: &[u8],
    request: &SignatureRequest,
) -> Result<Vec<u8>, Failure> {
    let signature = signed.map_err(Failure::Sign)?;
    let algorithm = message_algorithm(request.algorithm())
        .ok_or(Failure::Sign(RemoteSignError::Unsupported))?;
    let verifies = OwnedCert::from_der(certificate).is_ok_and(|certificate| {
        certificate
            .view()
            .spki
            .verify_digest_signature(algorithm, request.digest(), &signature)
            .is_ok()
    });
    if verifies {
        Ok(signature)
    } else {
        Err(Failure::Mismatch)
    }
}

/// The verification profile of a request's algorithm; the card signs a
/// digest, and ECDSA comes back as `r || s`.
const fn message_algorithm(
    algorithm: RemoteSignatureAlgorithm,
) -> Option<MessageSignatureAlgorithm> {
    match algorithm {
        RemoteSignatureAlgorithm::EcdsaSha256 => Some(MessageSignatureAlgorithm::EcdsaSha256Raw),
        RemoteSignatureAlgorithm::EcdsaSha384 => Some(MessageSignatureAlgorithm::EcdsaSha384Raw),
        RemoteSignatureAlgorithm::EcdsaSha512 => Some(MessageSignatureAlgorithm::EcdsaSha512Raw),
        RemoteSignatureAlgorithm::RsaPkcs1Sha256 => Some(MessageSignatureAlgorithm::RsaPkcs1Sha256),
        RemoteSignatureAlgorithm::RsaPkcs1Sha384 => Some(MessageSignatureAlgorithm::RsaPkcs1Sha384),
        RemoteSignatureAlgorithm::RsaPkcs1Sha512 => Some(MessageSignatureAlgorithm::RsaPkcs1Sha512),
        RemoteSignatureAlgorithm::RsaPssSha256 => Some(MessageSignatureAlgorithm::RsaPssSha256),
        RemoteSignatureAlgorithm::EcdsaSha224 => None,
    }
}

/// The card operation for a browser's signature request.
fn authentication_operation(request: &SignatureRequest, context: &DisplayText) -> CardOperation {
    CardOperation::BrowserAuthenticate {
        origin: context.as_str().to_owned(),
        key_profile: key_profile(request.key_profile()),
        algorithm: signature_algorithm(request.algorithm()),
        digest: request.digest().to_vec(),
    }
}

const fn key_profile(profile: RemoteKeyProfile) -> CardKeyProfile {
    match profile {
        RemoteKeyProfile::EcdsaP256 => CardKeyProfile::EcdsaP256,
        RemoteKeyProfile::EcdsaP384 => CardKeyProfile::EcdsaP384,
        RemoteKeyProfile::Rsa2048 => CardKeyProfile::Rsa2048,
        RemoteKeyProfile::Rsa3072 => CardKeyProfile::Rsa3072,
    }
}

const fn signature_algorithm(algorithm: RemoteSignatureAlgorithm) -> SignatureAlgorithm {
    match algorithm {
        RemoteSignatureAlgorithm::EcdsaSha224 => SignatureAlgorithm::EcdsaSha224,
        RemoteSignatureAlgorithm::EcdsaSha256 => SignatureAlgorithm::EcdsaSha256,
        RemoteSignatureAlgorithm::EcdsaSha384 => SignatureAlgorithm::EcdsaSha384,
        RemoteSignatureAlgorithm::EcdsaSha512 => SignatureAlgorithm::EcdsaSha512,
        RemoteSignatureAlgorithm::RsaPkcs1Sha256 => SignatureAlgorithm::RsaPkcs1Sha256,
        RemoteSignatureAlgorithm::RsaPkcs1Sha384 => SignatureAlgorithm::RsaPkcs1Sha384,
        RemoteSignatureAlgorithm::RsaPkcs1Sha512 => SignatureAlgorithm::RsaPkcs1Sha512,
        RemoteSignatureAlgorithm::RsaPssSha256 => SignatureAlgorithm::RsaPssSha256,
    }
}

/// The module's view of a failed request.
fn sign_error(error: &RemoteError) -> RemoteSignError {
    match error {
        RemoteError::CardAbsent | RemoteError::CardChanged => RemoteSignError::CardAbsent,
        RemoteError::Withdrawn | RemoteError::RevokedByPhone => RemoteSignError::Withdrawn,
        RemoteError::Outcome(outcome) => outcome_error(outcome),
        _ => RemoteSignError::Unreachable,
    }
}

fn outcome_error(outcome: &OperationOutcome) -> RemoteSignError {
    match outcome {
        OperationOutcome::Rejected(error) | OperationOutcome::Cancelled(error) => {
            result_error(*error)
        }
        // The session ended with the operation live: whether the card
        // signed is not known here (section 8.1 item 3).
        OperationOutcome::Lost => RemoteSignError::Ambiguous,
        OperationOutcome::Refused | OperationOutcome::Completed(_) => RemoteSignError::Unsupported,
    }
}

/// A section 10.3 error name the phone gave, as the module reports it.
const fn result_error(error: ResultError) -> RemoteSignError {
    match error {
        ResultError::UserCancelled => RemoteSignError::Cancelled,
        ResultError::OperationExpired => RemoteSignError::Expired,
        ResultError::RetryFloor => RemoteSignError::CredentialLocked,
        ResultError::CardError => RemoteSignError::CardAbsent,
        ResultError::InvalidLifetime
        | ResultError::Unauthorized
        | ResultError::UnsupportedParameter => RemoteSignError::Unsupported,
        ResultError::Busy | ResultError::DuplicateOperation | ResultError::OperationFailed => {
            RemoteSignError::Ambiguous
        }
    }
}

fn slot_id(phone: &PairSummary) -> Option<RemoteSlotId> {
    RemoteSlotId::parse(&phone.pair_id_hex()).ok()
}

/// Sleeps for `duration` in short steps, so a stop is seen promptly and
/// a request that arrives meanwhile ends the pause within one step.
fn pause(shared: &Shared, duration: Duration) {
    const STEP: Duration = Duration::from_millis(250);
    let mut left = duration;
    while !left.is_zero() && !shared.stopped() && !shared.wanted() {
        let step = left.min(STEP);
        thread::sleep(step);
        left -= step;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_SHA384_LEN: usize = 48;

    #[test]
    fn a_browser_request_becomes_an_authentication_on_the_named_computer() {
        let request = SignatureRequest::new(
            RemoteKeyProfile::EcdsaP384,
            RemoteSignatureAlgorithm::EcdsaSha384,
            vec![7; DIGEST_SHA384_LEN],
        )
        .expect("a registered combination");
        let context = DisplayText::new("alpha-desk".to_owned()).expect("short");
        let CardOperation::BrowserAuthenticate {
            origin,
            key_profile,
            algorithm,
            digest,
        } = authentication_operation(&request, &context)
        else {
            panic!("a browser authentication");
        };
        assert_eq!(origin, "alpha-desk");
        assert_eq!(key_profile, CardKeyProfile::EcdsaP384);
        assert_eq!(algorithm, SignatureAlgorithm::EcdsaSha384);
        assert_eq!(digest, vec![7; DIGEST_SHA384_LEN]);
    }

    #[test]
    fn every_phone_answer_maps_to_a_module_error() {
        assert_eq!(
            sign_error(&RemoteError::CardAbsent),
            RemoteSignError::CardAbsent
        );
        assert_eq!(
            sign_error(&RemoteError::Withdrawn),
            RemoteSignError::Withdrawn
        );
        assert_eq!(
            sign_error(&RemoteError::RevokedByPhone),
            RemoteSignError::Withdrawn
        );
        assert_eq!(sign_error(&RemoteError::Busy), RemoteSignError::Unreachable);
        assert_eq!(
            sign_error(&RemoteError::NotPaired),
            RemoteSignError::Unreachable
        );
        assert_eq!(
            outcome_error(&OperationOutcome::Lost),
            RemoteSignError::Ambiguous
        );
        assert_eq!(
            outcome_error(&OperationOutcome::Refused),
            RemoteSignError::Unsupported
        );
    }

    #[test]
    fn every_error_name_the_phone_gives_maps_to_a_module_error() {
        let named = |error: ResultError| outcome_error(&OperationOutcome::Rejected(error));
        assert_eq!(
            named(ResultError::UserCancelled),
            RemoteSignError::Cancelled
        );
        assert_eq!(
            outcome_error(&OperationOutcome::Cancelled(ResultError::OperationExpired)),
            RemoteSignError::Expired
        );
        assert_eq!(
            named(ResultError::RetryFloor),
            RemoteSignError::CredentialLocked
        );
        assert_eq!(named(ResultError::CardError), RemoteSignError::CardAbsent);
        for unsupported in [
            ResultError::InvalidLifetime,
            ResultError::Unauthorized,
            ResultError::UnsupportedParameter,
        ] {
            assert_eq!(named(unsupported), RemoteSignError::Unsupported);
        }
        for unknown in [
            ResultError::Busy,
            ResultError::DuplicateOperation,
            ResultError::OperationFailed,
        ] {
            assert_eq!(named(unknown), RemoteSignError::Ambiguous);
        }
    }

    #[test]
    fn the_first_word_is_awaited_and_a_later_one_is_not() {
        let shared = Shared {
            offer: Mutex::new(None),
            requests: Mutex::new(None),
            stop: AtomicBool::new(false),
            wanted: AtomicBool::new(false),
            context: DisplayText::new("alpha-desk".to_owned()).expect("short"),
            spoken: (Mutex::new(false), Condvar::new()),
        };
        let started = Instant::now();
        shared.await_first_word(Duration::from_millis(50));
        assert!(started.elapsed() >= Duration::from_millis(50));
        shared.publish(None);
        let started = Instant::now();
        shared.await_first_word(Duration::from_secs(5));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_signature_is_handed_on_only_after_it_verifies_under_the_certificate() {
        let request = SignatureRequest::new(
            RemoteKeyProfile::EcdsaP384,
            RemoteSignatureAlgorithm::EcdsaSha384,
            vec![7; DIGEST_SHA384_LEN],
        )
        .expect("a registered combination");
        // A signature the certificate cannot vouch for is a mismatch,
        // never a signature for the browser; here the certificate parses
        // as nothing, so no signature can verify under it.
        assert_eq!(
            checked(Ok(vec![0; 96]), &[], &request),
            Err(Failure::Mismatch)
        );
        // The phone's own refusal passes through and keeps the cache.
        assert_eq!(
            checked(Err(RemoteSignError::Cancelled), &[], &request),
            Err(Failure::Sign(RemoteSignError::Cancelled))
        );
        // A profile the module cannot check is unsupported, not a
        // mismatch.
        let unchecked = SignatureRequest::new(
            RemoteKeyProfile::EcdsaP256,
            RemoteSignatureAlgorithm::EcdsaSha224,
            vec![7; 28],
        )
        .expect("a registered combination");
        assert_eq!(
            checked(Ok(vec![0; 64]), &[], &unchecked),
            Err(Failure::Sign(RemoteSignError::Unsupported))
        );
        assert_eq!(
            message_algorithm(RemoteSignatureAlgorithm::EcdsaSha384),
            Some(MessageSignatureAlgorithm::EcdsaSha384Raw)
        );
    }

    #[test]
    fn a_request_ends_the_pause_at_once() {
        let shared = Shared {
            offer: Mutex::new(None),
            requests: Mutex::new(None),
            stop: AtomicBool::new(false),
            wanted: AtomicBool::new(true),
            context: computer_context(),
            spoken: (Mutex::new(false), Condvar::new()),
        };
        let started = Instant::now();
        pause(&shared, Duration::from_secs(5));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_stopped_source_offers_nothing_and_signs_nothing() {
        let source = PhoneSource::new();
        let _ = source.offered();
        assert!(source.worker.lock().expect("worker").is_some());
        source.stop();
        assert!(source.worker.lock().expect("worker").is_none());
        assert!(source.shared.offer.lock().expect("offer").is_none());
        assert!(source.shared.requests.lock().expect("requests").is_none());
        let request = SignatureRequest::new(
            RemoteKeyProfile::EcdsaP384,
            RemoteSignatureAlgorithm::EcdsaSha384,
            vec![1; DIGEST_SHA384_LEN],
        )
        .expect("a registered combination");
        let pair_id = RemoteSlotId::parse(&"0".repeat(32)).expect("a pair identifier");
        let context = DisplayText::new("alpha-desk".to_owned()).expect("short");
        assert_eq!(
            source.sign(&pair_id, &request, &context, Duration::from_millis(10)),
            Err(RemoteSignError::Unreachable)
        );
        // A host that initialises again gets the thread again.
        let _ = source.offered();
        assert!(source.worker.lock().expect("worker").is_some());
        source.stop();
    }
}
