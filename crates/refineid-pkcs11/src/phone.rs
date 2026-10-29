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
//! card reports (RAPP v26.10.29 sections 8.3 and 8.4). The slot's token is
//! the authentication certificate the record caches, confirmed against
//! the fingerprint the phone reports for its card and read from the card
//! afresh when the record lacks it or the phone serves another card. The
//! token stands before and between sessions, and goes when for
//! [`IDENTITY_OFFER_GRACE_MS`] no session has reported the card present,
//! at once when the pairing goes or a session reports another card
//! (section 8.4 item 3). A signature asked for by the browser is handed to
//! that thread and answered on the same session, dialing for one when
//! none is open; that is the one thing the phone does. A pairing forgotten
//! on this computer is told to the phone by that thread, on the session it
//! holds or on the next one (section 4.6). The thread sweeps the pairings
//! for idle expiry when it starts and daily (section 4.6 item 5); a pairing
//! that expires takes its slot with it, silently.
//!
//! The host finalizes the module when its user quits it or unloads the
//! module, and that is this computer's withdrawal (section 4.5 item 8):
//! the thread closes its open session with `service_withdrawn`, drops a
//! dial not yet open without a notice, keeps the pairing, and ends before
//! `C_Finalize` returns.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use refineid_lib_core::x509::{MessageSignatureAlgorithm, OwnedCert};
use refineid_pkcs11::remote::{
    RemoteOffer, RemoteSignError, RemoteTokenSource, SessionCertificate,
};
use refineid_pkcs11::slot_kind::RemoteSlotId;
use refineid_rapp::{IDENTITY_OFFER_GRACE_MS, ResultError};
use refineid_rapp_core::engine::{IDLE_SWEEP_INTERVAL, OperationOutcome, Withdrawal};
use refineid_rapp_core::file_store::FilePairingStore;
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

/// How long the token stands on a confirmed certificate while no session
/// reports the card present (section 8.4 item 3).
const IDENTITY_OFFER_GRACE: Duration = Duration::from_millis(IDENTITY_OFFER_GRACE_MS);

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

/// What the module offers for the paired phone (section 8.4 item 3): the
/// slot while the pairing stands, and the token on a certificate the phone
/// confirmed on a session, held while a session reports that card present
/// and for the grace after.
struct Offering {
    slot: RemoteSlotId,
    label: String,
    token: Option<Token>,
}

/// The certificate the token stands on, and how long it stands.
struct Token {
    certificate: Vec<u8>,
    /// The card the certificate is the authentication certificate of.
    fingerprint: CertificateFingerprint,
    /// `None` while a session reports the card present; otherwise when
    /// the token goes unless a session confirms the card first.
    until: Option<Instant>,
}

impl Token {
    fn new(certificate: Vec<u8>, until: Option<Instant>) -> Self {
        Self {
            fingerprint: CertificateFingerprint::of_certificate(&certificate),
            certificate,
            until,
        }
    }

    fn stands_at(&self, now: Instant) -> bool {
        self.until.is_none_or(|until| now < until)
    }
}

impl Offering {
    /// The pairing's slot as the module starts serving it at `now`: a
    /// certificate cached on an earlier session stands for the grace,
    /// before any session confirms it.
    fn new(slot: RemoteSlotId, label: String, cached: Option<Vec<u8>>, now: Instant) -> Self {
        Self {
            slot,
            label,
            token: cached
                .map(|certificate| Token::new(certificate, Some(now + IDENTITY_OFFER_GRACE))),
        }
    }

    /// What the module offers at `now`.
    fn remote_offer(&self, context: &DisplayText, now: Instant) -> RemoteOffer {
        RemoteOffer::new(
            self.slot,
            self.label.clone(),
            context.clone(),
            self.token
                .as_ref()
                .filter(|token| token.stands_at(now))
                .map(|token| SessionCertificate::new(token.certificate.clone())),
        )
    }

    /// A session confirmed `certificate` as the card's: the token stands
    /// on it while the session reports the card present.
    fn confirmed(&mut self, certificate: Vec<u8>) {
        self.token = Some(Token::new(certificate, None));
    }

    /// Whether the token stands on a card other than the one `reported`
    /// as present: a different card, which withdraws it at once (section
    /// 8.4 item 3).
    fn stands_on_another_card(&self, reported: CertificateFingerprint) -> bool {
        self.token
            .as_ref()
            .is_some_and(|token| token.fingerprint != reported)
    }

    /// A session reports the confirmed card present again.
    fn present(&mut self) {
        if let Some(token) = &mut self.token {
            token.until = None;
        }
    }

    /// No session reports the card present from `now` on: the session
    /// ended, or the phone reported absence. The grace runs from the first
    /// such moment.
    fn unconfirmed(&mut self, now: Instant) {
        if let Some(token) = &mut self.token
            && token.until.is_none()
        {
            token.until = Some(now + IDENTITY_OFFER_GRACE);
        }
    }

    /// The token goes at once, until a session confirms the card again.
    fn withdrawn(&mut self) {
        self.token = None;
    }
}

/// What the session thread shares with the module's calls.
struct Shared {
    offer: Mutex<Option<Offering>>,
    requests: Mutex<Option<Sender<SignRequest>>>,
    /// Raised when the host finalizes the module, which ends the thread's
    /// run; each run has its own.
    withdrawal: Mutex<Withdrawal>,
    /// A request is waiting while no session is held: the thread dials
    /// at once instead of pausing out its round.
    wanted: AtomicBool,
    context: DisplayText,
    spoken: (Mutex<bool>, Condvar),
}

impl Shared {
    /// Applies `change` to the offering and speaks.
    fn offering(&self, change: impl FnOnce(&mut Option<Offering>)) {
        if let Ok(mut offering) = self.offer.lock() {
            change(&mut offering);
        }
        let (spoken, word) = &self.spoken;
        if let Ok(mut spoken) = spoken.lock() {
            *spoken = true;
            word.notify_all();
        }
    }

    /// No pairing to offer: the slot goes with its token.
    fn withdraw_slot(&self) {
        self.offering(|offering| *offering = None);
    }

    /// The slot of the pairing the thread serves. A slot already offered
    /// keeps its token as it stands, so a new dial never extends the
    /// grace; another pairing's slot starts afresh from its cached
    /// certificate.
    fn serve_pairing(
        &self,
        slot: RemoteSlotId,
        label: String,
        cached: Option<Vec<u8>>,
        now: Instant,
    ) {
        self.offering(|offering| match offering {
            Some(current) if current.slot == slot => current.label = label,
            _ => *offering = Some(Offering::new(slot, label, cached, now)),
        });
    }

    /// Whether the offered token stands on a card other than `reported`.
    fn offers_another_card(&self, reported: CertificateFingerprint) -> bool {
        self.offer.lock().is_ok_and(|offering| {
            offering
                .as_ref()
                .is_some_and(|offering| offering.stands_on_another_card(reported))
        })
    }

    /// Applies one token event to the offered slot.
    fn token(&self, event: impl FnOnce(&mut Offering)) {
        self.offering(|offering| {
            if let Some(current) = offering {
                event(current);
            }
        });
    }

    /// Waits until the thread has published once, or `limit` passed.
    fn await_first_word(&self, limit: Duration) {
        let (spoken, word) = &self.spoken;
        if let Ok(guard) = spoken.lock() {
            let _ = word.wait_timeout_while(guard, limit, |spoken| !*spoken);
        }
    }

    /// The withdrawal of the thread's current run.
    fn withdrawal(&self) -> Withdrawal {
        self.withdrawal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Gives the next run a withdrawal not yet raised.
    fn renew_withdrawal(&self) {
        *self
            .withdrawal
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Withdrawal::new();
    }

    fn stopped(&self) -> bool {
        self.withdrawal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .raised()
    }

    fn wanted(&self) -> bool {
        self.wanted.load(Ordering::Acquire)
    }
}

/// The paired phone, offered to the module as a slot.
pub struct PhoneSource {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
    /// The directory of the pairing store the session thread reads.
    store: PathBuf,
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
    /// A source over this user's pairing store that starts its session
    /// thread at the first slot refresh.
    #[must_use]
    pub fn new() -> Self {
        Self::over_store(FilePairingStore::default_directory())
    }

    /// A source over the pairing store in `store` that starts its session
    /// thread at the first slot refresh.
    fn over_store(store: PathBuf) -> Self {
        Self {
            shared: Arc::new(Shared {
                offer: Mutex::new(None),
                requests: Mutex::new(None),
                withdrawal: Mutex::new(Withdrawal::new()),
                wanted: AtomicBool::new(false),
                context: computer_context(),
                spoken: (Mutex::new(false), Condvar::new()),
            }),
            worker: Mutex::new(None),
            store,
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
        let store = self.store.clone();
        *worker = thread::Builder::new()
            .name("refineid-phone".to_owned())
            .spawn(move || serve(&shared, &receiver, &store))
            .ok();
        drop(worker);
        self.shared.await_first_word(FIRST_WORD_WAIT);
    }
}

impl RemoteTokenSource for PhoneSource {
    fn offered(&self) -> Option<RemoteOffer> {
        self.ensure_started();
        let now = Instant::now();
        self.shared.offer.lock().ok().and_then(|offering| {
            offering
                .as_ref()
                .map(|offering| offering.remote_offer(&self.shared.context, now))
        })
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

    /// This computer withdraws (RAPP v26.10.29 section 4.5 item 8): the
    /// thread writes the `service_withdrawn` close of its open session
    /// within a quarter of the quit bound and ends; a dial in progress ends
    /// at its next step without a notice.
    fn stop(&self) {
        self.shared.withdrawal().raise();
        if let Ok(mut requests) = self.shared.requests.lock() {
            *requests = None;
        }
        // The host unloads the module once this returns: no code of it may
        // still run on the thread then.
        let handle = self.worker.lock().ok().and_then(|mut worker| worker.take());
        if let Some(handle) = handle {
            let _ = handle.join();
        }
        self.shared.withdraw_slot();
        // A host that initialises the module again starts the thread
        // again at its first slot refresh.
        if let Ok(mut spoken) = self.shared.spoken.0.lock() {
            *spoken = false;
        }
        self.shared.renew_withdrawal();
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

/// The session thread over the pairing store in `store`: read the record,
/// dial, read the certificate, hold, answer.
fn serve(shared: &Shared, requests: &Receiver<SignRequest>, store: &Path) {
    let mut idle_swept: Option<Instant> = None;
    while !shared.stopped() {
        // A pairing that expires is no longer usable: the round below
        // finds no phone and the slot goes. A refused store is swept again
        // on the next round.
        if idle_swept.is_none_or(|at| at.elapsed() >= IDLE_SWEEP_INTERVAL)
            && expire_idle_pairings(store)
        {
            idle_swept = Some(Instant::now());
        }
        // A connected card reader with a card overrides RAPP.
        // When a physical card is present in an attached reader, withdraw the phone slot.
        if refineid_lib_pcsc::presence_signature()
            .is_ok_and(|sig| sig.iter().any(|(_, present)| *present))
        {
            unpaired(shared, requests);
            pause(shared, REDIAL_PAUSE);
            continue;
        }

        // A store that cannot be read just now says nothing of the
        // pairing: the offering and its grace stand as they are.
        let Ok(mut reader) = RemoteReader::open_local_without_sweep(store)
            .map(|reader| reader.following(shared.withdrawal()))
        else {
            pause(shared, UNPAIRED_PAUSE);
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
        // The slot stands while the pairing does, and so does its token,
        // on the certificate a session confirmed, for the grace without a
        // session: a browser that asks before the session is open is given
        // the identity, and its signature wakes the dial and waits for the
        // phone within the browser's deadline (section 8.4 item 3). A
        // browser that was given no certificate once keeps resuming that
        // handshake and never asks again.
        shared.serve_pairing(
            slot,
            phone.peer_display_name.clone(),
            phone.auth_cert.clone(),
            Instant::now(),
        );
        // A phone this computer forgot is told so on a session of its own
        // when it is in sight (section 4.6 item 2).
        reader.deliver_revocation_notices();
        // A request that woke the pause has this dial; one that arrives
        // during the dial makes a failed dial try once more at once,
        // and the pause follows only when no request arrived.
        shared.wanted.store(false, Ordering::Release);
        match reader.dial_session(phone.pair_id, DIAL_TIMEOUT) {
            Ok(session) => {
                match hold(shared, requests, store, &mut reader, session, &phone, slot) {
                    After::Grace => shared.token(|offering| offering.unconfirmed(Instant::now())),
                    After::Withdraw => shared.token(Offering::withdrawn),
                }
            }
            Err(RemoteError::Busy) => pause(shared, BUSY_PAUSE),
            // The phone announced that it stopped serving: its presence
            // goes at once (section 4.5 item 6).
            Err(RemoteError::Withdrawn) => {
                shared.token(Offering::withdrawn);
                pause(shared, REDIAL_PAUSE);
            }
            Err(_) if shared.wanted() => {}
            Err(_) => pause(shared, REDIAL_PAUSE),
        }
    }
    shared.withdraw_slot();
}

/// Sweeps the pairings in `store` for idle expiry (section 4.6 item 5);
/// whether every change was stored.
fn expire_idle_pairings(store: &Path) -> bool {
    RemoteReader::open_local_without_sweep(store)
        .is_ok_and(|mut reader| reader.expire_idle_pairings().is_ok())
}

/// No pairing to serve: the slot goes, requests that wait are told the
/// token is withdrawn, and the thread pauses before looking again.
fn unpaired(shared: &Shared, requests: &Receiver<SignRequest>) {
    shared.withdraw_slot();
    shared.wanted.store(false, Ordering::Release);
    while let Ok(request) = requests.try_recv() {
        let _ = request.reply.send(Err(RemoteSignError::Withdrawn));
    }
    pause(shared, UNPAIRED_PAUSE);
}

/// What the token does once a held session has ended.
enum After {
    /// The token stands for the grace (section 8.4 item 3).
    Grace,
    /// The token goes at once, until a session confirms the card again.
    Withdraw,
}

/// What the phone's latest card report means to the held session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CardEvent {
    /// The phone holds no card: the grace runs (section 8.4 item 3).
    Absent,
    /// The phone holds the card this session confirmed.
    Confirmed,
    /// The phone holds a card this session has not confirmed.
    Unconfirmed(CertificateFingerprint),
}

/// The event the phone's `reported` card is to a session that confirmed
/// the card `confirmed`, if any.
fn card_event(
    reported: Option<CertificateFingerprint>,
    confirmed: Option<CertificateFingerprint>,
) -> CardEvent {
    match reported {
        None => CardEvent::Absent,
        Some(fingerprint) if confirmed == Some(fingerprint) => CardEvent::Confirmed,
        Some(fingerprint) => CardEvent::Unconfirmed(fingerprint),
    }
}

/// A certificate confirmed on the held session, and the card it belongs
/// to.
struct Confirmed {
    certificate: Vec<u8>,
    fingerprint: CertificateFingerprint,
}

/// How a confirmation that read nothing leaves the held session: on, or
/// ended as `After` says.
fn ended_by(error: &RemoteError) -> Option<After> {
    match error {
        // The phone forgot this computer or stopped serving: its
        // presence goes at once (sections 4.6 item 4 and 4.5 item 6).
        RemoteError::RevokedByPhone | RemoteError::Withdrawn => Some(After::Withdraw),
        RemoteError::Session(_) => Some(After::Grace),
        // A read that failed, a card that went or changed meanwhile, or a
        // cache that was not written: the session stays, the grace runs,
        // and the next report the phone sends is followed.
        _ => None,
    }
}

/// Keeps `session` while the record stays usable and the phone in sight,
/// following the phone's card reports, answering the browser's requests
/// on it and serving it between them (sections 8.3 and 8.4).
fn hold(
    shared: &Shared,
    requests: &Receiver<SignRequest>,
    store: &Path,
    reader: &mut RemoteReader,
    mut session: RemoteSession,
    phone: &PairSummary,
    slot: RemoteSlotId,
) -> After {
    let mut confirmed: Option<Confirmed> = None;
    // The card a confirmation was last tried for: a failed read is not
    // tried again until the phone reports a card anew.
    let mut tried: Option<CertificateFingerprint> = None;
    let mut record_checked = Instant::now();
    loop {
        if shared.stopped() {
            reader.withdraw_session(session);
            return After::Grace;
        }
        let event = card_event(
            session.card_fingerprint(),
            confirmed.as_ref().map(|card| card.fingerprint),
        );
        match event {
            CardEvent::Absent => {
                tried = None;
                shared.token(|offering| offering.unconfirmed(Instant::now()));
            }
            CardEvent::Confirmed => shared.token(Offering::present),
            CardEvent::Unconfirmed(reported) => {
                confirmed = None;
                // Another card than the token stands on withdraws it at
                // once; the card's own certificate brings it back.
                if shared.offers_another_card(reported) {
                    shared.token(Offering::withdrawn);
                } else {
                    shared.token(|offering| offering.unconfirmed(Instant::now()));
                }
                if tried != Some(reported) {
                    tried = Some(reported);
                    // The identity is the one whose fingerprint the phone
                    // reports (section 8.4 item 2): the cached certificate
                    // when it is that one, otherwise the card's, read once
                    // and cached.
                    match reader.confirmed_auth_cert(&mut session) {
                        Ok(certificate) => {
                            confirmed = Some(Confirmed {
                                fingerprint: CertificateFingerprint::of_certificate(&certificate),
                                certificate: certificate.clone(),
                            });
                            shared.token(|offering| offering.confirmed(certificate));
                        }
                        Err(error) => {
                            if let Some(after) = ended_by(&error) {
                                reader.close_session(session);
                                return after;
                            }
                        }
                    }
                }
            }
        }
        match requests.recv_timeout(SERVICE_STEP) {
            // The browser gave up while the session was being opened;
            // the card is not asked for a signature nobody will read.
            Ok(request) if request.expired() => {}
            Ok(request) if request.pair_id != slot => {
                let _ = request.reply.send(Err(RemoteSignError::Withdrawn));
            }
            Ok(request) => match &confirmed {
                // No card this session confirmed: absence, or a card whose
                // certificate could not be read.
                None => {
                    let error = if session.card_present() {
                        RemoteSignError::Ambiguous
                    } else {
                        RemoteSignError::CardAbsent
                    };
                    let _ = request.reply.send(Err(error));
                }
                Some(card) => {
                    let signed = sign(reader, &mut session, &request);
                    match checked(signed, &card.certificate, &request.request) {
                        Ok(signature) => {
                            let _ = request.reply.send(Ok(signature));
                        }
                        // A signature the confirmed certificate does not
                        // verify says the card on the phone is not the one
                        // cached: the token goes, the cache goes, and the
                        // next session reads the card again.
                        Err(Failure::Mismatch) => {
                            let _ = request.reply.send(Err(RemoteSignError::Ambiguous));
                            let _ = reader.forget_auth_cert(phone.pair_id);
                            reader.close_session(session);
                            return After::Withdraw;
                        }
                        Err(Failure::Sign(error)) => {
                            let _ = request.reply.send(Err(error));
                            match error {
                                // The phone stopped serving or forgot this
                                // computer: its presence goes at once.
                                RemoteSignError::Withdrawn => {
                                    reader.close_session(session);
                                    return After::Withdraw;
                                }
                                RemoteSignError::Unreachable => {
                                    reader.close_session(session);
                                    return After::Grace;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            },
            Err(RecvTimeoutError::Timeout) => {}
            // Only the module's stop drops the request channel.
            Err(RecvTimeoutError::Disconnected) => {
                reader.withdraw_session(session);
                return After::Grace;
            }
        }
        if record_checked.elapsed() >= RECORD_CHECK_INTERVAL {
            record_checked = Instant::now();
            match held_record(store, phone.pair_id) {
                HeldRecord::Usable | HeldRecord::Unreadable => {}
                HeldRecord::Forgotten => {
                    reader.revoke_in_session(session);
                    return After::Withdraw;
                }
                HeldRecord::Gone => {
                    reader.close_session(session);
                    return After::Withdraw;
                }
            }
        }
        match reader.service(&mut session, SERVICE_STEP) {
            Ok(()) => {}
            // The phone forgot this computer or stopped serving: the
            // token goes at once (sections 4.6 item 4 and 4.5 item 6).
            Err(RemoteError::RevokedByPhone | RemoteError::Withdrawn) => return After::Withdraw,
            Err(_) => return After::Grace,
        }
    }
}

/// What the record another program keeps says of the held pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeldRecord {
    /// The record still names the pairing as usable.
    Usable,
    /// This computer's user forgot the pairing, or a new pairing
    /// superseded it (RAPP v26.10.29 section 4.6): the phone is told.
    Forgotten,
    /// The store reads but holds no usable record of the pairing: the
    /// record is gone or no longer decodes. That is no forget, so the
    /// session closes without the revocation notice (section 10.1).
    Gone,
    /// The store cannot be read just now; nothing is concluded.
    Unreadable,
}

/// The held pairing as the record another program keeps in `store` says.
fn held_record(store: &Path, pair_id: PairId) -> HeldRecord {
    let Ok(reader) = RemoteReader::open_local_without_sweep(store) else {
        return HeldRecord::Unreadable;
    };
    let state = reader
        .pairs()
        .into_iter()
        .find(|pair| pair.pair_id == pair_id)
        .map(|pair| pair.state);
    match state {
        Some(PairingState::PairedDisconnected) => HeldRecord::Usable,
        Some(PairingState::Revoking) => HeldRecord::Forgotten,
        _ => HeldRecord::Gone,
    }
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
        RemoteError::CardAbsent(_) | RemoteError::CardChanged => RemoteSignError::CardAbsent,
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
        ResultError::InvalidLifetime
        | ResultError::Unauthorized
        | ResultError::UnsupportedParameter => RemoteSignError::Unsupported,
        // A failed operation; a card that did not answer is no absence
        // (section 8.4 item 1), and the token stays.
        ResultError::CardError
        | ResultError::Busy
        | ResultError::DuplicateOperation
        | ResultError::OperationFailed => RemoteSignError::Ambiguous,
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
    use refineid_rapp::{
        EndpointRole, PAIR_ID_SIZE, PAIRING_IDLE_EXPIRY_MS, PairRecord, ProfileName,
        compute_grants_hash, generate_pair_key_material,
    };
    use refineid_rapp_core::engine::current_time_ms;
    use refineid_rapp_core::remote::CardRequest;
    use refineid_rapp_core::session_lock::{SessionLock, session_lock_path};
    use refineid_rapp_core::store::{PairingRecord, PairingStore as _, PeerIntroduction};

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
            sign_error(&RemoteError::CardAbsent(CardRequest::ToPhone)),
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
        for unsupported in [
            ResultError::InvalidLifetime,
            ResultError::Unauthorized,
            ResultError::UnsupportedParameter,
        ] {
            assert_eq!(named(unsupported), RemoteSignError::Unsupported);
        }
        for failed in [
            ResultError::CardError,
            ResultError::Busy,
            ResultError::DuplicateOperation,
            ResultError::OperationFailed,
        ] {
            assert_eq!(named(failed), RemoteSignError::Ambiguous);
        }
    }

    /// A synthetic certificate a session confirmed.
    const CERTIFICATE: &[u8] = b"synthetic authentication certificate";
    /// A synthetic certificate of another card.
    const OTHER_CERTIFICATE: &[u8] = b"synthetic certificate of another card";
    /// A moment well inside the grace.
    const WITHIN_GRACE: Duration = Duration::from_secs(1);

    /// Hex digits that spell one byte.
    const HEX_DIGITS_PER_BYTE: usize = 2;
    /// Hex digits that spell a pair identifier.
    const PAIR_ID_HEX_DIGITS: usize = PAIR_ID_SIZE * HEX_DIGITS_PER_BYTE;

    fn the_slot() -> RemoteSlotId {
        RemoteSlotId::parse(&"a".repeat(PAIR_ID_HEX_DIGITS)).expect("a pair identifier in hex")
    }

    fn certificate_at(offering: &Offering, now: Instant) -> Option<Vec<u8>> {
        let context = DisplayText::new("alpha-desk".to_owned()).expect("short");
        offering
            .remote_offer(&context, now)
            .certificate()
            .map(|certificate| certificate.as_der().to_vec())
    }

    #[test]
    fn a_cached_certificate_stands_before_any_session_for_the_grace() {
        let start = Instant::now();
        let offering = Offering::new(
            the_slot(),
            "Alpha Phone".to_owned(),
            Some(CERTIFICATE.to_vec()),
            start,
        );
        assert_eq!(
            certificate_at(&offering, start + IDENTITY_OFFER_GRACE - WITHIN_GRACE),
            Some(CERTIFICATE.to_vec())
        );
        assert_eq!(
            certificate_at(&offering, start + IDENTITY_OFFER_GRACE),
            None
        );
    }

    #[test]
    fn a_reported_card_holds_the_token_and_absence_starts_the_grace() {
        let start = Instant::now();
        let mut offering = Offering::new(the_slot(), "Alpha Phone".to_owned(), None, start);
        assert_eq!(certificate_at(&offering, start), None);
        offering.confirmed(CERTIFICATE.to_vec());
        let long_after = start + IDENTITY_OFFER_GRACE + IDENTITY_OFFER_GRACE;
        assert_eq!(
            certificate_at(&offering, long_after),
            Some(CERTIFICATE.to_vec())
        );
        // Absence, or a session that ended: the grace runs from the first
        // such moment and is not restarted by another.
        offering.unconfirmed(start);
        offering.unconfirmed(start + WITHIN_GRACE);
        assert_eq!(
            certificate_at(&offering, start + IDENTITY_OFFER_GRACE),
            None
        );
        // A session reports the card present again: the token stands.
        offering.present();
        assert_eq!(
            certificate_at(&offering, long_after),
            Some(CERTIFICATE.to_vec())
        );
    }

    #[test]
    fn another_card_withdraws_at_once_until_a_session_confirms_it() {
        let start = Instant::now();
        let mut offering = Offering::new(
            the_slot(),
            "Alpha Phone".to_owned(),
            Some(CERTIFICATE.to_vec()),
            start,
        );
        offering.withdrawn();
        assert_eq!(certificate_at(&offering, start), None);
        offering.present();
        assert_eq!(certificate_at(&offering, start), None);
        offering.confirmed(OTHER_CERTIFICATE.to_vec());
        assert_eq!(
            certificate_at(&offering, start),
            Some(OTHER_CERTIFICATE.to_vec())
        );
    }

    fn shared() -> Shared {
        Shared {
            offer: Mutex::new(None),
            requests: Mutex::new(None),
            withdrawal: Mutex::new(Withdrawal::new()),
            wanted: AtomicBool::new(false),
            context: DisplayText::new("alpha-desk".to_owned()).expect("short"),
            spoken: (Mutex::new(false), Condvar::new()),
        }
    }

    /// When the offered token goes, if it is on a grace.
    fn deadline(shared: &Shared) -> Option<Instant> {
        shared
            .offer
            .lock()
            .expect("offer")
            .as_ref()
            .and_then(|offering| offering.token.as_ref())
            .and_then(|token| token.until)
    }

    #[test]
    fn a_new_dial_never_extends_the_grace() {
        let shared = shared();
        let start = Instant::now();
        // A session confirmed the card and then ended: the grace runs.
        shared.serve_pairing(the_slot(), "Alpha Phone".to_owned(), None, start);
        shared.token(|offering| offering.confirmed(CERTIFICATE.to_vec()));
        shared.token(|offering| offering.unconfirmed(start));
        let running = deadline(&shared);
        assert_eq!(running, Some(start + IDENTITY_OFFER_GRACE));
        // The next round of the thread serves the same pairing and dials
        // again, the record still caching the certificate: the deadline
        // stays, and so does a session that ends again.
        shared.serve_pairing(
            the_slot(),
            "Alpha Phone".to_owned(),
            Some(CERTIFICATE.to_vec()),
            start + WITHIN_GRACE,
        );
        shared.token(|offering| offering.unconfirmed(start + WITHIN_GRACE));
        assert_eq!(deadline(&shared), running);
        // A token withdrawn at once stays withdrawn over a new round.
        shared.token(Offering::withdrawn);
        shared.serve_pairing(
            the_slot(),
            "Alpha Phone".to_owned(),
            Some(CERTIFICATE.to_vec()),
            start + WITHIN_GRACE,
        );
        let offered = shared.offer.lock().expect("offer");
        let offering = offered.as_ref().expect("the slot stands");
        assert_eq!(certificate_at(offering, start + WITHIN_GRACE), None);
    }

    #[test]
    fn absence_at_session_start_keeps_the_offer_for_the_grace_and_a_report_confirms_it() {
        let shared = shared();
        let start = Instant::now();
        let fingerprint = CertificateFingerprint::of_certificate(CERTIFICATE);
        shared.serve_pairing(
            the_slot(),
            "Alpha Phone".to_owned(),
            Some(CERTIFICATE.to_vec()),
            start,
        );
        // The session opens with the phone reporting no card: absence is
        // no other card, so the token stays on the grace it started with.
        assert_eq!(card_event(None, None), CardEvent::Absent);
        shared.token(|offering| offering.unconfirmed(start + WITHIN_GRACE));
        assert_eq!(deadline(&shared), Some(start + IDENTITY_OFFER_GRACE));
        assert!(!shared.offers_another_card(fingerprint));
        // The phone then reports the card: the session confirms it, and
        // the token stands while the card is reported present.
        assert_eq!(
            card_event(Some(fingerprint), None),
            CardEvent::Unconfirmed(fingerprint)
        );
        shared.token(|offering| offering.confirmed(CERTIFICATE.to_vec()));
        assert_eq!(
            card_event(Some(fingerprint), Some(fingerprint)),
            CardEvent::Confirmed
        );
        assert_eq!(deadline(&shared), None);
        // Another card reported present stands against the token.
        assert!(
            shared.offers_another_card(CertificateFingerprint::of_certificate(OTHER_CERTIFICATE))
        );
    }

    #[test]
    fn the_first_word_is_awaited_and_a_later_one_is_not() {
        let shared = Shared {
            offer: Mutex::new(None),
            requests: Mutex::new(None),
            withdrawal: Mutex::new(Withdrawal::new()),
            wanted: AtomicBool::new(false),
            context: DisplayText::new("alpha-desk".to_owned()).expect("short"),
            spoken: (Mutex::new(false), Condvar::new()),
        };
        let started = Instant::now();
        shared.await_first_word(Duration::from_millis(50));
        assert!(started.elapsed() >= Duration::from_millis(50));
        shared.withdraw_slot();
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
            withdrawal: Mutex::new(Withdrawal::new()),
            wanted: AtomicBool::new(true),
            context: computer_context(),
            spoken: (Mutex::new(false), Condvar::new()),
        };
        let started = Instant::now();
        pause(&shared, Duration::from_secs(5));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// The pairing in the test's store.
    const PAIR_ID: [u8; PAIR_ID_SIZE] = *b"synthetic-pair-1";
    /// When the test's pairing was made: past the idle limit at any run.
    const LONG_AGO_MS: u64 = 1_700_000_000_000;
    /// How long the test waits for the thread's sweep to reach the store.
    const SWEEP_WAIT: Duration = Duration::from_secs(5);
    /// The pause between looks at the store.
    const SWEEP_LOOK: Duration = Duration::from_millis(20);

    /// A fresh directory for a pairing store of the test's own.
    fn scratch_store() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "refineid-pkcs11-phone-{}-{nanos:x}",
            std::process::id()
        ))
    }

    /// A confirmed pairing of [`PAIR_ID`] made at [`LONG_AGO_MS`] that has
    /// had no session.
    fn idle_pairing() -> PairingRecord {
        let local = generate_pair_key_material().expect("local keys");
        let peer = generate_pair_key_material().expect("peer keys");
        let profiles = vec![ProfileName::Authentication];
        let grants_hash = compute_grants_hash(&profiles).expect("grants hash");
        let pairing = local
            .with_private_key(|private| {
                PairRecord::new(
                    PairId::from_array(PAIR_ID),
                    EndpointRole::Requester,
                    *private,
                    *local.public_key(),
                    *peer.public_key(),
                    grants_hash,
                    profiles,
                    LONG_AGO_MS,
                )
            })
            .expect("a valid record");
        let phone = PeerIntroduction {
            display_name: "Alpha Phone".to_owned(),
            platform: "iOS".to_owned(),
        };
        PairingRecord::new(pairing, phone).expect("a requester record")
    }

    /// The state of [`PAIR_ID`] in `store`, once it reads as `state` or
    /// [`SWEEP_WAIT`] passed.
    fn state_within_wait(store: &Path, state: PairingState) -> Option<PairingState> {
        let deadline = Instant::now() + SWEEP_WAIT;
        loop {
            let read = FilePairingStore::open_without_sweep(store)
                .ok()
                .and_then(|records| {
                    records
                        .get(PairId::from_array(PAIR_ID))
                        .ok()
                        .map(PairingRecord::state)
                });
            if read == Some(state) || Instant::now() >= deadline {
                return read;
            }
            thread::sleep(SWEEP_LOOK);
        }
    }

    #[test]
    fn a_stopped_source_offers_nothing_and_signs_nothing() {
        let store = scratch_store();
        assert!(current_time_ms() >= LONG_AGO_MS + PAIRING_IDLE_EXPIRY_MS);
        FilePairingStore::open(&store)
            .expect("the test's store")
            .insert(idle_pairing())
            .expect("the pairing is stored");
        // Held here, the pairing's session lock keeps the thread from
        // dialing for the pairing.
        let session = SessionLock::acquire(&session_lock_path(&store, PairId::from_array(PAIR_ID)))
            .expect("the pairing's session lock");
        let source = PhoneSource::over_store(store.clone());
        let _ = source.offered();
        assert!(source.worker.lock().expect("worker").is_some());
        // The thread swept the test's store at its start: the pairing idle
        // past the limit expired there.
        assert_eq!(
            state_within_wait(&store, PairingState::Revoking),
            Some(PairingState::Revoking)
        );
        let run = source.shared.withdrawal();
        source.stop();
        // The run withdrew; the next one starts with its own withdrawal
        // not yet raised.
        assert!(run.raised());
        assert!(!source.shared.stopped());
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
        drop(session);
        std::fs::remove_dir_all(&store).expect("the test's store is removed");
    }
}
