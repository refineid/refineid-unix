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
//! record another program keeps, looks for the phone while the record is
//! usable, dials as the view of the phone says (RAPP v26.11.2 section 8.3:
//! when the phone appears, when the browser asks with no session open,
//! and within the redial window after a loss), and keeps the session open,
//! answering the phone's pings and reading its card reports (section 8.4). The slot's token is
//! the authentication certificate read from the phone's card on a session
//! and held in memory only: the pairing record keeps none (refineid-core
//! `doc/security/certificate-custody.md`). Until a session confirms the
//! card the slot has no token. The token then stands while sessions follow,
//! and goes when for [`IDENTITY_OFFER_GRACE_MS`] no session has reported
//! the card present, at once when the pairing goes or a session reports
//! another card (section 8.4 item 3); a session then reads the card again.
//! A module call that asks for the token while none stands and no session
//! is open wakes the dial and waits, as long as the module allows it, for a
//! session to raise the token, so a browser's first login finds the
//! certificate. A signature asked for by the browser is handed
//! to that thread and answered on the same session, dialing for one when
//! none is open; that is the one thing the phone does. A phone that
//! withdrew, or closed with `card_unavailable`, takes the token at once
//! and is not dialed until it announces itself again (section 4.5 item 6);
//! a request meanwhile is refused at once. A pairing forgotten on this
//! computer while the thread holds its session is told to the phone on
//! that session (section 4.6 item 1); the program that forgot it tells the
//! phone when it appears otherwise, from the revocation backlog (item 6).
//! The backlog runs alongside the active pairing while remote use is on,
//! and alone while a local card suspends remote use or no pairing is
//! usable.
//! The thread sweeps the pairings for idle expiry when
//! it starts and daily (section 4.6 item 5); a pairing that expires takes
//! its slot with it, silently.
//!
//! The host finalizes the module when its user quits it or unloads the
//! module, and that is this computer's withdrawal (section 4.5 item 8):
//! the thread closes its open session with `service_withdrawn`, drops a
//! dial not yet open without a notice, keeps the pairing, and ends before
//! `C_Finalize` returns.

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use refineid_lib_core::x509::{DigestCheckError, MessageSignatureAlgorithm, OwnedCert};
use refineid_pkcs11::remote::{
    RemoteOffer, RemoteSignError, RemoteTokenSource, SessionCertificate,
};
use refineid_pkcs11::slot_kind::RemoteSlotId;
use refineid_rapp::{IDENTITY_OFFER_GRACE_MS, RequesterSessionEnd, ResultError};
use refineid_rapp_core::engine::{IDLE_SWEEP_INTERVAL, OperationOutcome, Withdrawal};
use refineid_rapp_core::file_store::FilePairingStore;
use refineid_rapp_core::ids::{CertificateFingerprint, PairId};
use refineid_rapp_core::operations::{
    CardKeyProfile, CardOperation, CardOperationResult, SignatureAlgorithm,
};
use refineid_rapp_core::remote::{
    BacklogSightings, PairSummary, RemoteError, RemoteReader, RemoteSession, SessionTier,
    local_host_name,
};
use refineid_rapp_core::store::PairingState;
use refineid_rapp_core::view::{ConsumerAnswer, CustodianView};
use refineid_remote::{DisplayText, RemoteKeyProfile, RemoteSignatureAlgorithm, SignatureRequest};

/// How long one dial browses for the phone beyond its first round: none,
/// so a dial tries the phones in sight once.
const DIAL_BROWSE: Duration = Duration::ZERO;
/// The transport label a failure names when no session carried it.
#[cfg(debug_assertions)]
const NO_SESSION_LABEL: &str = "no session";
/// The peer a failed session names when no paired phone is served.
const UNKNOWN_PAIRING_LABEL: &str = "unknown pairing";

/// A failed session's cause with its peer and transport: `case` is the
/// error's case name or a fixed text, `peer` the paired phone's display
/// name (a device label, never a holder name), and `tier` the tier of the
/// held session that carried the failure, `None` when none did.
#[cfg(debug_assertions)]
#[must_use]
fn session_failure_message(case: &str, peer: &str, tier: Option<SessionTier>) -> String {
    let transport = tier.map_or(NO_SESSION_LABEL, SessionTier::label);
    format!("{case}, {peer}, {transport}")
}

/// Reports a failed signature request naming its peer and transport; in a
/// release build this borrows its inputs and writes nothing.
#[cfg(debug_assertions)]
fn report_signature_failure(peer: &str, tier: Option<SessionTier>, error: &RemoteSignError) {
    let case = refineid_dev_errors::Cause::case(error);
    let message = session_failure_message(case.as_str(), peer, tier);
    refineid_dev_errors::report!(Pkcs11, "signature request failed", name message.as_str());
}

/// Reports a failed signature request naming its peer and transport; in a
/// release build this borrows its inputs and writes nothing.
#[cfg(not(debug_assertions))]
fn report_signature_failure(peer: &str, tier: Option<SessionTier>, error: &RemoteSignError) {
    let _ = (peer, tier, error);
}

/// Reports a failed session event with a fixed text cause, naming its peer
/// and transport; in a release build this borrows its inputs and writes
/// nothing.
#[cfg(debug_assertions)]
fn report_session_text(
    event: &'static str,
    peer: &str,
    tier: Option<SessionTier>,
    text: &'static str,
) {
    let message = session_failure_message(text, peer, tier);
    refineid_dev_errors::report!(Pkcs11, event, name message.as_str());
}

/// Reports a failed session event with a fixed text cause, naming its peer
/// and transport; in a release build this borrows its inputs and writes
/// nothing.
#[cfg(not(debug_assertions))]
fn report_session_text(
    event: &'static str,
    peer: &str,
    tier: Option<SessionTier>,
    text: &'static str,
) {
    let _ = (event, peer, tier, text);
}

/// The pause between looks for the phone while no session is held.
const LOOK_PAUSE: Duration = Duration::from_secs(1);

/// The pause while a card in a reader here suspends remote use.
const SUSPENDED_PAUSE: Duration = Duration::from_secs(10);

/// The pause while another program holds the phone session.
const BUSY_PAUSE: Duration = Duration::from_secs(5);

/// The pause while no usable pairing record exists.
const UNPAIRED_PAUSE: Duration = Duration::from_secs(3);

/// How often a held session lets the revocation backlog look for its
/// phones (section 4.6 item 6): often enough to tell a phone that
/// appears, seldom enough to leave the held session alone.
const BACKLOG_DURING_SESSION: Duration = Duration::from_secs(30);

/// How long a held session waits for a browser request, and then for the
/// phone's traffic, in turn: the phone's pings and card reports are read
/// within one step.
const SERVICE_STEP: Duration = Duration::from_millis(250);

/// Between readings of the record another program keeps, which may have
/// forgotten the held pairing: the close then leaves on the held session,
/// within the quit bound (section 4.6 items 1 and 6).
const RECORD_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// How long the token stands on a confirmed certificate while no session
/// reports the card present (section 8.4 item 3).
const IDENTITY_OFFER_GRACE: Duration = Duration::from_millis(IDENTITY_OFFER_GRACE_MS);

/// The longest part of a reading's wait spent on the thread's first word,
/// so a host that lists the slots once at load sees the phone's slot; the
/// rest of the wait is the token's.
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
/// confirmed on a session, held in memory while a session reports that
/// card present and for the grace after.
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
    /// The pairing's slot as the module starts serving it: no token until
    /// a session confirms the card.
    const fn new(slot: RemoteSlotId, label: String) -> Self {
        Self {
            slot,
            label,
            token: None,
        }
    }

    /// The certificate the token stands on at `now`, if it stands.
    fn standing_certificate(&self, now: Instant) -> Option<&[u8]> {
        self.token
            .as_ref()
            .filter(|token| token.stands_at(now))
            .map(|token| token.certificate.as_slice())
    }

    /// What the module offers at `now`.
    fn remote_offer(&self, context: &DisplayText, now: Instant) -> RemoteOffer {
        RemoteOffer::new(
            self.slot,
            self.label.clone(),
            context.clone(),
            self.standing_certificate(now)
                .map(|certificate| SessionCertificate::new(certificate.to_vec())),
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

/// Whether a reader of this computer holds a card, which suspends remote
/// use. The module asks PC/SC ([`card_in_a_reader`]); tests give their own.
type LocalCardCheck = fn() -> bool;

/// Whether any PC/SC reader of this computer holds a card.
fn card_in_a_reader() -> bool {
    refineid_lib_pcsc::presence_signature().is_ok_and(|sig| sig.iter().any(|(_, present)| *present))
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
    /// The thread holds a session to the phone.
    in_session: AtomicBool,
    context: DisplayText,
    spoken: (Mutex<bool>, Condvar),
    /// Whether a local card suspends remote use just now.
    local_card: LocalCardCheck,
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
    /// grace; another pairing's slot starts with no token.
    fn serve_pairing(&self, slot: RemoteSlotId, label: String) {
        self.offering(|offering| match offering {
            Some(current) if current.slot == slot => current.label = label,
            _ => *offering = Some(Offering::new(slot, label)),
        });
    }

    /// The certificate the offered token stands on at `now`, if any: the
    /// one a session read, held in memory.
    fn standing_certificate(&self, now: Instant) -> Option<Vec<u8>> {
        self.offer.lock().ok().and_then(|offering| {
            offering
                .as_ref()
                .and_then(|offering| offering.standing_certificate(now))
                .map(<[u8]>::to_vec)
        })
    }

    /// Whether the phone's slot is offered without a standing token.
    fn slot_without_token(&self) -> bool {
        self.offer.lock().is_ok_and(|offering| {
            offering
                .as_ref()
                .is_some_and(|offering| offering.standing_certificate(Instant::now()).is_none())
        })
    }

    /// A reading that asks for the token found the phone's slot without
    /// one: with no session held, the thread is asked to dial (section
    /// 8.3), and the reading waits up to `limit` for a session to raise the
    /// token. A zero `limit` asks nothing. How often a reading may wait is
    /// the module's to decide.
    fn wake_for_token(&self, limit: Duration) {
        if limit.is_zero() || self.in_session.load(Ordering::Acquire) || !self.slot_without_token()
        {
            return;
        }
        self.wanted.store(true, Ordering::Release);
        let (spoken, word) = &self.spoken;
        if let Ok(guard) = spoken.lock() {
            let _ = word.wait_timeout_while(guard, limit, |_| {
                self.slot_without_token() && !self.stopped()
            });
        }
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

impl PhoneSource {
    /// A source over this user's pairing store that starts its session
    /// thread at the first reading that may wait, or `None` when no per-user
    /// configuration directory resolves or the store is not this
    /// process's: owned by its effective uid, or missing while it is not root.
    #[must_use]
    pub fn for_this_user() -> Option<Self> {
        let store = FilePairingStore::default_directory()?;
        store_is_ours(StoreOwner::of(&store), effective_uid())
            .then(|| Self::over_store(store, card_in_a_reader))
    }

    /// A source over the pairing store in `store` that starts its session
    /// thread at the first reading that may wait, with `local_card` telling
    /// it when a card in a reader suspends remote use.
    fn over_store(store: PathBuf, local_card: LocalCardCheck) -> Self {
        Self {
            shared: Arc::new(Shared {
                offer: Mutex::new(None),
                requests: Mutex::new(None),
                withdrawal: Mutex::new(Withdrawal::new()),
                wanted: AtomicBool::new(false),
                in_session: AtomicBool::new(false),
                context: computer_context(),
                spoken: (Mutex::new(false), Condvar::new()),
                local_card,
            }),
            worker: Mutex::new(None),
            store,
        }
    }

    /// Starts the session thread when none runs, and waits at most `limit`
    /// for its first word.
    fn ensure_started(&self, limit: Duration) {
        let Ok(mut worker) = self.worker.lock() else {
            return;
        };
        if worker.is_none() && !self.shared.stopped() {
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
        }
        let running = worker.is_some();
        drop(worker);
        if running {
            self.shared.await_first_word(limit);
        }
    }
}

impl RemoteTokenSource for PhoneSource {
    /// The slot and its token as the thread last spoke of them. A reading
    /// with a `wait` starts the thread, waits for its first word for at
    /// most `FIRST_WORD_WAIT` of it, and spends the rest waking the dial
    /// when no token stands; a zero `wait` reads what stands, starts
    /// nothing and dials nothing.
    fn offered(&self, wait: Duration) -> Option<RemoteOffer> {
        let asked = Instant::now();
        if !wait.is_zero() {
            self.ensure_started(wait.min(FIRST_WORD_WAIT));
            self.shared
                .wake_for_token(wait.saturating_sub(asked.elapsed()));
        }
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

    /// This computer withdraws (RAPP v26.11.2 section 4.5 item 8): the
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
        // again at its first reading that may wait.
        if let Ok(mut spoken) = self.shared.spoken.0.lock() {
            *spoken = false;
        }
        self.shared.renew_withdrawal();
        refineid_dev_errors::flush!();
    }
}

/// The superuser's uid.
const ROOT_UID: libc::uid_t = 0;

/// Who owns the pairing store's directory, as its metadata reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreOwner {
    /// The directory does not exist.
    Missing,
    /// The directory exists and this uid owns it.
    Uid(libc::uid_t),
    /// The directory's metadata cannot be read.
    Unreadable,
}

impl StoreOwner {
    /// The owner of `directory`.
    fn of(directory: &Path) -> Self {
        match std::fs::metadata(directory) {
            Ok(metadata) => Self::Uid(metadata.uid()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::Missing,
            Err(_) => Self::Unreadable,
        }
    }
}

/// Whether the process running as `effective_uid` serves the phone from
/// the store `owner` describes: a store it owns; a missing store unless
/// it runs as root, so the owner's first pairing still creates it; never
/// a store it cannot read.
fn store_is_ours(owner: StoreOwner, effective_uid: libc::uid_t) -> bool {
    match owner {
        StoreOwner::Uid(uid) => uid == effective_uid,
        StoreOwner::Missing => effective_uid != ROOT_UID,
        StoreOwner::Unreadable => false,
    }
}

/// The process's effective uid.
#[allow(
    unsafe_code,
    reason = "geteuid(2) is the only source of the effective uid; the call takes no arguments"
)]
fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid has no preconditions and always succeeds
    // (POSIX.1-2017, geteuid).
    unsafe { libc::geteuid() }
}

/// The context every request carries: this computer, by name, and
/// nothing the module cannot know (PKCS#11 carries no relying party).
fn computer_context() -> DisplayText {
    DisplayText::new(local_host_name()).unwrap_or_else(|_| {
        DisplayText::new("RefineID".to_owned())
            .unwrap_or_else(|_| unreachable!("a short name fits"))
    })
}

/// What the pairing store directory looked like at one reading: its own
/// modification time, and each entry's name, length and modification
/// time. The records are read and parsed anew only when this differs
/// from the last reading, so a look that finds nothing changed costs one
/// directory listing and no file reads. A store that cannot be listed has
/// an empty signature, which differs from any listing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct StoreSignature {
    /// The directory's modification time, which a record added, removed
    /// or replaced by rename changes.
    directory: Option<SystemTime>,
    /// Each entry's name, length and modification time, in name order.
    entries: Vec<(OsString, u64, Option<SystemTime>)>,
}

impl StoreSignature {
    /// The signature of `store` now.
    fn of(store: &Path) -> Self {
        let directory = std::fs::metadata(store)
            .and_then(|metadata| metadata.modified())
            .ok();
        let mut entries: Vec<_> = std::fs::read_dir(store)
            .map(|dir| {
                dir.filter_map(Result::ok)
                    .map(|entry| {
                        let metadata = entry.metadata().ok();
                        (
                            entry.file_name(),
                            metadata.as_ref().map_or(0, std::fs::Metadata::len),
                            metadata.and_then(|metadata| metadata.modified().ok()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        entries.sort();
        Self { directory, entries }
    }
}

/// The session thread over the pairing store in `store`: read the record,
/// look for the phone, dial as the view says, read the certificate, hold,
/// answer.
fn serve(shared: &Shared, requests: &Receiver<SignRequest>, store: &Path) {
    let mut idle_swept: Option<Instant> = None;
    // The view of the phone, and the pairing it belongs to.
    let mut view = CustodianView::new();
    let mut viewed: Option<PairId> = None;
    // The store as last read, and its signature then: read again only
    // when the directory says something changed.
    let mut opened: Option<(StoreSignature, RemoteReader)> = None;
    // In-sight memory for the revocation backlog (section 4.6 item 6): it
    // lives as long as the thread, across reader reopens, so a phone that
    // stays in sight is dialed once.
    let mut sightings = BacklogSightings::default();
    while !shared.stopped() {
        // A pairing that expires is gone: the round below finds no phone
        // and the slot goes. A refused store is swept again on the next
        // round.
        if idle_swept.is_none_or(|at| at.elapsed() >= IDLE_SWEEP_INTERVAL)
            && expire_idle_pairings(store)
        {
            idle_swept = Some(Instant::now());
        }
        // A connected card reader with a card overrides RAPP: remote use
        // is suspended, and resumes with a fresh look when the card goes.
        if (shared.local_card)() {
            unpaired(shared, requests);
            viewed = None;
            // A local card suspends remote use but not the revocation
            // backlog, which is then the only remote activity (section
            // 4.6 item 6).
            if let Ok(mut backlog) = RemoteReader::open_local_without_sweep(store) {
                backlog.tell_forgotten_phones(&mut sightings);
            }
            pause(shared, SUSPENDED_PAUSE);
            continue;
        }

        // A store that cannot be read just now says nothing of the
        // pairing: the offering and its grace stand as they are.
        let signature = StoreSignature::of(store);
        if opened.as_ref().is_none_or(|(seen, _)| *seen != signature) {
            opened = RemoteReader::open_local_without_sweep(store)
                .map(|reader| (signature, reader.following(shared.withdrawal())))
                .ok();
        }
        let Some((_, reader)) = opened.as_mut() else {
            pause(shared, UNPAIRED_PAUSE);
            continue;
        };
        let Some(phone) = reader.phone() else {
            // No usable pairing: the revocation backlog is the only remote
            // activity (section 4.6 item 6).
            reader.tell_forgotten_phones(&mut sightings);
            unpaired(shared, requests);
            viewed = None;
            continue;
        };
        // A usable pairing does not stop the revocation backlog: a
        // forgotten phone is still told when it appears, on its own
        // connection, without disturbing the active pairing (section 4.6
        // item 6).
        reader.tell_forgotten_phones(&mut sightings);
        let Some(slot) = slot_id(&phone) else {
            unpaired(shared, requests);
            viewed = None;
            continue;
        };
        if viewed != Some(phone.pair_id) {
            view = CustodianView::new();
            viewed = Some(phone.pair_id);
        }
        // The slot stands while the pairing does. Its token stands on the
        // certificate a session read, for the grace without a session: a
        // signature asked meanwhile wakes the dial and waits for the phone
        // within the browser's deadline (section 8.4 item 3). Before any
        // session the slot has no token, and a browser listing the slots
        // wakes the dial and waits for one.
        shared.serve_pairing(slot, phone.peer_display_name.clone());
        if !dial_due(shared, requests, reader, &phone, &mut view) {
            pause(shared, LOOK_PAUSE);
            continue;
        }
        match reader.dial_session(phone.pair_id, DIAL_BROWSE) {
            Ok(session) => {
                view.dial_succeeded();
                shared.in_session.store(true, Ordering::Release);
                let held = hold(
                    shared,
                    requests,
                    store,
                    reader,
                    session,
                    &phone,
                    slot,
                    &mut sightings,
                );
                shared.in_session.store(false, Ordering::Release);
                match held.after {
                    After::Grace => shared.token(|offering| offering.unconfirmed(Instant::now())),
                    After::Withdraw => shared.token(Offering::withdrawn),
                }
                match held.end {
                    Some(end) => view.session_ended(end, Instant::now()),
                    None => view.closed_here(),
                }
            }
            // Another program here holds the phone: a dial that ended
            // before `session.ready`, redialed within the window.
            Err(RemoteError::Busy) => {
                view.dial_failed(Instant::now());
                pause(shared, BUSY_PAUSE);
            }
            Err(error) => match error.session_end() {
                // The phone forgot this computer, stopped serving or can
                // serve no card: its presence goes at once (sections 4.5
                // item 6 and 4.6 item 4).
                Some(end @ (RequesterSessionEnd::Revoked | RequesterSessionEnd::Withdrawn)) => {
                    shared.token(Offering::withdrawn);
                    view.session_ended(end, Instant::now());
                }
                Some(RequesterSessionEnd::Violation) => {
                    view.session_ended(RequesterSessionEnd::Violation, Instant::now());
                }
                Some(RequesterSessionEnd::Loss) | None => view.dial_failed(Instant::now()),
            },
        }
    }
    shared.withdraw_slot();
}

/// One look for the phone, and whether a dial follows it (section 8.3): the
/// phone appeared, a redial within the window is due, or the browser asked
/// with no session open. A phone that withdrew takes the token at once,
/// and a request meanwhile is refused at once (section 4.5 item 6).
fn dial_due(
    shared: &Shared,
    requests: &Receiver<SignRequest>,
    reader: &RemoteReader,
    phone: &PairSummary,
    view: &mut CustodianView,
) -> bool {
    let appeared = match reader.look(phone.pair_id) {
        Ok(instances) => view.looked(instances),
        Err(RemoteError::Withdrawn) => {
            view.withdrawal_seen();
            shared.token(Offering::withdrawn);
            false
        }
        Err(_) => false,
    };
    let redial = view.redial_due(Instant::now());
    // A request that woke the pause has this dial; one that arrives during
    // the dial asks for the next.
    let wanted = shared.wanted.swap(false, Ordering::AcqRel);
    let asked = wanted && view.consumer_request() == ConsumerAnswer::Dial;
    if wanted && !asked {
        while let Ok(request) = requests.try_recv() {
            refuse(
                &request,
                RemoteSignError::Withdrawn,
                &phone.peer_display_name,
                None,
            );
        }
    }
    appeared || redial || asked
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
        refuse(
            &request,
            RemoteSignError::Withdrawn,
            UNKNOWN_PAIRING_LABEL,
            None,
        );
    }
    pause(shared, UNPAIRED_PAUSE);
}

/// Answers `request` with `error`, the module's failure for the browser,
/// naming the paired `peer` and the tier of the held session, if any.
fn refuse(request: &SignRequest, error: RemoteSignError, peer: &str, tier: Option<SessionTier>) {
    report_signature_failure(peer, tier, &error);
    let _ = request.reply.send(Err(error));
}

/// How a held session ended: what the token does, and how the session's
/// end is treated (section 4.5 item 6), `None` for a close this computer
/// sent for its own reasons.
struct Held {
    after: After,
    end: Option<RequesterSessionEnd>,
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
        // A read that failed, or a card that went or changed meanwhile:
        // the session stays, the grace runs,
        // and the next report the phone sends is followed.
        _ => None,
    }
}

/// Keeps `session` while the record stays usable and the phone in sight,
/// following the phone's card reports, answering the browser's requests
/// on it and serving it between them (sections 8.3 and 8.4).
#[allow(
    clippy::too_many_arguments,
    reason = "the held session carries its thread, channel, store, reader, session, phone, slot and backlog sightings"
)]
fn hold(
    shared: &Shared,
    requests: &Receiver<SignRequest>,
    store: &Path,
    reader: &mut RemoteReader,
    mut session: RemoteSession,
    phone: &PairSummary,
    slot: RemoteSlotId,
    sightings: &mut BacklogSightings,
) -> Held {
    let tier = Some(session.tier());
    let mut confirmed: Option<Confirmed> = None;
    // The card a confirmation was last tried for: a failed read is not
    // tried again until the phone reports a card anew.
    let mut tried: Option<CertificateFingerprint> = None;
    let mut record_checked = Instant::now();
    // The store as last signed here: empty at first, so the first check
    // reads the record once, and after that only a changed store does.
    let mut record_seen = StoreSignature::default();
    // The backlog last looked while this session stands: the round above
    // looked before the dial, so the first look here waits its turn.
    let mut backlog_checked = Instant::now();
    loop {
        if shared.stopped() {
            reader.withdraw_session(session);
            return Held {
                after: After::Grace,
                end: None,
            };
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
                    // reports (section 8.4 item 2): the certificate held in
                    // memory when it is that one, otherwise the card's,
                    // read once on this session.
                    let held = shared.standing_certificate(Instant::now());
                    match reader.confirmed_auth_cert(&mut session, held.as_deref()) {
                        Ok(certificate) => {
                            confirmed = Some(Confirmed {
                                fingerprint: CertificateFingerprint::of_certificate(&certificate),
                                certificate: certificate.clone(),
                            });
                            shared.token(|offering| offering.confirmed(certificate));
                        }
                        Err(error) => {
                            if let Some(after) = ended_by(&error) {
                                let end = session.end_treatment();
                                reader.close_session(session);
                                return Held { after, end };
                            }
                        }
                    }
                }
            }
        }
        match requests.recv_timeout(SERVICE_STEP) {
            // The browser gave up while the session was being opened;
            // the card is not asked for a signature nobody will read.
            Ok(request) if request.expired() => {
                refineid_dev_errors::report!(
                    Pkcs11,
                    "signature request dropped",
                    "the browser stopped waiting"
                );
            }
            // A request for another slot: no session of its own carried it.
            Ok(request) if request.pair_id != slot => {
                refuse(
                    &request,
                    RemoteSignError::Withdrawn,
                    &phone.peer_display_name,
                    None,
                );
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
                    refuse(&request, error, &phone.peer_display_name, tier);
                }
                Some(card) => {
                    let signed = sign(reader, &mut session, &request);
                    match checked(signed, &card.certificate, &request.request) {
                        Ok(signature) => {
                            let _ = request.reply.send(Ok(signature));
                        }
                        // A signature the confirmed certificate does not
                        // verify says the card on the phone is not the one
                        // read: the token goes with its certificate, and the
                        // next session reads the card again.
                        Err(Failure::Mismatch) => {
                            report_session_text(
                                "signature not handed on",
                                &phone.peer_display_name,
                                tier,
                                "it does not verify under the confirmed certificate",
                            );
                            refuse(
                                &request,
                                RemoteSignError::Ambiguous,
                                &phone.peer_display_name,
                                tier,
                            );
                            reader.close_session(session);
                            return Held {
                                after: After::Withdraw,
                                end: None,
                            };
                        }
                        // A check that cannot run says nothing of the
                        // card: the request is refused and the token kept.
                        Err(Failure::Refused) => {
                            let _ = request.reply.send(Err(RemoteSignError::Unsupported));
                        }
                        Err(Failure::Sign(error)) => {
                            refuse(&request, error, &phone.peer_display_name, tier);
                            match error {
                                // The phone stopped serving or forgot this
                                // computer: its presence goes at once.
                                RemoteSignError::Withdrawn => {
                                    let end = session.end_treatment();
                                    reader.close_session(session);
                                    return Held {
                                        after: After::Withdraw,
                                        end,
                                    };
                                }
                                RemoteSignError::Unreachable => {
                                    let end = session.end_treatment();
                                    reader.close_session(session);
                                    return Held {
                                        after: After::Grace,
                                        end,
                                    };
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
                return Held {
                    after: After::Grace,
                    end: None,
                };
            }
        }
        if record_checked.elapsed() >= RECORD_CHECK_INTERVAL {
            record_checked = Instant::now();
            let signature = StoreSignature::of(store);
            let changed = signature != record_seen;
            record_seen = signature;
            let record = if changed {
                held_record(store, phone.pair_id)
            } else {
                HeldRecord::Usable
            };
            match record {
                HeldRecord::Usable | HeldRecord::Unreadable => {}
                HeldRecord::Forgotten => {
                    reader.revoke_in_session(session);
                    return Held {
                        after: After::Withdraw,
                        end: Some(RequesterSessionEnd::Revoked),
                    };
                }
                HeldRecord::Gone => {
                    reader.close_session(session);
                    return Held {
                        after: After::Withdraw,
                        end: None,
                    };
                }
            }
        }
        // The revocation backlog runs while the active pairing's session
        // stands, on its own connection: a forgotten phone that appears is
        // told without disturbing this session (section 4.6 item 6).
        if backlog_checked.elapsed() >= BACKLOG_DURING_SESSION {
            backlog_checked = Instant::now();
            reader.tell_forgotten_phones(sightings);
        }
        match reader.service(&mut session, SERVICE_STEP) {
            Ok(()) => {}
            // The phone forgot this computer, stopped serving or can serve
            // no card: the token goes at once (sections 4.6 item 4 and 4.5
            // item 6).
            Err(RemoteError::RevokedByPhone | RemoteError::Withdrawn) => {
                return Held {
                    after: After::Withdraw,
                    end: session.end_treatment(),
                };
            }
            Err(_) => {
                return Held {
                    after: After::Grace,
                    end: session.end_treatment(),
                };
            }
        }
    }
}

/// What the record another program keeps says of the held pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeldRecord {
    /// The record still names the pairing as usable.
    Usable,
    /// This computer's user forgot the pairing, or a new pairing
    /// superseded it (RAPP v26.11.2 section 4.6 item 6): the phone is told
    /// on the held session.
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
    /// The phone answered with a signature the confirmed certificate does
    /// not verify: the card on the phone is not the one read.
    Mismatch,
    /// The phone answered with a signature the module cannot check
    /// under the confirmed certificate: the certificate does not decode,
    /// its key is not of the request's kind, or the digest is not the
    /// hash's length.
    Refused,
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
/// alone. A profile the module cannot check is reported unsupported, a
/// check that cannot run is refused, and both keep the token; a
/// signature that does not verify is a mismatch.
fn checked(
    signed: Result<Vec<u8>, RemoteSignError>,
    certificate: &[u8],
    request: &SignatureRequest,
) -> Result<Vec<u8>, Failure> {
    let signature = signed.map_err(Failure::Sign)?;
    let algorithm = message_algorithm(request.algorithm())
        .ok_or(Failure::Sign(RemoteSignError::Unsupported))?;
    let certificate = OwnedCert::from_der(certificate).map_err(|_| Failure::Refused)?;
    match certificate
        .view()
        .spki
        .verify_digest_signature(algorithm, request.digest(), &signature)
    {
        Ok(()) => Ok(signature),
        Err(DigestCheckError::Refused) => Err(Failure::Refused),
        Err(DigestCheckError::DoesNotVerify) => Err(Failure::Mismatch),
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
    use refineid_pkcs11::remote::REMOTE_WAKE_WAIT;
    use refineid_rapp::{
        DisplayName, EndpointRole, PAIR_ID_SIZE, PAIRING_IDLE_EXPIRY_MS, PairRecord, ProfileName,
        compute_grants_hash, generate_pair_key_material,
    };
    use refineid_rapp_core::engine::current_time_ms;
    use refineid_rapp_core::remote::CardRequest;
    use refineid_rapp_core::session_lock::{SessionLock, session_lock_path};
    use refineid_rapp_core::store::{PairingRecord, PairingStore as _};

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
    fn no_token_stands_until_a_session_confirms_the_card() {
        let start = Instant::now();
        let mut offering = Offering::new(the_slot(), "Alpha Phone".to_owned());
        assert_eq!(certificate_at(&offering, start), None);
        offering.confirmed(CERTIFICATE.to_vec());
        offering.unconfirmed(start);
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
        let mut offering = Offering::new(the_slot(), "Alpha Phone".to_owned());
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
        let mut offering = Offering::new(the_slot(), "Alpha Phone".to_owned());
        offering.confirmed(CERTIFICATE.to_vec());
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
            in_session: AtomicBool::new(false),
            context: DisplayText::new("alpha-desk".to_owned()).expect("short"),
            spoken: (Mutex::new(false), Condvar::new()),
            local_card: no_local_card,
        }
    }

    /// A computer whose readers hold no card.
    const fn no_local_card() -> bool {
        false
    }

    /// A computer with a card in one of its readers.
    const fn a_local_card() -> bool {
        true
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
        shared.serve_pairing(the_slot(), "Alpha Phone".to_owned());
        shared.token(|offering| offering.confirmed(CERTIFICATE.to_vec()));
        shared.token(|offering| offering.unconfirmed(start));
        let running = deadline(&shared);
        assert_eq!(running, Some(start + IDENTITY_OFFER_GRACE));
        // The next round of the thread serves the same pairing and dials
        // again: the deadline stays, and so does a session that ends again.
        shared.serve_pairing(the_slot(), "Alpha Phone".to_owned());
        shared.token(|offering| offering.unconfirmed(start + WITHIN_GRACE));
        assert_eq!(deadline(&shared), running);
        // A token withdrawn at once stays withdrawn over a new round.
        shared.token(Offering::withdrawn);
        shared.serve_pairing(the_slot(), "Alpha Phone".to_owned());
        let offered = shared.offer.lock().expect("offer");
        let offering = offered.as_ref().expect("the slot stands");
        assert_eq!(certificate_at(offering, start + WITHIN_GRACE), None);
    }

    #[test]
    fn absence_at_session_start_keeps_the_offer_for_the_grace_and_a_report_confirms_it() {
        let shared = shared();
        let start = Instant::now();
        let fingerprint = CertificateFingerprint::of_certificate(CERTIFICATE);
        shared.serve_pairing(the_slot(), "Alpha Phone".to_owned());
        // An earlier session confirmed the card and ended.
        shared.token(|offering| offering.confirmed(CERTIFICATE.to_vec()));
        shared.token(|offering| offering.unconfirmed(start));
        // The next session opens with the phone reporting no card: absence
        // is no other card, so the token stays on the grace it started
        // with, and the certificate held in memory is the one to confirm.
        assert_eq!(card_event(None, None), CardEvent::Absent);
        shared.token(|offering| offering.unconfirmed(start + WITHIN_GRACE));
        assert_eq!(deadline(&shared), Some(start + IDENTITY_OFFER_GRACE));
        assert!(!shared.offers_another_card(fingerprint));
        assert_eq!(
            shared.standing_certificate(start + WITHIN_GRACE),
            Some(CERTIFICATE.to_vec())
        );
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
            in_session: AtomicBool::new(false),
            context: DisplayText::new("alpha-desk".to_owned()).expect("short"),
            spoken: (Mutex::new(false), Condvar::new()),
            local_card: no_local_card,
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
        // A certificate that parses as nothing cannot check the
        // signature: the request is refused, never handed on, and the
        // refusal is no mismatch.
        assert_eq!(
            checked(Ok(vec![0; 96]), &[], &request),
            Err(Failure::Refused)
        );
        // The phone's own refusal passes through and keeps the token.
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
            in_session: AtomicBool::new(false),
            context: computer_context(),
            spoken: (Mutex::new(false), Condvar::new()),
            local_card: no_local_card,
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
    /// A store path no other test in this process uses: tests run in
    /// parallel and the clock can read the same instant for two of them.
    fn scratch_store() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "refineid-pkcs11-phone-{}-{nanos:x}-{serial}",
            std::process::id()
        ))
    }

    #[test]
    fn the_store_signature_changes_with_the_directory_and_its_entries() {
        let store = scratch_store();
        let absent = StoreSignature::of(&store);
        assert_eq!(absent, StoreSignature::default(), "no store, no signature");

        std::fs::create_dir_all(&store).expect("the store directory");
        let empty = StoreSignature::of(&store);
        assert_ne!(empty, absent);
        assert_eq!(
            empty,
            StoreSignature::of(&store),
            "nothing changed, same signature"
        );

        let record = store.join("record");
        std::fs::write(&record, b"one").expect("a record");
        let one = StoreSignature::of(&store);
        assert_ne!(one, empty, "an added record changes it");
        assert_eq!(one, StoreSignature::of(&store));

        std::fs::write(&record, b"longer").expect("the record rewritten");
        assert_ne!(
            StoreSignature::of(&store),
            one,
            "a rewritten record changes it"
        );

        std::fs::remove_dir_all(&store).expect("the store removed");
    }

    /// A confirmed pairing of [`PAIR_ID`] made at [`LONG_AGO_MS`] that has
    /// had no session.
    fn idle_pairing() -> PairingRecord {
        pairing_made_at(LONG_AGO_MS)
    }

    /// A confirmed pairing of [`PAIR_ID`] made at `created_at_ms` that has
    /// had no session.
    fn pairing_made_at(created_at_ms: u64) -> PairingRecord {
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
                    DisplayName::parse("Alpha Phone".to_owned()).expect("a valid name"),
                    created_at_ms,
                )
            })
            .expect("a valid record");
        PairingRecord::new(pairing, "iOS".to_owned()).expect("a requester record")
    }

    /// The state of [`PAIR_ID`] in `store`, once it reads as `state`, `None`
    /// for no record, or [`SWEEP_WAIT`] passed.
    fn state_within_wait(store: &Path, state: Option<PairingState>) -> Option<PairingState> {
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
            if read == state || Instant::now() >= deadline {
                return read;
            }
            thread::sleep(SWEEP_LOOK);
        }
    }

    /// A wait shorter than [`FIRST_WORD_WAIT`], which a reading must keep
    /// to however long the thread takes to speak.
    const SHORT_WAIT: Duration = Duration::from_millis(300);

    /// What the scheduler may add to a reading beyond its wait.
    const SCHEDULING_SLACK: Duration = Duration::from_millis(500);

    /// Before the phone connects the browser sees the phone's slot with no
    /// token, after a reading that waited no longer than it was granted for
    /// the dial; a reading that must not block answers at once. No
    /// certificate is on the computer.
    #[test]
    fn before_the_phone_connects_the_slot_has_no_token() {
        let (store, session) = a_paired_store_out_of_reach();
        let source = PhoneSource::over_store(store.clone(), no_local_card);
        let started = Instant::now();
        let offer = source.offered(REMOTE_WAKE_WAIT).expect("the phone's slot");
        assert!(started.elapsed() < REMOTE_WAKE_WAIT + SCHEDULING_SLACK);
        assert_eq!(Some(*offer.pair_id()), slot_id_of_pair());
        assert!(offer.certificate().is_none());
        let again = Instant::now();
        let offer = source.offered(Duration::ZERO).expect("the slot");
        assert!(offer.certificate().is_none());
        assert!(again.elapsed() < SCHEDULING_SLACK);
        source.stop();
        drop(session);
        std::fs::remove_dir_all(&store).expect("the test's store is removed");
    }

    /// A card in a reader of this computer suspends remote use: the
    /// browser sees no phone slot, within the wait the reading was granted.
    #[test]
    fn before_the_phone_connects_a_local_card_suspends_the_slot() {
        let (store, session) = a_paired_store_out_of_reach();
        let source = PhoneSource::over_store(store.clone(), a_local_card);
        let started = Instant::now();
        assert!(source.offered(REMOTE_WAKE_WAIT).is_none());
        assert!(started.elapsed() < REMOTE_WAKE_WAIT + SCHEDULING_SLACK);
        source.stop();
        drop(session);
        std::fs::remove_dir_all(&store).expect("the test's store is removed");
    }

    /// A store holding a fresh pairing, and the pairing's session lock,
    /// which held by the test keeps the thread's dial from reaching a
    /// phone.
    fn a_paired_store_out_of_reach() -> (PathBuf, SessionLock) {
        let store = scratch_store();
        FilePairingStore::open(&store)
            .expect("the test's store")
            .insert(pairing_made_at(current_time_ms()))
            .expect("the pairing is stored");
        let session = SessionLock::acquire(&session_lock_path(&store, PairId::from_array(PAIR_ID)))
            .expect("the pairing's session lock");
        (store, session)
    }

    /// The slot of [`PAIR_ID`].
    fn slot_id_of_pair() -> Option<RemoteSlotId> {
        let hex: String = PAIR_ID.iter().map(|byte| format!("{byte:02x}")).collect();
        RemoteSlotId::parse(&hex).ok()
    }

    /// A reading that must not block starts no thread and dials nothing,
    /// even with a pairing stored; the first reading that may wait starts
    /// the thread.
    #[test]
    fn a_reading_that_must_not_block_starts_nothing_and_dials_nothing() {
        let store = scratch_store();
        FilePairingStore::open(&store)
            .expect("the test's store")
            .insert(pairing_made_at(current_time_ms()))
            .expect("the pairing is stored");
        let session = SessionLock::acquire(&session_lock_path(&store, PairId::from_array(PAIR_ID)))
            .expect("the pairing's session lock");
        let source = PhoneSource::over_store(store.clone(), no_local_card);
        let started = Instant::now();
        assert!(source.offered(Duration::ZERO).is_none());
        assert!(started.elapsed() < SCHEDULING_SLACK);
        assert!(source.worker.lock().expect("worker").is_none());
        assert!(!source.shared.wanted());
        let _ = source.offered(REMOTE_WAKE_WAIT);
        assert!(source.worker.lock().expect("worker").is_some());
        source.stop();
        drop(session);
        std::fs::remove_dir_all(&store).expect("the test's store is removed");
    }

    /// A reading with a wait and no token asks the thread to dial and waits
    /// for the session to raise the token on the certificate it read.
    #[test]
    fn a_reading_wakes_the_dial_and_a_session_raises_the_token() {
        let shared = Arc::new(shared());
        shared.serve_pairing(the_slot(), "Alpha Phone".to_owned());
        let session = Arc::clone(&shared);
        let reader = thread::spawn(move || {
            while !session.wanted() {
                thread::sleep(SWEEP_LOOK);
            }
            session.token(|offering| offering.confirmed(CERTIFICATE.to_vec()));
        });
        let started = Instant::now();
        shared.wake_for_token(REMOTE_WAKE_WAIT);
        assert!(started.elapsed() < REMOTE_WAKE_WAIT);
        reader.join().expect("the session's thread");
        assert_eq!(
            shared.standing_certificate(Instant::now()),
            Some(CERTIFICATE.to_vec())
        );
    }

    /// A phone out of reach holds a reading to its wait and no longer, and
    /// the next reading may wait again: the module decides how often.
    #[test]
    fn an_unanswered_wake_ends_at_its_wait_and_keeps_no_rest_of_its_own() {
        let shared = shared();
        shared.serve_pairing(the_slot(), "Alpha Phone".to_owned());
        for _ in 0..2 {
            shared.wanted.store(false, Ordering::Release);
            let started = Instant::now();
            shared.wake_for_token(SHORT_WAIT);
            let took = started.elapsed();
            assert!(took >= SHORT_WAIT, "{took:?}");
            assert!(took < SHORT_WAIT + SCHEDULING_SLACK, "{took:?}");
            assert!(shared.wanted(), "the dial was asked for");
            assert!(shared.standing_certificate(Instant::now()).is_none());
        }
    }

    /// A reading while a session is held, or while the token stands, or
    /// with no wait, asks nothing of the phone and waits for nothing.
    #[test]
    fn a_held_session_a_standing_token_or_no_wait_needs_no_wake() {
        let shared = shared();
        shared.serve_pairing(the_slot(), "Alpha Phone".to_owned());
        let started = Instant::now();
        shared.wake_for_token(Duration::ZERO);
        assert!(!shared.wanted());
        shared.in_session.store(true, Ordering::Release);
        shared.wake_for_token(REMOTE_WAKE_WAIT);
        assert!(!shared.wanted());
        shared.in_session.store(false, Ordering::Release);
        shared.token(|offering| offering.confirmed(CERTIFICATE.to_vec()));
        shared.wake_for_token(REMOTE_WAKE_WAIT);
        assert!(!shared.wanted());
        assert!(started.elapsed() < SCHEDULING_SLACK);
    }

    /// A synthetic ordinary user's uid.
    const USER_UID: libc::uid_t = 1000;
    /// Another synthetic ordinary user's uid.
    const OTHER_UID: libc::uid_t = 1001;

    #[test]
    fn only_a_store_this_process_owns_or_may_create_is_served() {
        assert!(store_is_ours(StoreOwner::Uid(USER_UID), USER_UID));
        assert!(store_is_ours(StoreOwner::Uid(ROOT_UID), ROOT_UID));
        assert!(!store_is_ours(StoreOwner::Uid(USER_UID), ROOT_UID));
        assert!(!store_is_ours(StoreOwner::Uid(OTHER_UID), USER_UID));
        assert!(store_is_ours(StoreOwner::Missing, USER_UID));
        assert!(!store_is_ours(StoreOwner::Missing, ROOT_UID));
        assert!(!store_is_ours(StoreOwner::Unreadable, USER_UID));
        assert!(!store_is_ours(StoreOwner::Unreadable, ROOT_UID));
    }

    #[test]
    fn the_owner_of_a_store_reads_from_its_directory() {
        let store = scratch_store();
        assert_eq!(StoreOwner::of(&store), StoreOwner::Missing);
        std::fs::create_dir_all(&store).expect("the test's store");
        let owner = std::fs::metadata(&store).expect("metadata").uid();
        assert_eq!(StoreOwner::of(&store), StoreOwner::Uid(owner));
        std::fs::remove_dir_all(&store).expect("the test's store is removed");
    }

    /// Over a missing store the thread pauses without a word: the reading
    /// keeps to its wait, though it is shorter than [`FIRST_WORD_WAIT`].
    #[test]
    fn a_source_over_a_missing_store_offers_nothing_and_creates_nothing() {
        let store = scratch_store();
        let source = PhoneSource::over_store(store.clone(), no_local_card);
        let started = Instant::now();
        assert!(source.offered(SHORT_WAIT).is_none());
        assert!(started.elapsed() < SHORT_WAIT + SCHEDULING_SLACK);
        source.stop();
        assert!(!store.exists());
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
        let source = PhoneSource::over_store(store.clone(), no_local_card);
        let _ = source.offered(REMOTE_WAKE_WAIT);
        assert!(source.worker.lock().expect("worker").is_some());
        // The thread swept the test's store at its start: the pairing idle
        // past the limit expired there, its record gone with its key.
        assert_eq!(state_within_wait(&store, None), None);
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
        let _ = source.offered(REMOTE_WAKE_WAIT);
        assert!(source.worker.lock().expect("worker").is_some());
        source.stop();
        drop(session);
        std::fs::remove_dir_all(&store).expect("the test's store is removed");
    }
}
