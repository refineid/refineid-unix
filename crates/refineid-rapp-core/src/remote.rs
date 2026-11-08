//! The workstation's remote card reader: pairing by code and sessions to
//! the paired phone, over the stream tier.
//!
//! This is the surface the CLI, the GUI, the TLS client, and the PKCS#11
//! module use. Pairing browses for custodians in `mode=pairing` and tries
//! the typed code with each one found, in turn (RAPP v26.11.2 section
//! 4.2, "Trying Each Custodian in Pairing Mode"). A session browses for
//! custodians in `mode=session`, dials each, and opens with a routing
//! value that is fresh per dial and keyed by the pairing's static
//! agreement. A custodian that does not hold the pairing closes the
//! connection, and the next one is tried. A withdrawn record announcing the
//! pairing, or a session close carrying `service_withdrawn` or
//! `card_unavailable`, ends the search at once; the withdrawn instance is
//! never dialed, and the pairing is dialed again only when a session
//! record on another instance names it.
//!
//! The phone's word on the pairing comes only inside a session: a close
//! carrying `pairing_revoked` revokes the pairing here at once (RAPP
//! v26.11.2 section 4.6 item 4). A pairing forgotten here is told to the
//! phone the same way: by the session that holds it, or on the next
//! session with the phone, whose first message is the close (items 1, 2
//! and 6). The record keeps its static key for the close alone, serves
//! nothing else, and waits in the revocation backlog: each time the phone
//! appears for the pairing one connection opens for it, and the key and
//! the record go only on the phone's echo, or untold once the pairing's
//! idle expiry would have passed (item 3).
//!
//! An open session reports which card the phone holds, if any (section
//! 8.4); an operation is sent only on a session that reports one, and the
//! phone's identity is offered only on a certificate whose fingerprint the
//! phone confirmed on a session. The certificate is read from the phone
//! and handed to the caller, which holds it in memory; nothing here
//! stores it.
//!
//! A reader that follows a [`Withdrawal`] stops when it is raised (section
//! 4.5 item 8): its open session closes with `service_withdrawn`, a dial
//! not yet open closes without a notice, nothing more is dialed, and every
//! pairing stays.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::addresses;

use crate::engine::{
    AdmissionError, OperationOutcome, PairingCandidateSource, PairingConnection,
    PairingSearchError, Requester, RequesterConfig, Session, SessionEnd, SessionError, Withdrawal,
    current_time_ms,
};
use crate::file_store::{FilePairingStore, read_record};
use crate::ids::{CertificateFingerprint, PairId};
use crate::message::{CardPresence, CardReader, CardStatusMessage, CloseReason};
use crate::operations::{CardOperation, CardOperationResult, CertificateKind};
use crate::session_lock::{LockError, SessionLock, ceremony_lock_path, session_lock_path};
use crate::store::{PairingRecord, PairingStore, StoreError};
use crate::stream::{
    DiscoveryMode, HintMatch, RoutingPreamble, STREAM_CANDIDATE_ID, StreamError, StreamService,
    browse, browse_stream_services, dial,
};
use crate::transport::FrameTransport;
use crate::transport::TcpFrameTransport;
use refineid_rapp::{
    DISPLAY_NAME_MAX_BYTES, DiscoveryKey, DisplayName, PairingState, ProfileName,
    QUIT_WITHDRAWAL_BOUND_MS, RequesterSessionEnd, RoutingKey, TransportProfile, WithdrawalKey,
};

/// How long one discovery round listens for answers.
const BROWSE_ROUND: Duration = Duration::from_secs(2);
/// How long a completed round must have missed a forgotten pairing before
/// its next listing is an appearance (section 4.6 item 6): a missed round
/// bridges a phone that briefly drops out, while a phone that stays listed
/// is never dialed again. The Apple and Android Requesters hold their
/// sightings for the same thirty seconds.
const BACKLOG_LOSS_HOLD: Duration = Duration::from_secs(30);
/// How long a command-line search waits for the paired phone to come
/// into sight and open a session: long enough for a phone that is
/// asleep in the holder's pocket when the search starts.
///
/// This host finds the phone over the local network only (mDNS and
/// DNS-SD, hierarchy specification section 3.2); it has no BLE
/// transport. The terms, longest first:
///
/// - The holder picks the phone up, unlocks it and brings the RefineID
///   app forward to serve. This is human time no specification
///   bounds; about 20 seconds is an estimate, not a measurement.
/// - A phone whose Wi-Fi dozed reassociates and takes its address
///   again: a few seconds when it was disconnected; while it stays
///   associated in power save, multicast waits only for the next DTIM
///   beacon, a fraction of a second.
/// - The phone registers its service: a random wait of up to 250 ms
///   and three probes 250 ms apart before it may answer (RFC 6762
///   section 8.1), about one second.
/// - The record is seen at the next query: queries go out every
///   `BROWSE_ROUND`, to the group and to the phone's remembered
///   address, so at most one round, two seconds.
///
/// The sum is about 25 seconds; 30 leaves margin. For comparison on
/// the transport this host lacks: Apple's accessory guidelines have a
/// BLE peripheral advertise every 20 ms for its first 30 seconds, and
/// Android's slowest advertising mode is about one advertisement a
/// second, so a waking phone found over BLE is in sight well within the
/// same bound. The dial and handshake that follow have their own
/// deadlines (`SESSION_RECEIVE_DEADLINE`).
pub const PHONE_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
/// How long pairing waits for each custodian message; the holder may be
/// reading the screen. `CPace` step 2 has the shorter attempt deadline.
const PAIRING_RECEIVE_DEADLINE: Duration = Duration::from_secs(60);
/// How long a session handshake waits for each custodian message.
const SESSION_RECEIVE_DEADLINE: Duration = Duration::from_secs(30);
/// How long a new session waits for the phone's first card report, which
/// it sends right after `session.ready` (section 8.4 item 1), when the
/// discovery time is spent.
const CARD_REPORT_WAIT: Duration = Duration::from_secs(5);
/// The lifetime each request asks for unless the caller bounds it
/// (section 8.1 item 2).
const OPERATION_LIFETIME: Duration = Duration::from_millis(300_000);
/// The transport label a failed session names: this host reaches the
/// phone over the local network stream tier only.
#[cfg(debug_assertions)]
pub(crate) const SESSION_TRANSPORT_LABEL: &str = "network";
/// The peer a failed session names when its pair record cannot be read.
pub(crate) const UNKNOWN_PAIRING_LABEL: &str = "unknown pairing";

/// A failed session's cause with its peer and transport: `case` is the
/// error's case name or a fixed text, `peer` the pair record's
/// `peer_display_name` (a device label, never a holder name).
#[cfg(debug_assertions)]
#[must_use]
pub(crate) fn session_failure_message(case: &str, peer: &str) -> String {
    format!("{case}, {peer}, {SESSION_TRANSPORT_LABEL}")
}

/// The peer a failed session names: the pair record's display name, or
/// [`UNKNOWN_PAIRING_LABEL`] when the record cannot be read. In a release
/// build this names nothing without reading the store.
#[cfg(debug_assertions)]
#[must_use]
pub(crate) fn pairing_peer_label(store: &impl PairingStore, pair_id: PairId) -> String {
    store
        .get(pair_id)
        .map(|record| record.peer_display_name().as_str().to_owned())
        .unwrap_or_else(|_| UNKNOWN_PAIRING_LABEL.to_owned())
}

/// The peer a failed session names: in a release build nothing is read and
/// [`UNKNOWN_PAIRING_LABEL`] is named without a store lookup.
#[cfg(not(debug_assertions))]
#[must_use]
pub(crate) fn pairing_peer_label(store: &impl PairingStore, pair_id: PairId) -> String {
    let _ = (store, pair_id);
    UNKNOWN_PAIRING_LABEL.to_owned()
}

/// Reports a failed session naming its peer and transport; in a release
/// build this borrows its inputs and writes nothing.
#[cfg(debug_assertions)]
fn report_session_error(event: &'static str, peer: &str, error: &impl core::fmt::Debug) {
    let case = refineid_dev_errors::Cause::case(error);
    let message = session_failure_message(case.as_str(), peer);
    refineid_dev_errors::report!(Rapp, event, name message.as_str());
}

/// Reports a failed session naming its peer and transport; in a release
/// build this borrows its inputs and writes nothing.
#[cfg(not(debug_assertions))]
fn report_session_error(event: &'static str, peer: &str, error: &impl core::fmt::Debug) {
    let _ = (event, peer, error);
}

/// Reports a failed session with a fixed text cause, naming its peer and
/// transport; in a release build this borrows its inputs and writes
/// nothing.
#[cfg(debug_assertions)]
fn report_session_text(event: &'static str, peer: &str, text: &'static str) {
    let message = session_failure_message(text, peer);
    refineid_dev_errors::report!(Rapp, event, name message.as_str());
}

/// Reports a failed session with a fixed text cause, naming its peer and
/// transport; in a release build this borrows its inputs and writes
/// nothing.
#[cfg(not(debug_assertions))]
fn report_session_text(event: &'static str, peer: &str, text: &'static str) {
    let _ = (event, peer, text);
}

/// What a new session waits for before it is handed over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CardWait {
    /// A card the phone can serve, within the discovery time.
    Present,
    /// The phone's first card report, present or absent.
    Report,
}

/// The keys one stored pairing uses to find and reach its custodian.
struct PairingKeys {
    discovery: DiscoveryKey,
    routing: RoutingKey,
    withdrawal: WithdrawalKey,
}

impl PairingKeys {
    /// The keys of a pairing that may dial: a usable one, or a forgotten
    /// one that still owes the phone its close.
    fn derive(record: &PairingRecord) -> Result<Self, RemoteError> {
        if !matches!(
            record.state(),
            PairingState::PairedDisconnected | PairingState::Revoking
        ) {
            return Err(RemoteError::NotPaired);
        }
        let pairing = record.pairing();
        Ok(Self {
            discovery: DiscoveryKey::derive(pairing).map_err(|_| RemoteError::NotPaired)?,
            routing: RoutingKey::derive(pairing).map_err(|_| RemoteError::NotPaired)?,
            withdrawal: WithdrawalKey::derive(pairing).map_err(|_| RemoteError::NotPaired)?,
        })
    }

    /// A session preamble with a fresh routing value.
    fn session_preamble(&self) -> Result<RoutingPreamble, RemoteError> {
        self.routing
            .route(TransportProfile::Stream, |nonce| {
                getrandom::fill(nonce).map_err(|_| refineid_rapp::RandomUnavailable)
            })
            .map(RoutingPreamble::Session)
            .map_err(|_| RemoteError::RandomUnavailable)
    }
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The custodians in pairing mode on the local network, browsed round by
/// round until `deadline`: the endpoints a typed code is tried with, each
/// known by its service instance and dialed at the addresses it last
/// answered from.
struct PairingServices {
    found: Vec<StreamService>,
    deadline: Instant,
}

impl PairingServices {
    /// The record last seen for `instance`.
    fn service(&self, instance: &str) -> Option<&StreamService> {
        self.found
            .iter()
            .find(|service| service.instance == instance)
    }
}

impl PairingCandidateSource for PairingServices {
    type Endpoint = String;
    type Transport = TcpFrameTransport;

    fn discover(&mut self) -> Option<Vec<String>> {
        if Instant::now() >= self.deadline {
            return None;
        }
        let services = browse(DiscoveryMode::Pairing, BROWSE_ROUND);
        let instances = services
            .iter()
            .map(|service| service.instance.clone())
            .collect();
        for service in services {
            self.found
                .retain(|known| known.instance != service.instance);
            self.found.push(service);
        }
        Some(instances)
    }

    fn open(&mut self, instance: &String) -> Option<PairingConnection<TcpFrameTransport>> {
        let service = self.service(instance)?;
        let transport = dial(
            &service.endpoints,
            STREAM_CANDIDATE_ID,
            PAIRING_RECEIVE_DEADLINE,
            &RoutingPreamble::Pairing,
        )
        .ok()?;
        PairingConnection::read(transport).ok()
    }
}

/// The session custodians worth dialing for the pairing keyed by `keys`,
/// best first: those whose rotating hint names the pairing, then those
/// publishing no hints. A custodian whose hints all name other pairings is
/// never dialed, and neither is an instance that announced its withdrawal
/// for the pairing.
///
/// # Errors
/// [`RemoteError::Withdrawn`] when a custodian announced its withdrawal
/// for the pairing and no session record on another instance names it.
fn sessions_for(
    keys: &PairingKeys,
    services: &[StreamService],
) -> Result<Vec<StreamService>, RemoteError> {
    let now = unix_seconds();
    let withdrawn: Vec<String> = services
        .iter()
        .filter(|service| service.withdraws(&keys.withdrawal, now))
        .map(|service| service.instance.clone())
        .collect();
    let (mut named, mut unhinted) = (Vec::new(), Vec::new());
    for service in services {
        if !service.advertises(DiscoveryMode::Session) || withdrawn.contains(&service.instance) {
            continue;
        }
        match service.hint_match(&keys.discovery, now) {
            HintMatch::Named => named.push(service.clone()),
            HintMatch::Unhinted => unhinted.push(service.clone()),
            HintMatch::Other => {}
        }
    }
    if !withdrawn.is_empty() && named.is_empty() {
        return Err(RemoteError::Withdrawn);
    }
    named.extend(unhinted);
    Ok(named)
}

/// The answer of one operation whose session, if it ended, reported itself
/// as `ended`. A delivered result stands; any other ending of a session
/// the phone withdrew or revoked reports that.
fn operation_result(
    outcome: Result<OperationOutcome, AdmissionError>,
    ended: Option<RemoteError>,
) -> Result<CardOperationResult, RemoteError> {
    match (outcome, ended) {
        (Ok(OperationOutcome::Completed(result)), _) => Ok(result),
        (_, Some(ended)) => Err(ended),
        (Ok(other), None) => Err(RemoteError::Outcome(Box::new(other))),
        (Err(error), None) => Err(RemoteError::Admission(error)),
    }
}

/// How a session that ended with `end` reports itself: a withdrawal or a
/// revocation the phone announced, or nothing particular.
const fn ended_by(end: Option<SessionEnd>) -> Option<RemoteError> {
    match end {
        Some(SessionEnd::PeerClose(reason)) => peer_close_error(reason),
        _ => None,
    }
}

/// The phone's close `reason` as the reader reports it by name: its
/// withdrawal, which `card_unavailable` is to this computer too (section
/// 4.5 item 6), and its revocation.
const fn peer_close_error(reason: CloseReason) -> Option<RemoteError> {
    match RequesterSessionEnd::of_received_close(Some(reason)) {
        RequesterSessionEnd::Withdrawn => Some(RemoteError::Withdrawn),
        RequesterSessionEnd::Revoked => Some(RemoteError::RevokedByPhone),
        RequesterSessionEnd::Violation | RequesterSessionEnd::Loss => None,
    }
}

/// Whether the phone's close `reason` ends a dial at once: every reason
/// but a loss's, so a withdrawal, a revocation and a protocol violation
/// are not redialed (section 4.5 item 6).
const fn ends_the_dial(reason: CloseReason) -> bool {
    !matches!(
        RequesterSessionEnd::of_received_close(Some(reason)),
        RequesterSessionEnd::Loss
    )
}

/// A session error as the reader reports it: the phone's withdrawal and
/// its revocation by name, anything else as it came.
fn session_error(error: SessionError) -> RemoteError {
    match error {
        SessionError::ClosedByPeer(reason) => {
            peer_close_error(reason).unwrap_or(RemoteError::Session(error))
        }
        other => RemoteError::Session(other),
    }
}

/// Runs one operation on an open session of any transport, asking the
/// phone to let it expire `lifetime` after the request (section 8.1 item
/// 2); the runner behind [`RemoteReader::execute_on_with_lifetime`].
///
/// # Errors
/// [`RemoteError`] when the phone reports no card, the operation cannot
/// be admitted, or it ends without a result.
pub fn execute_on_session<Store, Transport>(
    requester: &mut Requester<Store>,
    session: &mut Session<Transport>,
    operation: &CardOperation,
    lifetime: Duration,
) -> Result<CardOperationResult, RemoteError>
where
    Store: PairingStore,
    Transport: FrameTransport,
{
    if session.card_present() != Some(true) {
        return Err(RemoteError::CardAbsent(CardRequest::of(
            session.card_status(),
        )));
    }
    let outcome = requester.execute(session, operation, lifetime_ms(lifetime));
    operation_result(outcome, ended_by(session.end()))
}

/// Where the user is asked to give the phone its card (RAPP v26.11.2
/// section 8.4 item 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardRequest {
    /// Into the phone's card reader: the phone's latest `card.status`
    /// reports the card absent and a reader attached.
    InPhoneReader,
    /// To the phone itself, in every other case.
    ToPhone,
}

impl CardRequest {
    /// The request the latest `card.status` on an open session calls for;
    /// a session whose phone has reported nothing asks at the phone.
    #[must_use]
    pub const fn of(status: Option<CardStatusMessage>) -> Self {
        match status {
            Some(CardStatusMessage {
                card: CardPresence::Absent,
                reader: CardReader::Attached,
            }) => Self::InPhoneReader,
            _ => Self::ToPhone,
        }
    }
}

/// Why a remote reader call ended without its answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteError {
    /// The pairing store could not be read or written.
    Store(StoreError),
    /// No stored pairing matches.
    NotPaired,
    /// No custodian advertised a session for the pairing before the
    /// deadline.
    NotFound,
    /// The phone announced that it stopped serving the pairing, or that it
    /// can serve no card (section 4.5 item 6).
    Withdrawn,
    /// The phone told this computer that it forgot it; the pairing is
    /// revoked here and the user pairs again.
    RevokedByPhone,
    /// The phone opened the session but reports no card it can serve;
    /// where the user is asked to give it the card.
    CardAbsent(CardRequest),
    /// The certificate read from the card is not the one the phone
    /// reports serving: the card changed during the read.
    CardChanged,
    /// The system random source failed.
    RandomUnavailable,
    /// The typed code paired with no phone.
    Pairing(PairingSearchError),
    /// No custodian opened a session for the pairing, or the session
    /// ended.
    Session(SessionError),
    /// The operation could not be admitted.
    Admission(AdmissionError),
    /// The operation ended without a result.
    Outcome(Box<OperationOutcome>),
    /// Another program on this computer holds the phone session, or is
    /// pairing.
    Busy,
}

impl core::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "pairing store: {error:?}"),
            Self::NotPaired => f.write_str("no paired phone"),
            Self::NotFound => f.write_str("no phone found on the local network"),
            Self::Withdrawn => f.write_str("no remote card is available"),
            Self::RevokedByPhone => f.write_str("the phone forgot this computer; pair it again"),
            Self::CardAbsent(CardRequest::InPhoneReader) => {
                f.write_str("the phone has no card; insert the card into the phone's card reader")
            }
            Self::CardAbsent(CardRequest::ToPhone) => {
                f.write_str("the phone has no card; present the card to the phone")
            }
            Self::CardChanged => f.write_str("the card on the phone changed; try again"),
            Self::RandomUnavailable => f.write_str("the system random source failed"),
            Self::Pairing(error) => write!(f, "pairing: {error}"),
            Self::Session(error) => write!(f, "session: {error}"),
            Self::Admission(error) => write!(f, "operation: {error}"),
            Self::Outcome(outcome) if **outcome == OperationOutcome::Refused => {
                f.write_str("the phone's message was not understood")
            }
            Self::Outcome(outcome) => write!(f, "operation ended: {outcome:?}"),
            Self::Busy => {
                f.write_str("the phone session is held by another program on this computer")
            }
        }
    }
}

impl core::error::Error for RemoteError {}

impl RemoteError {
    /// How this computer treats the end of the session this error ended
    /// (section 4.5 item 6, "How a session ends"); `None` for an error
    /// that ended no session of the phone's.
    #[must_use]
    pub const fn session_end(&self) -> Option<RequesterSessionEnd> {
        match self {
            Self::RevokedByPhone => Some(RequesterSessionEnd::Revoked),
            Self::Withdrawn => Some(RequesterSessionEnd::Withdrawn),
            Self::Session(SessionError::Violation) => Some(RequesterSessionEnd::Violation),
            Self::Session(SessionError::ClosedByPeer(reason)) => {
                Some(RequesterSessionEnd::of_received_close(Some(*reason)))
            }
            Self::Session(SessionError::Transport(_)) => Some(RequesterSessionEnd::Loss),
            _ => None,
        }
    }
}

/// What a stored pairing shows to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairSummary {
    /// The pair identifier.
    pub pair_id: PairId,
    /// The name the phone last sent for itself.
    pub peer_display_name: String,
    /// The phone's platform label.
    pub peer_platform: String,
    /// The granted credential profiles.
    pub granted_profiles: Vec<ProfileName>,
    /// Where the stored pairing stands: awaiting the phone's storage
    /// confirmation (section 4.3 item 4), usable, or forgotten here with
    /// the phone yet to be told (section 4.6 item 2).
    pub state: PairingState,
}

impl PairSummary {
    /// Whether the pairing can open a session for the user.
    #[must_use]
    pub fn usable(&self) -> bool {
        self.state == PairingState::PairedDisconnected
    }

    /// The pair identifier as lowercase hex.
    #[must_use]
    pub fn pair_id_hex(&self) -> String {
        self.pair_id
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// The route a revocation-backlog appearance arrived on (section 4.6 item
/// 6): one connection per appearance, by the route that appeared, never
/// both in one appearance. This host finds the phone over the local
/// network only; the Bluetooth route is named for the rule it obeys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum BacklogRoute {
    /// An mDNS `mode=session` record carrying the pairing's discovery
    /// hint, or naming no hints.
    Stream,
}

/// In-sight memory for the revocation backlog (section 4.6 item 6): one
/// sighting per forgotten pairing and route, with when a completed round
/// last missed it. A listing is an appearance only when the pairing was
/// never sighted on that route, or when it was missed by a completed
/// round and the loss hold below has passed since the miss. Time between
/// rounds without a completed round that missed it is never absence, so a
/// phone that stays listed is dialed once, however far apart the rounds
/// run, and never again until a round misses it and it reappears. An mDNS
/// record that is lost or removed ends the sighting at once, as leaving
/// the backlog does (the pairing's echo or idle expiry destroyed the
/// record); nothing is ever purged by elapsed time. The memory lives as
/// long as the owning process; a restart treats the first sighting as an
/// appearance.
#[derive(Debug, Default)]
pub struct BacklogSightings {
    sightings: HashMap<(PairId, BacklogRoute), Sighting>,
}

/// What one completed round last said of a forgotten pairing on a route:
/// in sight, or missed since `absent_since`.
#[derive(Debug)]
struct Sighting {
    absent_since: Option<Instant>,
}

impl BacklogSightings {
    /// Notes that a completed round listed `pair_id` on `route` at `now`:
    /// whether the listing is an appearance. A listing clears the absence
    /// a missed round noted; a pairing never sighted on the route appears
    /// at its first listing.
    fn appearance(&mut self, pair_id: PairId, route: BacklogRoute, now: Instant) -> bool {
        match self.sightings.get_mut(&(pair_id, route)) {
            None => {
                self.sightings
                    .insert((pair_id, route), Sighting { absent_since: None });
                true
            }
            Some(sighting) => {
                let appeared = sighting.absent_since.is_some_and(|absent| {
                    now.saturating_duration_since(absent) >= BACKLOG_LOSS_HOLD
                });
                sighting.absent_since = None;
                appeared
            }
        }
    }

    /// Notes that a completed round did not list `pair_id` on `route` at
    /// `now`: absence starts then, unless an earlier missed round already
    /// started it. A pairing never sighted stays unknown: its first
    /// listing is still an appearance.
    fn missed(&mut self, pair_id: PairId, route: BacklogRoute, now: Instant) {
        if let Some(sighting) = self.sightings.get_mut(&(pair_id, route))
            && sighting.absent_since.is_none()
        {
            sighting.absent_since = Some(now);
        }
    }

    /// Ends the sighting of `pair_id`, as an mDNS record's loss or removal
    /// does and as leaving the backlog does: the pairing's echo or idle
    /// expiry destroyed the record, so its next listing is an appearance.
    fn drop_pairing(&mut self, pair_id: PairId) {
        self.sightings.retain(|key, _| key.0 != pair_id);
    }

    /// Drops the sightings of pairings no longer in the backlog, as a lost
    /// or removed record ends them: only `forgotten` still owes a notice.
    fn drop_left_backlog(&mut self, forgotten: &[PairId]) {
        self.sightings.retain(|key, _| forgotten.contains(&key.0));
    }
}

/// The workstation's remote reader over its durable pairing store.
#[derive(Debug)]
pub struct RemoteReader {
    requester: Requester<FilePairingStore>,
    /// Opens the session a backlog appearance dials. Tests replace it to
    /// count dial attempts without a network.
    dial: fn(&[String], &str, Duration, &RoutingPreamble) -> Result<TcpFrameTransport, StreamError>,
}

/// One open session to a phone that reported a card it can serve; the
/// pairing's lock is held with it.
#[derive(Debug)]
pub struct RemoteSession {
    session: Session<TcpFrameTransport>,
    _lock: SessionLock,
}

/// Takes `path`, naming the holder of a held lock.
fn take_lock(path: &std::path::Path) -> Result<SessionLock, RemoteError> {
    SessionLock::acquire(path).map_err(|error| match error {
        LockError::Held => RemoteError::Busy,
        LockError::Unavailable => RemoteError::Store(StoreError::WriteRefused),
    })
}

/// A lifetime as the wire's milliseconds.
fn lifetime_ms(lifetime: Duration) -> u64 {
    u64::try_from(lifetime.as_millis()).unwrap_or(u64::MAX)
}

impl RemoteSession {
    /// Whether the phone reports a card it can serve on this session.
    #[must_use]
    pub fn card_present(&self) -> bool {
        self.session.card_present() == Some(true)
    }

    /// The fingerprint of the authentication certificate of the card the
    /// phone reports serving (section 8.4 item 2); `None` while it reports
    /// none.
    #[must_use]
    pub const fn card_fingerprint(&self) -> Option<CertificateFingerprint> {
        match self.session.card_status() {
            Some(CardStatusMessage {
                card: CardPresence::Present(fingerprint),
                ..
            }) => Some(fingerprint),
            Some(CardStatusMessage {
                card: CardPresence::Absent,
                ..
            })
            | None => None,
        }
    }

    /// Where the user is asked to give the phone its card, by the phone's
    /// latest report on this session (section 8.4 item 6).
    #[must_use]
    pub const fn card_request(&self) -> CardRequest {
        CardRequest::of(self.session.card_status())
    }

    /// The pairing this session serves.
    #[must_use]
    pub const fn pair_id(&self) -> PairId {
        self.session.pair_id()
    }

    /// How this computer treats the session's end (section 4.5 item 6),
    /// once it ended other than by this computer's own close.
    #[must_use]
    pub fn end_treatment(&self) -> Option<RequesterSessionEnd> {
        self.session.end().and_then(SessionEnd::treatment)
    }
}

/// The platform label this workstation introduces itself with: the
/// operating system's own name (section 4.3 item 3).
#[must_use]
pub const fn local_platform() -> &'static str {
    match std::env::consts::OS.as_bytes() {
        b"linux" => "Linux",
        b"freebsd" => "FreeBSD",
        b"openbsd" => "OpenBSD",
        b"netbsd" => "NetBSD",
        b"macos" => "macOS",
        _ => "Unix",
    }
}

/// This computer's host name without its domain, as the phone lists it:
/// the node name the `uname` system call reports, or `RefineID` when the
/// system has no name of its own. Read once per process: the PKCS#11
/// module runs this inside browsers and PAM, so it spawns no program and
/// does not ask again on its session thread's every round.
#[must_use]
pub fn local_host_name() -> String {
    static HOST_NAME: OnceLock<String> = OnceLock::new();
    HOST_NAME.get_or_init(read_host_name).clone()
}

/// The short host name from `uname`, or `RefineID` for an unset one.
fn read_host_name() -> String {
    let system = rustix::system::uname();
    let printed = system.nodename().to_string_lossy();
    let short = printed.trim().split('.').next().unwrap_or("").trim();
    if short.is_empty()
        || UNSET_HOST_NAMES
            .iter()
            .any(|unset| unset.eq_ignore_ascii_case(short))
    {
        "RefineID".to_owned()
    } else {
        short.to_owned()
    }
}

/// The names a system reports before it has been given one.
const UNSET_HOST_NAMES: [&str; 2] = ["localhost", "(none)"];

/// What joins the operating system's name to the host name in this
/// computer's display name (section 4.3 item 3).
const DISPLAY_NAME_SEPARATOR: &str = " - ";

/// The name this computer gives itself to the phone, `<operating system> -
/// <host name>` (section 4.3 item 3): `Linux - example-host`.
#[must_use]
pub fn local_display_name() -> DisplayName {
    display_name_of(local_platform(), &local_host_name())
}

/// `platform` and `host` joined as a display name, the host name shortened
/// at a character boundary until the whole fits
/// [`DISPLAY_NAME_MAX_BYTES`].
fn display_name_of(platform: &str, host: &str) -> DisplayName {
    let mut name = format!("{platform}{DISPLAY_NAME_SEPARATOR}{host}");
    while name.len() > DISPLAY_NAME_MAX_BYTES {
        name.pop();
    }
    // The platform is never blank, so the name never is.
    DisplayName::parse(name).unwrap_or_else(|_| unreachable!("a platform name is never blank"))
}

impl RemoteReader {
    /// Opens the per-user pairing store, introducing this workstation by
    /// its host name and platform.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the store cannot be opened.
    pub fn open_local() -> Result<Self, RemoteError> {
        Self::open(local_display_name(), local_platform())
    }

    /// Opens the store in `directory` as this computer without sweeping
    /// it, for a program that reads the records another program keeps. A
    /// record an earlier build stored with a certificate is still
    /// rewritten without it.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the store cannot be opened.
    pub fn open_local_without_sweep(directory: &std::path::Path) -> Result<Self, RemoteError> {
        let store = FilePairingStore::open_without_sweep(directory)
            .map_err(RemoteError::Store)
            .inspect_err(|error| {
                refineid_dev_errors::report!(Rapp, "pairing store not opened", error)
            })?;
        Ok(Self::with_store(
            local_display_name(),
            local_platform(),
            store,
        ))
    }

    /// Opens the per-user pairing store.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the store cannot be opened.
    pub fn open(display_name: DisplayName, platform: &str) -> Result<Self, RemoteError> {
        let store = FilePairingStore::open_default()
            .map_err(RemoteError::Store)
            .inspect_err(|error| {
                refineid_dev_errors::report!(Rapp, "pairing store not opened", error)
            })?;
        let mut reader = Self::with_store(display_name, platform, store);
        reader.sweep();
        Ok(reader)
    }

    /// Uses `store` for pairings, as it stands.
    #[must_use]
    pub fn with_store(display_name: DisplayName, platform: &str, store: FilePairingStore) -> Self {
        Self {
            requester: Requester::new(
                RequesterConfig {
                    display_name,
                    platform: platform.to_owned(),
                },
                store,
            ),
            dial,
        }
    }

    /// Follows `withdrawal`, this computer's withdrawal from remote use
    /// (section 4.5 item 8), for the program that holds the phone's
    /// session.
    #[must_use]
    pub fn following(mut self, withdrawal: Withdrawal) -> Self {
        self.requester.follow(withdrawal);
        self
    }

    /// Dials only while this computer has not withdrawn (section 4.5 item
    /// 8).
    fn may_dial(&self) -> Result<(), RemoteError> {
        if self.requester.withdrawn() {
            Err(RemoteError::Session(SessionError::WithdrawnHere))
        } else {
            Ok(())
        }
    }

    /// The owning program's sweep of the store: pairings without a session
    /// for the idle limit expire and lose their keys (section 4.6 items 5
    /// and 6), forgotten records whose idle expiry would have passed lose
    /// theirs untold (item 3), and,
    /// while no pairing ceremony runs on this computer, records a past
    /// ceremony left unconfirmed are revoked (section 4.3 item 4). A
    /// running ceremony's record is unconfirmed until its phone answers. A
    /// change the store refused is made by the next open.
    fn sweep(&mut self) {
        let _ = self.expire_idle_pairings();
        self.requester.expire_revocation_notices(current_time_ms());
        if let Ok(_ceremony) = take_lock(&ceremony_lock_path(self.requester.store().directory())) {
            self.requester.revoke_unconfirmed_pairings();
        }
    }

    /// Sweeps every stored pairing for idle expiry now (section 4.6 item
    /// 5): a pairing that had no session for
    /// [`refineid_rapp::PAIRING_IDLE_EXPIRY_DAYS`] days expires silently,
    /// and its key and record go at once (item 6). Returns how many
    /// expired.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the store refused a pairing's change;
    /// that pairing stays as it was for the next sweep.
    pub fn expire_idle_pairings(&mut self) -> Result<usize, RemoteError> {
        self.requester
            .expire_idle_pairings(current_time_ms())
            .map_err(RemoteError::Store)
            .inspect_err(|error| {
                refineid_dev_errors::report!(Rapp, "idle pairings not expired", error)
            })
    }

    /// Every stored pairing, newest first.
    #[must_use]
    pub fn pairs(&self) -> Vec<PairSummary> {
        let store = self.requester.store();
        store
            .pair_ids()
            .into_iter()
            .filter_map(|pair_id| store.get(pair_id).ok())
            .map(|record| PairSummary {
                pair_id: record.pair_id(),
                peer_display_name: record.peer_display_name().as_str().to_owned(),
                peer_platform: record.peer_platform().to_owned(),
                granted_profiles: record.pairing().profiles().to_vec(),
                state: record.state(),
            })
            .collect()
    }

    /// The paired phone: the one pairing that can open a session. A new
    /// pairing supersedes the one before it, so there is at most one.
    #[must_use]
    pub fn phone(&self) -> Option<PairSummary> {
        self.pairs().into_iter().find(PairSummary::usable)
    }

    /// Forgets the paired phone at its user's word (section 4.6 item 6):
    /// the pairing serves nothing from now on and joins the revocation
    /// backlog, keeping its key for the `pairing_revoked` close alone. The
    /// phone is told when it appears for the pairing; the key and the
    /// record go on its echo, or untold at the pairing's idle expiry. A
    /// pairing whose session another program here holds is told by that
    /// program. Returns whether the phone echoed the close.
    ///
    /// # Errors
    /// [`RemoteError::NotPaired`] when no phone is paired, and
    /// [`RemoteError::Store`] when the record cannot be rewritten.
    pub fn forget(&mut self) -> Result<bool, RemoteError> {
        let pair_id = self.phone().ok_or(RemoteError::NotPaired)?.pair_id;
        self.forget_and_tell(pair_id)
    }

    /// Forgets the pairing `pair_id` now at its user's word and tells the
    /// phone when it appears for the pairing, as [`Self::forget`] does for
    /// the paired phone; for a caller that must forget the pairing it saw,
    /// not whichever is paired by the time it runs.
    ///
    /// # Errors
    /// As [`Self::forget`].
    pub fn forget_and_tell(&mut self, pair_id: PairId) -> Result<bool, RemoteError> {
        self.requester
            .forget(pair_id, current_time_ms())
            .map_err(RemoteError::Store)
            .inspect_err(|error| {
                refineid_dev_errors::report!(Rapp, "pairing not forgotten", error);
            })?;
        // The forget itself is an appearance for the backlog: the phone in
        // sight now is told at once, from this process's first sighting.
        let services = self.browse_for(pair_id);
        Ok(self.tell_forgotten_phone(
            pair_id,
            &services,
            &mut BacklogSightings::default(),
            Instant::now(),
        ))
    }

    /// Tells the phone of every forgotten pairing when it appears for it
    /// (section 4.6 item 6): one connection per pairing, by the route that
    /// appeared, the close as its first message, at most the quit bound of
    /// waiting for each echo. Only an appearance dials: a phone never
    /// sighted for the pairing, or listed again after a completed round
    /// missed it and the loss hold passed since the miss. A phone that
    /// stays listed is never dialed again, however far apart the rounds
    /// run: time between rounds without a completed round that missed it
    /// is never absence. A pairing told, or with no phone in sight, or
    /// whose session another program holds, stays in the backlog for the
    /// next appearance or its idle expiry. It runs whether or not this
    /// computer withdrew or the phone announced its withdrawal, offers no
    /// identity and starts no operation, and runs alongside the active
    /// pairing's discovery while remote use is on. Returns how many phones
    /// echoed the close.
    pub fn tell_forgotten_phones(&mut self, sightings: &mut BacklogSightings) -> usize {
        let mut forgotten: Vec<PairId> = self
            .pairs()
            .into_iter()
            .filter(|pair| pair.state == PairingState::Revoking)
            .map(|pair| pair.pair_id)
            .collect();
        // Whatever the store read before says, the disk decides: a pairing
        // gone or no longer forgotten owes nothing, and one whose notice
        // expired is revoked untold (item 3) and dials nothing. A pairing
        // that left the backlog drops its sightings, as a lost or removed
        // mDNS record ends them; what stays forgotten keeps its sightings
        // across backlog changes, so a phone that stays in sight is not
        // dialed again when another pairing is forgotten.
        forgotten.retain(|pair_id| {
            if self.owed_notice(*pair_id).is_some() {
                return true;
            }
            sightings.drop_pairing(*pair_id);
            false
        });
        if forgotten.is_empty() {
            return 0;
        }
        // Sightings of pairings a sweep destroyed meanwhile end too.
        sightings.drop_left_backlog(&forgotten);
        // One browse round for the whole backlog: every forgotten pairing
        // reads the same round, and each appearance dials once.
        let services = self.browse_for_backlog(&forgotten);
        let now = Instant::now();
        forgotten
            .into_iter()
            .filter(|pair_id| self.tell_forgotten_phone(*pair_id, &services, sightings, now))
            .count()
    }

    /// The disk-fresh record of the forgotten `pair_id` when it still owes
    /// its notice (section 4.6 items 3 and 6): `None` when the pairing is
    /// gone or no longer forgotten, which owe nothing. A record whose
    /// notice expired is revoked untold here, and none of these dials.
    fn owed_notice(&mut self, pair_id: PairId) -> Option<PairingRecord> {
        let directory = self.requester.store().directory().to_path_buf();
        let record = read_record(&directory, pair_id)?;
        if record.state() != PairingState::Revoking {
            return None;
        }
        if record
            .pairing()
            .revocation_notice_expired(current_time_ms())
        {
            let _ = self.requester.store_mut().remove(pair_id);
            return None;
        }
        Some(record)
    }

    /// The one connection that tells the phone holding the forgotten
    /// `pair_id` that this computer forgot it (section 4.6 item 6), when
    /// the phone appears for the pairing: one session to the first service
    /// in sight carries the `pairing_revoked` close as its first message,
    /// by the route that appeared, and the echo is awaited at most the quit
    /// bound. The key and the record go only on the echo; without one, or
    /// with no phone in sight, they stay in the backlog until the next
    /// appearance or the pairing's idle expiry (item 3). A pairing whose
    /// session another program on this computer holds is left to that
    /// program, which tells the phone in session. Returns whether the phone
    /// echoed the close.
    fn tell_forgotten_phone(
        &mut self,
        pair_id: PairId,
        services: &[StreamService],
        sightings: &mut BacklogSightings,
        now: Instant,
    ) -> bool {
        // Right before the dial the record is read again as the disk holds
        // it: a pairing gone meanwhile sends nothing, and one whose idle
        // expiry passed meanwhile is revoked untold.
        let Some(record) = self.owed_notice(pair_id) else {
            sightings.drop_pairing(pair_id);
            return false;
        };
        let Ok(keys) = PairingKeys::derive(&record) else {
            return false;
        };
        // A pairing whose session another program on this computer holds is
        // left to that program, which tells the phone in session: a round
        // that cannot dial notes neither sight nor absence.
        let Ok(_lock) = take_lock(&session_lock_path(
            self.requester.store().directory(),
            pair_id,
        )) else {
            return false;
        };
        let found = sessions_for(&keys, services)
            .ok()
            .and_then(|matched| matched.into_iter().next());
        let Some(service) = found else {
            // The completed round did not list the pairing: absence starts
            // now, unless an earlier miss already started it.
            sightings.missed(pair_id, BacklogRoute::Stream, now);
            return false;
        };
        // The round listed the pairing, by the stream route: only an
        // appearance dials, never a phone that stays listed.
        if !sightings.appearance(pair_id, BacklogRoute::Stream, now) {
            return false;
        }
        let peer = record.peer_display_name().as_str().to_owned();
        let told = self.deliver_to_appearance(pair_id, &peer, &keys, &service, current_time_ms());
        // The echo destroys the record; an expiry the dial found destroys
        // it untold. Either ends the sighting.
        let stays = self
            .requester
            .store()
            .get(pair_id)
            .is_ok_and(|record| record.state() == PairingState::Revoking);
        if told || !stays {
            sightings.drop_pairing(pair_id);
        }
        told
    }

    /// One browse round for the revocation backlog: the service instances
    /// in sight, asking the remembered addresses of every forgotten
    /// pairing as well as the network.
    fn browse_for_backlog(&self, forgotten: &[PairId]) -> Vec<StreamService> {
        let directory = self.requester.store().directory();
        let mut remembered: Vec<Ipv4Addr> = Vec::new();
        for pair_id in forgotten {
            for address in addresses::remembered(directory, *pair_id) {
                if !remembered.contains(&address) {
                    remembered.push(address);
                }
            }
        }
        browse_stream_services(BROWSE_ROUND, &remembered)
    }

    /// Opens one session to the appeared `service` for the forgotten
    /// `pair_id` and delivers the close on it; whether the phone echoed
    /// it. Without the echo the record stays in the backlog.
    fn deliver_to_appearance(
        &mut self,
        pair_id: PairId,
        peer: &str,
        keys: &PairingKeys,
        service: &StreamService,
        now_ms: u64,
    ) -> bool {
        let wait = Duration::from_millis(QUIT_WITHDRAWAL_BOUND_MS);
        let Ok(preamble) = keys.session_preamble() else {
            return false;
        };
        let dial = self.dial;
        let Ok(transport) = dial(&service.endpoints, STREAM_CANDIDATE_ID, wait, &preamble) else {
            report_session_text("revocation close not delivered", peer, "no session");
            return false;
        };
        match self.requester.send_revocation_notice(
            pair_id,
            transport,
            Instant::now() + wait,
            now_ms,
        ) {
            Ok(true) => true,
            Ok(false) => {
                report_session_text("revocation close not acknowledged", peer, "no echo");
                false
            }
            Err(error) => {
                report_session_error("revocation close not delivered", peer, &error);
                false
            }
        }
    }

    /// Forgets every usable pairing but `kept`, telling each phone when it
    /// appears, so one phone is paired (section 4.6 item 6).
    fn supersede_others(&mut self, kept: PairId) {
        let older: Vec<PairId> = self
            .pairs()
            .into_iter()
            .filter(|pair| pair.usable() && pair.pair_id != kept)
            .map(|pair| pair.pair_id)
            .collect();
        for pair_id in older {
            let _ = self.forget_and_tell(pair_id);
        }
    }

    /// Pairs with the phone showing `code`, trying each phone in pairing
    /// mode found until `discovery_timeout` passes with none tried (RAPP
    /// v26.11.2 section 4.2, "Trying Each Custodian in Pairing Mode").
    ///
    /// Every profile the offer names is requested and granted; the phone
    /// decides what it grants and the sets must agree.
    ///
    /// One ceremony runs at a time on this computer: the store's pairing
    /// lock is held until this returns.
    ///
    /// # Errors
    /// [`RemoteError::Pairing`] for input that is not a code, a search that
    /// found no phone in pairing mode, a code every phone tried refused,
    /// and a ceremony that failed with the phone holding the code;
    /// [`RemoteError::Busy`] when another program is pairing, and
    /// [`RemoteError::Store`] when the record of a completed ceremony
    /// cannot be written.
    pub fn pair_with_code(
        &mut self,
        code: &str,
        discovery_timeout: Duration,
    ) -> Result<PairSummary, RemoteError> {
        self.pair_with_code_unreported(code, discovery_timeout)
            .inspect_err(|error| refineid_dev_errors::report!(Rapp, "pairing failed", error))
    }

    /// [`Self::pair_with_code`], before its failure is reported.
    fn pair_with_code_unreported(
        &mut self,
        code: &str,
        discovery_timeout: Duration,
    ) -> Result<PairSummary, RemoteError> {
        if crate::offer::normalize_pairing_code(code).is_none() {
            return Err(RemoteError::Pairing(PairingSearchError::InvalidCode));
        }
        let _ceremony = take_lock(&ceremony_lock_path(self.requester.store().directory()))?;
        let mut services = PairingServices {
            found: Vec::new(),
            deadline: Instant::now() + discovery_timeout,
        };
        let (pair_id, _) = self
            .requester
            .pair_with_code(code, &mut services, |_, requested| Some(requested.to_vec()))
            .map_err(RemoteError::Pairing)?;
        self.supersede_others(pair_id);
        self.pairs()
            .into_iter()
            .find(|pair| pair.pair_id == pair_id)
            .ok_or(RemoteError::NotPaired)
    }

    /// Listens once for the phone holding `pair_id` without dialing it.
    /// Returns the service instances in sight whose session records may
    /// serve the pairing (section 8.3, "in sight").
    ///
    /// # Errors
    /// [`RemoteError::NotPaired`] when no usable record names `pair_id`,
    /// and [`RemoteError::Withdrawn`] when the phone announced its
    /// withdrawal for the pairing (section 4.5 item 6).
    pub fn look(&self, pair_id: PairId) -> Result<Vec<String>, RemoteError> {
        let record = self
            .requester
            .store()
            .get(pair_id)
            .map_err(|_| RemoteError::NotPaired)?;
        let keys = PairingKeys::derive(record)?;
        sessions_for(&keys, &self.browse_for(pair_id)).map(|services| {
            services
                .into_iter()
                .map(|service| service.instance)
                .collect()
        })
    }

    /// One browse round for `pair_id`, asking the phone's remembered
    /// addresses directly as well as the network.
    fn browse_for(&self, pair_id: PairId) -> Vec<StreamService> {
        let remembered = addresses::remembered(self.requester.store().directory(), pair_id);
        browse_stream_services(BROWSE_ROUND, &remembered)
    }

    /// Remembers where the phone holding `pair_id` answered from, for the
    /// next browse. Only an address of a private or link-local network is
    /// kept: a remembered address is asked again on whatever network the
    /// computer joins next, and a query must not leave that network.
    fn remember_address(&self, pair_id: PairId, service: &StreamService) {
        let Some(address) = service
            .endpoints
            .iter()
            .filter_map(|endpoint| endpoint.parse::<SocketAddrV4>().ok())
            .find(|address| address.ip().is_private() || address.ip().is_link_local())
        else {
            return;
        };
        addresses::remember(self.requester.store().directory(), pair_id, *address.ip());
    }

    /// Opens a session to the phone holding `pair_id`, or the selected
    /// pairing when `None`, browsing until `discovery_timeout` passes, and
    /// waits for the phone's word on its card (section 8.4). A phone that
    /// first reports no card is given the rest of `discovery_timeout` to
    /// report one, so a card tapped after the dial still serves.
    ///
    /// The pairing's lock is held from here until the session is dropped,
    /// so one program at a time on this computer holds the phone.
    ///
    /// # Errors
    /// [`RemoteError`] when no pairing matches, another program holds the
    /// pairing's session, no phone opens a session for it, the phone
    /// forgot this computer, no card is reported before the timeout, or
    /// this computer withdrew, which ends the search at its next round.
    pub fn open_session(
        &mut self,
        pair_id: Option<PairId>,
        discovery_timeout: Duration,
    ) -> Result<RemoteSession, RemoteError> {
        self.establish(pair_id, discovery_timeout, CardWait::Present)
    }

    /// Opens a session to the phone holding `pair_id`, browsing until
    /// `discovery_timeout` passes, and returns it once the phone has
    /// reported its card, present or absent (section 8.4 item 1): for a
    /// holder that keeps the session open while the phone is in sight and
    /// follows its card reports (section 8.3).
    ///
    /// # Errors
    /// As [`Self::open_session`], and [`RemoteError::CardAbsent`] when the
    /// phone reports nothing of its card.
    pub fn dial_session(
        &mut self,
        pair_id: PairId,
        discovery_timeout: Duration,
    ) -> Result<RemoteSession, RemoteError> {
        self.establish(Some(pair_id), discovery_timeout, CardWait::Report)
    }

    /// Browses, dials and connects to the phone holding `pair_id`, or the
    /// selected pairing when `None`, and waits for its card as `wait` says.
    fn establish(
        &mut self,
        pair_id: Option<PairId>,
        discovery_timeout: Duration,
        wait: CardWait,
    ) -> Result<RemoteSession, RemoteError> {
        #[cfg(debug_assertions)]
        let peer = pair_id.map_or_else(
            || {
                self.phone()
                    .map(|phone| phone.peer_display_name)
                    .unwrap_or_else(|| UNKNOWN_PAIRING_LABEL.to_owned())
            },
            |pair_id| pairing_peer_label(self.requester.store(), pair_id),
        );
        #[cfg(not(debug_assertions))]
        let peer = UNKNOWN_PAIRING_LABEL.to_owned();
        self.establish_unreported(pair_id, discovery_timeout, wait)
            .inspect_err(|error| {
                report_session_error("phone session not opened", &peer, error);
            })
    }

    /// [`Self::establish`], before its failure is reported.
    fn establish_unreported(
        &mut self,
        pair_id: Option<PairId>,
        discovery_timeout: Duration,
        wait: CardWait,
    ) -> Result<RemoteSession, RemoteError> {
        self.may_dial()?;
        let pair_id = match pair_id {
            Some(pair_id) => pair_id,
            None => self.phone().ok_or(RemoteError::NotPaired)?.pair_id,
        };
        let record = self
            .requester
            .store()
            .get(pair_id)
            .map_err(|_| RemoteError::NotPaired)?;
        if record.state() != PairingState::PairedDisconnected {
            return Err(RemoteError::NotPaired);
        }
        let peer = record.peer_display_name().as_str().to_owned();
        let keys = PairingKeys::derive(record)?;
        let lock = take_lock(&session_lock_path(
            self.requester.store().directory(),
            pair_id,
        ))?;
        let deadline = Instant::now() + discovery_timeout;
        let mut last = RemoteError::NotFound;
        // One round at least, so a dial given no time to browse further
        // tries the phones in sight once.
        let mut first_round = true;
        while first_round || Instant::now() < deadline {
            first_round = false;
            self.may_dial()?;
            for service in sessions_for(&keys, &self.browse_for(pair_id))? {
                self.may_dial()?;
                let Ok(transport) = dial(
                    &service.endpoints,
                    STREAM_CANDIDATE_ID,
                    SESSION_RECEIVE_DEADLINE,
                    &keys.session_preamble()?,
                ) else {
                    continue;
                };
                let mut session = match self.requester.connect(pair_id, transport) {
                    Ok(session) => {
                        self.remember_address(pair_id, &service);
                        session
                    }
                    // The phone's word ends the dial (section 4.5 item 6), as
                    // does its authenticated violation, which opens no redial.
                    Err(error @ SessionError::Violation) => {
                        return Err(RemoteError::Session(error));
                    }
                    Err(error @ SessionError::ClosedByPeer(reason)) if ends_the_dial(reason) => {
                        return Err(session_error(error));
                    }
                    Err(error) => {
                        report_session_error("phone session attempt failed", &peer, &error);
                        last = RemoteError::Session(error);
                        continue;
                    }
                };
                let reported = match wait {
                    CardWait::Present => self.requester.await_card_present(
                        &mut session,
                        deadline
                            .saturating_duration_since(Instant::now())
                            .max(CARD_REPORT_WAIT),
                    ),
                    CardWait::Report => self
                        .requester
                        .await_card_report(&mut session, CARD_REPORT_WAIT),
                };
                match reported {
                    Ok(true) => {
                        return Ok(RemoteSession {
                            session,
                            _lock: lock,
                        });
                    }
                    Ok(false) => {
                        let request = CardRequest::of(session.card_status());
                        self.requester.disconnect(&mut session, CloseReason::Normal);
                        return Err(RemoteError::CardAbsent(request));
                    }
                    Err(error @ SessionError::Violation) => {
                        return Err(RemoteError::Session(error));
                    }
                    Err(error @ SessionError::ClosedByPeer(reason)) if ends_the_dial(reason) => {
                        return Err(session_error(error));
                    }
                    Err(error) => {
                        report_session_error("phone card report not received", &peer, &error);
                        last = RemoteError::Session(error);
                    }
                }
            }
        }
        Err(last)
    }

    /// Runs one operation on an open session with the default lifetime.
    ///
    /// # Errors
    /// As [`Self::execute_on_with_lifetime`].
    pub fn execute_on(
        &mut self,
        session: &mut RemoteSession,
        operation: &CardOperation,
    ) -> Result<CardOperationResult, RemoteError> {
        self.execute_on_with_lifetime(session, operation, OPERATION_LIFETIME)
    }

    /// Runs one operation on an open session, asking the phone to let it
    /// expire `lifetime` after the request (section 8.1 item 2).
    ///
    /// # Errors
    /// [`RemoteError`] when the phone reports no card, the operation cannot
    /// be admitted, or it ends without a result.
    pub fn execute_on_with_lifetime(
        &mut self,
        session: &mut RemoteSession,
        operation: &CardOperation,
        lifetime: Duration,
    ) -> Result<CardOperationResult, RemoteError> {
        let peer = pairing_peer_label(self.requester.store(), session.pair_id());
        execute_on_session(
            &mut self.requester,
            &mut session.session,
            operation,
            lifetime,
        )
        .inspect_err(|error| {
            report_session_error("card operation failed", &peer, error);
        })
    }

    /// Serves an open session for `wait`: answers the phone's pings,
    /// records its card reports, and keeps the liveness rule of section
    /// 8.3.
    ///
    /// # Errors
    /// [`RemoteError::Withdrawn`] or [`RemoteError::RevokedByPhone`] when
    /// the phone closed the session with that reason, and
    /// [`RemoteError::Session`] when the session ended otherwise, this
    /// computer's withdrawal included.
    pub fn service(
        &mut self,
        session: &mut RemoteSession,
        wait: Duration,
    ) -> Result<(), RemoteError> {
        let peer = pairing_peer_label(self.requester.store(), session.pair_id());
        self.requester
            .service(&mut session.session, wait)
            .map_err(session_error)
            .inspect_err(|error| {
                report_session_error("phone session ended", &peer, error);
            })
    }

    /// Closes a session deliberately; an already ended session is left
    /// as it ended.
    pub fn close_session(&mut self, mut session: RemoteSession) {
        self.requester
            .disconnect(&mut session.session, CloseReason::Complete);
    }

    /// Closes `session` as this computer's withdrawal from remote use
    /// (section 4.5 item 8): `session.close` with `service_withdrawn`,
    /// whose echo is awaited at most the quit bound (section 7.1 item 7).
    /// The pairing stays; an already ended session is left as it ended.
    pub fn withdraw_session(&mut self, mut session: RemoteSession) {
        self.requester
            .disconnect(&mut session.session, CloseReason::ServiceWithdrawn);
    }

    /// Closes `session` telling the phone that this computer forgot the
    /// pairing (section 4.6 item 1), for the session holder that finds the
    /// record forgotten by another program on this computer; the pairing's
    /// key and record go only on the echo, and stay in the revocation
    /// backlog otherwise (item 3).
    pub fn revoke_in_session(&mut self, mut session: RemoteSession) {
        self.requester.revoke_in_session(&mut session.session);
    }

    /// Runs one operation against the phone holding `pair_id`, or the
    /// selected pairing when `None`, browsing until `discovery_timeout`
    /// passes, on a session opened and closed for it.
    ///
    /// # Errors
    /// [`RemoteError`] when no pairing matches, no phone opens a session for
    /// it, the phone reports no card, or the operation ends without a
    /// result.
    pub fn execute(
        &mut self,
        pair_id: Option<PairId>,
        operation: &CardOperation,
        discovery_timeout: Duration,
    ) -> Result<CardOperationResult, RemoteError> {
        let mut session = self.open_session(pair_id, discovery_timeout)?;
        let result = self.execute_on(&mut session, operation);
        self.close_session(session);
        result
    }

    /// Reads the authentication certificate through the phone, on a session
    /// opened and closed for it, for the caller to hold in memory.
    ///
    /// # Errors
    /// As [`Self::confirmed_auth_cert`], and as [`Self::open_session`].
    pub fn refresh_auth_cert(
        &mut self,
        pair_id: PairId,
        discovery_timeout: Duration,
    ) -> Result<Vec<u8>, RemoteError> {
        let mut session = self.open_session(Some(pair_id), discovery_timeout)?;
        let result = self.confirmed_auth_cert(&mut session, None);
        self.close_session(session);
        result
    }

    /// The authentication certificate of the card the phone reports
    /// serving on `session` (section 8.4 item 2): `held`, the certificate
    /// the caller holds in memory, when its fingerprint is the reported
    /// one, and otherwise the card's, read afresh on the session and
    /// checked against the report. Nothing is stored.
    ///
    /// # Errors
    /// [`RemoteError::CardAbsent`] while the phone reports no card,
    /// [`RemoteError::CardChanged`] when the certificate read is not the
    /// one reported, and as [`Self::execute_on`] for the read.
    pub fn confirmed_auth_cert(
        &mut self,
        session: &mut RemoteSession,
        held: Option<&[u8]>,
    ) -> Result<Vec<u8>, RemoteError> {
        let peer = pairing_peer_label(self.requester.store(), session.pair_id());
        self.confirmed_auth_cert_unreported(session, held)
            .inspect_err(|error| {
                report_session_error("certificate not confirmed", &peer, error);
            })
    }

    /// [`Self::confirmed_auth_cert`], before its failure is reported.
    fn confirmed_auth_cert_unreported(
        &mut self,
        session: &mut RemoteSession,
        held: Option<&[u8]>,
    ) -> Result<Vec<u8>, RemoteError> {
        let reported = session
            .card_fingerprint()
            .ok_or_else(|| RemoteError::CardAbsent(session.card_request()))?;
        if let Some(held) = held
            && CertificateFingerprint::of_certificate(held) == reported
        {
            return Ok(held.to_vec());
        }
        let operation = CardOperation::ReadCertificate {
            kind: CertificateKind::Authentication,
        };
        let CardOperationResult::Certificate(der) = self.execute_on(session, &operation)? else {
            return Err(RemoteError::Outcome(Box::new(OperationOutcome::Refused)));
        };
        if session.card_fingerprint() != Some(CertificateFingerprint::of_certificate(&der)) {
            return Err(RemoteError::CardChanged);
        }
        Ok(der)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use refineid_rapp::{
        AnnouncementCandidate, DiscoveryKey, InstanceName, PairId, PairingState, ResultError,
        RoutingKey, WithdrawalKey, WithdrawnRecord, X25519_KEY_SIZE, discovery_epoch,
        withdrawal_counter,
    };

    use std::time::{Duration, Instant};

    use super::{
        AdmissionError, BACKLOG_LOSS_HOLD, BROWSE_ROUND, BacklogRoute, BacklogSightings,
        CardOperationResult, CardPresence, CardReader, CardRequest, CardStatusMessage,
        CertificateFingerprint, OperationOutcome, PairingKeys, PairingSearchError, RemoteError,
        RemoteReader, RoutingPreamble, SESSION_TRANSPORT_LABEL, SessionError, StreamError,
        StreamService, TcpFrameTransport, UNKNOWN_PAIRING_LABEL, Withdrawal, current_time_ms,
        lifetime_ms, operation_result, pairing_peer_label, session_failure_message, sessions_for,
        unix_seconds,
    };
    use crate::file_store::{FilePairingStore, path_for};
    use crate::session_lock::{SessionLock, ceremony_lock_path, session_lock_path};
    use crate::store::PairingStore as _;
    use crate::store::fixtures::{CREATED_AT_MS, PHONE_NAME, record};

    /// The pairing every reader holds.
    const PAIR_ID: [u8; refineid_rapp::PAIR_ID_SIZE] = *b"synthetic-pair-1";
    /// A pairing no reader holds.
    const UNKNOWN_PAIR_ID: [u8; refineid_rapp::PAIR_ID_SIZE] = *b"synthetic-pair-9";
    /// Synthetic static keys for the discovery tests.
    const PEER_PUBLIC: [u8; X25519_KEY_SIZE] = *b"synthetic custodian public key 1";
    const MINE: [u8; X25519_KEY_SIZE] = *b"synthetic requester static key 1";
    const THEIRS: [u8; X25519_KEY_SIZE] = *b"synthetic requester static key 2";
    /// A synthetic authentication certificate.
    const CERTIFICATE: &[u8] = b"synthetic authentication certificate";
    /// A code in the pairing alphabet (section 3.1).
    const CODE: &str = "7KX4M9";
    /// How long a reader that lost the lock race searches.
    const SEARCH: Duration = Duration::from_secs(1);
    /// The pause between looks at a lock another thread releases.
    const LOCK_STEP: Duration = Duration::from_millis(5);
    /// How many looks a released lock is given to settle.
    const LOCK_LOOKS: usize = 10;
    /// A lifetime of whole seconds, and the milliseconds it is sent as.
    const WHOLE_SECONDS: u64 = 90;
    const WHOLE_SECONDS_MS: u64 = 90_000;
    /// A lifetime of a millisecond and a half, sent as one millisecond.
    const SUB_MILLISECOND_MICROS: u64 = 1_500;
    const SUB_MILLISECOND_MS: u64 = 1;

    #[test]
    fn the_phones_reader_is_named_only_for_an_absent_card_beside_an_attached_reader() {
        let present = CardPresence::Present(CertificateFingerprint::of_certificate(CERTIFICATE));
        for (card, reader, request) in [
            (
                CardPresence::Absent,
                CardReader::Attached,
                CardRequest::InPhoneReader,
            ),
            (
                CardPresence::Absent,
                CardReader::Absent,
                CardRequest::ToPhone,
            ),
            (present, CardReader::Attached, CardRequest::ToPhone),
            (present, CardReader::Absent, CardRequest::ToPhone),
        ] {
            assert_eq!(
                CardRequest::of(Some(CardStatusMessage { card, reader })),
                request
            );
        }
        assert_eq!(CardRequest::of(None), CardRequest::ToPhone);
    }

    #[test]
    fn an_absent_card_is_asked_for_where_the_phone_can_take_it() {
        assert_eq!(
            RemoteError::CardAbsent(CardRequest::InPhoneReader).to_string(),
            "the phone has no card; insert the card into the phone's card reader"
        );
        assert_eq!(
            RemoteError::CardAbsent(CardRequest::ToPhone).to_string(),
            "the phone has no card; present the card to the phone"
        );
    }

    fn scratch() -> std::path::PathBuf {
        let suffix = getrandom::u64().unwrap();
        std::env::temp_dir().join(format!("refineid-rapp-remote-{suffix:x}"))
    }

    /// A reader over a store in `directory` holding `records`.
    fn reader_with(
        directory: &std::path::Path,
        records: Vec<crate::store::PairingRecord>,
    ) -> RemoteReader {
        let mut store = FilePairingStore::open(directory).unwrap();
        for record in records {
            store.insert(record).unwrap();
        }
        RemoteReader::with_store(desk(), "Linux", store)
    }

    /// The synthetic name of this computer.
    fn desk() -> refineid_rapp::DisplayName {
        super::display_name_of("Linux", "alpha-desk")
    }

    /// A reader over a store in `directory` holding one paired record.
    fn reader_with_pairing(directory: &std::path::Path) -> RemoteReader {
        reader_with(directory, vec![record(PairId::from_array(PAIR_ID))])
    }

    #[test]
    fn looking_listens_without_the_lock_and_names_an_unknown_pairing() {
        let directory = scratch();
        let reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        let held = SessionLock::acquire(&session_lock_path(&directory, pair_id)).unwrap();
        // Listening takes no lock: with the session held elsewhere and no
        // phone announcing this pairing on the test network, none in sight.
        assert_eq!(reader.look(pair_id), Ok(Vec::new()));
        drop(held);
        assert_eq!(reader.look(pair_id), Ok(Vec::new()));
        assert_eq!(
            reader.look(PairId::from_array(UNKNOWN_PAIR_ID)).err(),
            Some(RemoteError::NotPaired)
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_forgotten_phone_serves_nothing_and_waits_in_the_backlog() {
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        note_session(&mut reader, pair_id);
        reader.requester.forget(pair_id, current_time_ms()).unwrap();
        assert_eq!(reader.phone(), None);
        assert_eq!(reader.forget(), Err(RemoteError::NotPaired));
        let summary = reader.pairs().into_iter().next().unwrap();
        assert_eq!(summary.state, PairingState::Revoking);
        assert!(!summary.usable());
        assert_eq!(
            reader.open_session(Some(pair_id), Duration::ZERO).err(),
            Some(RemoteError::NotPaired)
        );
        // Nothing in sight: nothing is dialed and the record stays, key
        // and all, for the next appearance or its idle expiry.
        let mut sightings = BacklogSightings::default();
        assert!(!reader.tell_forgotten_phone(pair_id, &[], &mut sightings, Instant::now()));
        // No phone in sight on the test network either: no dial, and the
        // record stays.
        assert_eq!(reader.tell_forgotten_phones(&mut sightings), 0);
        assert_eq!(reader.pairs().len(), 1);
        assert!(path_for(&directory, pair_id).exists());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_forgotten_phone_whose_session_another_program_holds_is_left_to_it() {
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        note_session(&mut reader, pair_id);
        reader.requester.forget(pair_id, current_time_ms()).unwrap();
        let held = SessionLock::acquire(&session_lock_path(&directory, pair_id)).unwrap();
        assert!(!reader.tell_forgotten_phone(
            pair_id,
            &[],
            &mut BacklogSightings::default(),
            Instant::now()
        ));
        assert_eq!(reader.pairs().len(), 1);
        drop(held);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn this_computer_names_itself_by_its_system_and_host() {
        assert_eq!(desk().as_str(), "Linux - alpha-desk");
        let long_host = "\u{e9}".repeat(refineid_rapp::DISPLAY_NAME_MAX_BYTES);
        let name = super::display_name_of("Linux", &long_host);
        assert!(name.as_str().len() <= refineid_rapp::DISPLAY_NAME_MAX_BYTES);
        assert!(name.as_str().starts_with("Linux - \u{e9}"));
        assert!(
            super::local_display_name()
                .as_str()
                .starts_with(super::local_platform())
        );
    }

    #[test]
    fn a_forgotten_phone_untold_until_its_idle_expiry_loses_its_key() {
        let directory = scratch();
        // The fixture's pairing was made over thirty days ago, so its
        // idle expiry has passed: the forgotten record goes untold.
        let forgotten = record(PairId::from_array(PAIR_ID)).forgotten(current_time_ms());
        let mut reader = reader_with(&directory, vec![forgotten]);
        assert_eq!(reader.pairs().len(), 1);
        reader.sweep();
        assert!(reader.pairs().is_empty());
        assert!(!path_for(&directory, PairId::from_array(PAIR_ID)).exists());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn two_forgotten_phones_wait_in_the_backlog_together() {
        let directory = scratch();
        let pair_ids = [PAIR_ID, UNKNOWN_PAIR_ID].map(PairId::from_array);
        let mut reader = reader_with(
            &directory,
            pair_ids.iter().map(|pair_id| record(*pair_id)).collect(),
        );
        for pair_id in pair_ids {
            note_session(&mut reader, pair_id);
        }
        for pair_id in pair_ids {
            reader.requester.forget(pair_id, current_time_ms()).unwrap();
        }
        assert_eq!(reader.phone(), None);
        // No phone in sight: no dial, both records stay.
        assert_eq!(
            reader.tell_forgotten_phones(&mut BacklogSightings::default()),
            0
        );
        assert_eq!(reader.pairs().len(), 2);
        for pair_id in pair_ids {
            assert!(path_for(&directory, pair_id).exists());
        }
        let _ = std::fs::remove_dir_all(directory);
    }

    /// The gap between a listing and a relisting soon after.
    const SIGHTING_STEP: Duration = Duration::from_secs(1);
    /// Rounds further apart than the loss hold: staying listed across
    /// them is still not absence.
    const ROUND_STEP: Duration = Duration::from_secs(60);

    #[test]
    fn a_phone_first_listed_is_an_appearance() {
        let mut sightings = BacklogSightings::default();
        assert!(sightings.appearance(
            PairId::from_array(PAIR_ID),
            BacklogRoute::Stream,
            Instant::now()
        ));
    }

    #[test]
    fn a_phone_that_stays_listed_appears_once() {
        let mut sightings = BacklogSightings::default();
        let pair_id = PairId::from_array(PAIR_ID);
        let mut now = Instant::now();
        assert!(sightings.appearance(pair_id, BacklogRoute::Stream, now));
        // Round after round lists the same phone, however far apart the
        // rounds run: elapsed time without a completed round that missed
        // it is never absence, so none is an appearance and none dials.
        for _ in 0..3 {
            now += ROUND_STEP;
            assert!(!sightings.appearance(pair_id, BacklogRoute::Stream, now));
        }
    }

    #[test]
    fn a_phone_missed_by_a_completed_round_and_listed_after_the_hold_appears_again() {
        let mut sightings = BacklogSightings::default();
        let pair_id = PairId::from_array(PAIR_ID);
        let first = Instant::now();
        assert!(sightings.appearance(pair_id, BacklogRoute::Stream, first));
        // A completed round that does not list the phone starts its
        // absence; listed again once the hold passed since the miss, the
        // phone appears again.
        let missed_at = first + ROUND_STEP;
        sightings.missed(pair_id, BacklogRoute::Stream, missed_at);
        assert!(sightings.appearance(
            pair_id,
            BacklogRoute::Stream,
            missed_at + BACKLOG_LOSS_HOLD + SIGHTING_STEP
        ));
    }

    #[test]
    fn a_phone_listed_soon_after_one_missed_round_is_still_in_sight() {
        let mut sightings = BacklogSightings::default();
        let pair_id = PairId::from_array(PAIR_ID);
        let first = Instant::now();
        assert!(sightings.appearance(pair_id, BacklogRoute::Stream, first));
        let missed_at = first + ROUND_STEP;
        sightings.missed(pair_id, BacklogRoute::Stream, missed_at);
        // Listed again before the hold passed since the miss: the same
        // sighting, so no dial.
        assert!(!sightings.appearance(
            pair_id,
            BacklogRoute::Stream,
            missed_at + BACKLOG_LOSS_HOLD - SIGHTING_STEP
        ));
    }

    #[test]
    fn a_miss_without_a_sighting_leaves_the_first_listing_an_appearance() {
        let mut sightings = BacklogSightings::default();
        let pair_id = PairId::from_array(PAIR_ID);
        let now = Instant::now();
        sightings.missed(pair_id, BacklogRoute::Stream, now);
        assert!(sightings.appearance(pair_id, BacklogRoute::Stream, now));
    }

    #[test]
    fn sightings_tell_pairings_apart() {
        let mut sightings = BacklogSightings::default();
        let now = Instant::now();
        assert!(sightings.appearance(PairId::from_array(PAIR_ID), BacklogRoute::Stream, now));
        assert!(sightings.appearance(
            PairId::from_array(UNKNOWN_PAIR_ID),
            BacklogRoute::Stream,
            now
        ));
        assert!(!sightings.appearance(PairId::from_array(PAIR_ID), BacklogRoute::Stream, now));
    }

    #[test]
    fn a_pairing_that_left_the_backlog_appears_at_its_next_listing() {
        let mut sightings = BacklogSightings::default();
        let pair_id = PairId::from_array(PAIR_ID);
        let now = Instant::now();
        assert!(sightings.appearance(pair_id, BacklogRoute::Stream, now));
        // The pairing's echo destroyed the record and ended the sighting,
        // as an mDNS loss or removal does: its next listing is a new
        // appearance.
        sightings.drop_pairing(pair_id);
        assert!(sightings.appearance(pair_id, BacklogRoute::Stream, now));
    }

    #[test]
    fn dropping_a_pairing_that_left_keeps_the_other_sightings() {
        let mut sightings = BacklogSightings::default();
        let pair_id = PairId::from_array(PAIR_ID);
        let other = PairId::from_array(UNKNOWN_PAIR_ID);
        let now = Instant::now();
        assert!(sightings.appearance(pair_id, BacklogRoute::Stream, now));
        assert!(sightings.appearance(other, BacklogRoute::Stream, now));
        // Only the pairing that left the backlog ends its sighting; the
        // phone that stays listed is still the same sighting.
        sightings.drop_left_backlog(&[other]);
        assert!(sightings.appearance(pair_id, BacklogRoute::Stream, now));
        assert!(!sightings.appearance(other, BacklogRoute::Stream, now));
    }

    /// Notes a session to `pair_id` in `reader` now, so the pairing it then
    /// forgets waits in the backlog instead of expiring at once (section
    /// 4.6 item 3 counts from the latest established session, not from the
    /// forget).
    fn note_session(reader: &mut RemoteReader, pair_id: PairId) {
        reader
            .requester
            .store_mut()
            .sweep(pair_id, current_time_ms(), true)
            .unwrap();
    }

    /// A service instance on `endpoints`, publishing an unhinted
    /// `mode=session` record: any pairing's phone may serve it.
    fn unhinted_service(endpoints: Vec<String>) -> StreamService {
        StreamService {
            instance: "synthetic-instance".to_owned(),
            endpoints,
            txt: vec![
                ("v".to_owned(), "1".to_owned()),
                ("mode".to_owned(), "session".to_owned()),
            ],
        }
    }

    /// A dial that opens nothing, for the test named in its counter: counts
    /// the attempt and reports no session, so the record stays in the
    /// backlog.
    fn dial_nothing_once(
        _: &[String],
        _: &str,
        _: Duration,
        _: &RoutingPreamble,
    ) -> Result<TcpFrameTransport, StreamError> {
        DIALS_ONCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(StreamError::Unreachable)
    }

    /// As [`dial_nothing_once`], for the reappearance test.
    fn dial_nothing_again(
        _: &[String],
        _: &str,
        _: Duration,
        _: &RoutingPreamble,
    ) -> Result<TcpFrameTransport, StreamError> {
        DIALS_AGAIN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(StreamError::Unreachable)
    }

    /// As [`dial_nothing_once`], for the expired-record test.
    fn dial_nothing_expired(
        _: &[String],
        _: &str,
        _: Duration,
        _: &RoutingPreamble,
    ) -> Result<TcpFrameTransport, StreamError> {
        DIALS_EXPIRED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(StreamError::Unreachable)
    }

    /// As [`dial_nothing_once`], for the soon-after-a-miss test.
    fn dial_nothing_soon(
        _: &[String],
        _: &str,
        _: Duration,
        _: &RoutingPreamble,
    ) -> Result<TcpFrameTransport, StreamError> {
        DIALS_SOON.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(StreamError::Unreachable)
    }

    /// The dial attempts the staying-in-sight test opened.
    static DIALS_ONCE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// The dial attempts the reappearance test opened.
    static DIALS_AGAIN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// The dial attempts the expired-record test opened.
    static DIALS_EXPIRED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// The dial attempts the soon-after-a-miss test opened.
    static DIALS_SOON: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    #[test]
    fn a_phone_that_stays_in_sight_is_dialed_once() {
        use std::sync::atomic::Ordering;
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        note_session(&mut reader, pair_id);
        reader.requester.forget(pair_id, current_time_ms()).unwrap();
        reader.dial = dial_nothing_once;
        let services = vec![unhinted_service(vec!["198.51.100.7:1".to_owned()])];
        let mut sightings = BacklogSightings::default();
        let mut now = Instant::now();
        // The first listing is the appearance: one connection opens, its
        // handshake fails without an answer, and the record stays for the
        // next appearance.
        assert!(!reader.tell_forgotten_phone(pair_id, &services, &mut sightings, now));
        assert_eq!(DIALS_ONCE.load(Ordering::SeqCst), 1);
        assert_eq!(reader.pairs().len(), 1);
        // Round after round lists the same phone, further apart than the
        // loss hold: elapsed time without a completed round that missed it
        // is never absence, so nothing dials again.
        for _ in 0..3 {
            now += ROUND_STEP;
            assert!(!reader.tell_forgotten_phone(pair_id, &services, &mut sightings, now));
        }
        assert_eq!(DIALS_ONCE.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_phone_missed_by_a_round_and_back_after_the_hold_is_dialed_again() {
        use std::sync::atomic::Ordering;
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        note_session(&mut reader, pair_id);
        reader.requester.forget(pair_id, current_time_ms()).unwrap();
        reader.dial = dial_nothing_again;
        let services = vec![unhinted_service(vec!["198.51.100.7:1".to_owned()])];
        let mut sightings = BacklogSightings::default();
        let now = Instant::now();
        assert!(!reader.tell_forgotten_phone(pair_id, &services, &mut sightings, now));
        assert_eq!(DIALS_AGAIN.load(Ordering::SeqCst), 1);
        // A completed round that does not list the phone starts its
        // absence: nothing dials for a round with no phone in sight.
        let missed_at = now + ROUND_STEP;
        let no_services: Vec<StreamService> = Vec::new();
        assert!(!reader.tell_forgotten_phone(pair_id, &no_services, &mut sightings, missed_at));
        assert_eq!(DIALS_AGAIN.load(Ordering::SeqCst), 1);
        assert_eq!(reader.pairs().len(), 1);
        // Listed again once the hold passed since the missed round: the
        // appearance dials again.
        let back = missed_at + BACKLOG_LOSS_HOLD + SIGHTING_STEP;
        assert!(!reader.tell_forgotten_phone(pair_id, &services, &mut sightings, back));
        assert_eq!(DIALS_AGAIN.load(Ordering::SeqCst), 2);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_phone_listed_soon_after_one_missed_round_is_not_dialed_again() {
        use std::sync::atomic::Ordering;
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        note_session(&mut reader, pair_id);
        reader.requester.forget(pair_id, current_time_ms()).unwrap();
        reader.dial = dial_nothing_soon;
        let services = vec![unhinted_service(vec!["198.51.100.7:1".to_owned()])];
        let mut sightings = BacklogSightings::default();
        let now = Instant::now();
        assert!(!reader.tell_forgotten_phone(pair_id, &services, &mut sightings, now));
        assert_eq!(DIALS_SOON.load(Ordering::SeqCst), 1);
        // One completed round misses the phone, but it is listed again
        // before the hold passed since the miss: the same sighting, so no
        // dial, and the record stays in the backlog.
        let missed_at = now + ROUND_STEP;
        let no_services: Vec<StreamService> = Vec::new();
        assert!(!reader.tell_forgotten_phone(pair_id, &no_services, &mut sightings, missed_at));
        let soon = missed_at + BACKLOG_LOSS_HOLD - SIGHTING_STEP;
        assert!(!reader.tell_forgotten_phone(pair_id, &services, &mut sightings, soon));
        assert_eq!(DIALS_SOON.load(Ordering::SeqCst), 1);
        assert_eq!(reader.pairs().len(), 1);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn an_expired_record_is_revoked_untold_and_never_dialed() {
        use std::sync::atomic::Ordering;
        let directory = scratch();
        // The fixture's pairing was made over thirty days ago, so its idle
        // expiry has passed: the forgotten record owes no notice.
        let forgotten = record(PairId::from_array(PAIR_ID)).forgotten(current_time_ms());
        let mut reader = reader_with(&directory, vec![forgotten]);
        let pair_id = PairId::from_array(PAIR_ID);
        reader.dial = dial_nothing_expired;
        let services = vec![unhinted_service(vec!["198.51.100.7:1".to_owned()])];
        let mut sightings = BacklogSightings::default();
        // Even with the phone in sight nothing dials: the record goes
        // untold instead.
        assert!(!reader.tell_forgotten_phone(pair_id, &services, &mut sightings, Instant::now()));
        assert_eq!(DIALS_EXPIRED.load(Ordering::SeqCst), 0);
        assert!(reader.pairs().is_empty());
        assert!(!path_for(&directory, pair_id).exists());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn the_owners_sweep_expires_a_pairing_idle_for_thirty_days() {
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        assert!(current_time_ms() >= CREATED_AT_MS + refineid_rapp::PAIRING_IDLE_EXPIRY_MS);
        assert!(reader.phone().is_some());
        reader.sweep();
        // An expired pairing sends nothing: its key and record go at once.
        assert_eq!(reader.phone(), None);
        assert!(reader.pairs().is_empty());
        assert!(!path_for(&directory, pair_id).exists());
        assert_eq!(reader.expire_idle_pairings(), Ok(0));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_session_held_by_another_program_makes_the_pairing_busy() {
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        let held = SessionLock::acquire(&session_lock_path(&directory, pair_id)).unwrap();
        assert_eq!(
            reader.open_session(Some(pair_id), Duration::ZERO).err(),
            Some(RemoteError::Busy)
        );
        drop(held);
        // Released: allow a brief moment for the lock release to settle
        // under heavy parallel test load.
        let mut result = None;
        for _ in 0..LOCK_LOOKS {
            let res = reader.open_session(Some(pair_id), Duration::ZERO).err();
            if res != Some(RemoteError::Busy) {
                result = res;
                break;
            }
            std::thread::sleep(LOCK_STEP);
        }
        assert_eq!(result, Some(RemoteError::NotFound));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn two_readers_on_one_store_contend_for_the_pairing() {
        let directory = scratch();
        let mut first = reader_with_pairing(&directory);
        let mut second =
            RemoteReader::with_store(desk(), "Linux", FilePairingStore::open(&directory).unwrap());
        let pair_id = PairId::from_array(PAIR_ID);
        // The first reader searches for a phone, finding none, and holds
        // the pairing's lock for the whole search.
        let (started, searching) = std::sync::mpsc::channel();
        let searcher = std::thread::spawn(move || {
            started.send(()).unwrap();
            first.open_session(Some(pair_id), SEARCH)
        });
        searching.recv().unwrap();
        // The second reader asks during the search and is told the phone is
        // busy. Wait until the searcher has acquired the session lock before
        // opening the contending session.
        let lock_path = session_lock_path(&directory, pair_id);
        while SessionLock::acquire(&lock_path).is_ok() {
            std::thread::sleep(LOCK_STEP);
        }
        assert_eq!(
            second.open_session(Some(pair_id), Duration::ZERO).err(),
            Some(RemoteError::Busy)
        );
        assert_eq!(searcher.join().unwrap().err(), Some(RemoteError::NotFound));
        assert_eq!(
            second.open_session(Some(pair_id), Duration::ZERO).err(),
            Some(RemoteError::NotFound)
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_withdrawn_reader_dials_nothing_and_keeps_the_pairing() {
        let directory = scratch();
        let withdrawal = Withdrawal::new();
        let mut reader = reader_with_pairing(&directory).following(withdrawal.clone());
        let pair_id = PairId::from_array(PAIR_ID);
        withdrawal.raise();
        let started = Instant::now();
        assert_eq!(
            reader.dial_session(pair_id, SEARCH).err(),
            Some(RemoteError::Session(SessionError::WithdrawnHere))
        );
        // No browse round ran.
        assert!(started.elapsed() < BROWSE_ROUND);
        assert!(reader.phone().is_some_and(|phone| phone.usable()));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_withdrawal_ends_a_search_at_its_next_round() {
        /// A search several rounds long.
        const LONG_SEARCH: Duration = Duration::from_secs(10);
        /// How far into the search the computer quits.
        const QUIT_AFTER: Duration = Duration::from_millis(100);
        /// The rounds a search may run before it sees the withdrawal: the
        /// one in progress and its end.
        const ROUNDS_TO_STOP: u32 = 2;
        let directory = scratch();
        let withdrawal = Withdrawal::new();
        let mut reader = reader_with_pairing(&directory).following(withdrawal.clone());
        let pair_id = PairId::from_array(PAIR_ID);
        let quit = std::thread::spawn(move || {
            std::thread::sleep(QUIT_AFTER);
            withdrawal.raise();
        });
        let started = Instant::now();
        let outcome = reader.dial_session(pair_id, LONG_SEARCH);
        quit.join().unwrap();
        assert_eq!(
            outcome.err(),
            Some(RemoteError::Session(SessionError::WithdrawnHere))
        );
        assert!(started.elapsed() < BROWSE_ROUND * ROUNDS_TO_STOP);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_ceremony_held_by_another_program_makes_pairing_busy() {
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let held = SessionLock::acquire(&ceremony_lock_path(&directory)).unwrap();
        assert_eq!(
            reader.pair_with_code(CODE, Duration::ZERO).err(),
            Some(RemoteError::Busy)
        );
        drop(held);
        assert_eq!(
            reader.pair_with_code(CODE, Duration::ZERO).err(),
            Some(RemoteError::Pairing(PairingSearchError::NoneInPairingMode))
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_search_that_tried_no_phone_says_none_was_in_pairing_mode() {
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let outcome = reader.pair_with_code(CODE, Duration::ZERO).err();
        assert_eq!(
            outcome.map(|error| error.to_string()),
            Some("pairing: no phone in pairing mode was found".to_owned())
        );
        assert_eq!(
            RemoteError::Pairing(PairingSearchError::NotAccepted).to_string(),
            "pairing: the code was not accepted"
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    /// Whether any file in `directory` holds [`CERTIFICATE`].
    fn store_holds_certificate(directory: &std::path::Path) -> bool {
        std::fs::read_dir(directory).unwrap().any(|entry| {
            std::fs::read(entry.unwrap().path()).is_ok_and(|bytes| {
                bytes
                    .windows(CERTIFICATE.len())
                    .any(|window| window == CERTIFICATE)
            })
        })
    }

    /// Writes `pair_id`'s usable record in `directory` as an earlier build
    /// stored it, holding [`CERTIFICATE`].
    fn seed_certificate(directory: &std::path::Path, pair_id: PairId) {
        std::fs::create_dir_all(directory).unwrap();
        let blob = crate::persistence::frame_certificate_revision(&record(pair_id), CERTIFICATE);
        std::fs::write(path_for(directory, pair_id), blob).unwrap();
        assert!(store_holds_certificate(directory));
    }

    #[test]
    fn the_modules_reader_erases_a_stored_certificate_and_keeps_the_pairing() {
        let directory = scratch();
        let pair_id = PairId::from_array(PAIR_ID);
        seed_certificate(&directory, pair_id);
        let reader = RemoteReader::open_local_without_sweep(&directory).unwrap();
        assert!(!store_holds_certificate(&directory));
        let phone = reader.phone().unwrap();
        assert_eq!(phone.pair_id, pair_id);
        assert!(phone.usable());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn forgetting_a_phone_leaves_no_certificate_while_its_session_is_held() {
        let directory = scratch();
        let pair_id = PairId::from_array(PAIR_ID);
        seed_certificate(&directory, pair_id);
        let store = FilePairingStore::open(&directory).unwrap();
        let mut reader = RemoteReader::with_store(desk(), "Linux", store);
        note_session(&mut reader, pair_id);
        // Held here, the lock leaves the record to its holder and the backlog.
        let held = SessionLock::acquire(&session_lock_path(&directory, pair_id)).unwrap();
        assert_eq!(reader.forget_and_tell(pair_id), Ok(false));
        assert!(path_for(&directory, pair_id).exists());
        assert!(!store_holds_certificate(&directory));
        drop(held);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_new_pairing_replacing_the_old_erases_the_old_certificate() {
        let directory = scratch();
        let (old, new) = (
            PairId::from_array(PAIR_ID),
            PairId::from_array(UNKNOWN_PAIR_ID),
        );
        seed_certificate(&directory, old);
        let mut store = FilePairingStore::open(&directory).unwrap();
        store.insert(record(new)).unwrap();
        let mut reader = RemoteReader::with_store(desk(), "Linux", store);
        let held = SessionLock::acquire(&session_lock_path(&directory, old)).unwrap();
        reader.supersede_others(new);
        assert!(!store_holds_certificate(&directory));
        assert_eq!(reader.phone().unwrap().pair_id, new);
        drop(held);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn an_expired_pairing_leaves_no_certificate_and_no_file() {
        let directory = scratch();
        let pair_id = PairId::from_array(PAIR_ID);
        seed_certificate(&directory, pair_id);
        let mut reader = reader_with(&directory, Vec::new());
        assert_eq!(reader.expire_idle_pairings(), Ok(1));
        assert!(!path_for(&directory, pair_id).exists());
        assert!(!store_holds_certificate(&directory));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn busy_is_its_own_outcome_and_not_an_unreachable_phone() {
        assert_ne!(RemoteError::Busy, RemoteError::NotFound);
        assert_ne!(RemoteError::Busy, RemoteError::NotPaired);
        assert!(!matches!(RemoteError::Busy, RemoteError::Session(_)));
    }

    #[test]
    fn the_busy_error_names_another_program_on_this_computer() {
        assert_eq!(
            RemoteError::Busy.to_string(),
            "the phone session is held by another program on this computer"
        );
    }

    #[test]
    fn a_lifetime_is_sent_as_whole_milliseconds() {
        assert_eq!(
            lifetime_ms(Duration::from_secs(WHOLE_SECONDS)),
            WHOLE_SECONDS_MS
        );
        assert_eq!(
            lifetime_ms(Duration::from_micros(SUB_MILLISECOND_MICROS)),
            SUB_MILLISECOND_MS
        );
        assert_eq!(lifetime_ms(Duration::MAX), u64::MAX);
    }

    fn keys(local: [u8; X25519_KEY_SIZE]) -> PairingKeys {
        let pair_id = PairId::from_array(PAIR_ID);
        PairingKeys {
            discovery: DiscoveryKey::from_parts(pair_id, &local, &PEER_PUBLIC).unwrap(),
            routing: RoutingKey::from_parts(pair_id, &local, &PEER_PUBLIC).unwrap(),
            withdrawal: WithdrawalKey::from_parts(pair_id, &local, &PEER_PUBLIC).unwrap(),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn the_local_host_name_is_short_and_never_empty() {
        let name = super::local_host_name();
        assert!(!name.is_empty());
        assert!(!name.contains('.'));
    }

    fn service(instance: &str, txt: &[(&str, String)]) -> StreamService {
        StreamService {
            instance: instance.to_owned(),
            endpoints: vec!["192.0.2.10:47110".to_owned()],
            txt: txt
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        }
    }

    fn session(instance: &str, hints: Option<String>) -> StreamService {
        let mut txt = vec![("v", "1".to_owned()), ("mode", "session".to_owned())];
        if let Some(hints) = hints {
            txt.push(("hints", hints));
        }
        service(instance, &txt)
    }

    fn withdrawn(instance: &str, key: &WithdrawalKey) -> StreamService {
        let name = InstanceName::new(instance).unwrap();
        let candidate = AnnouncementCandidate {
            hint: key.hint(&name, withdrawal_counter(unix_seconds())),
            last_used_ms: 1,
        };
        let record = WithdrawnRecord::assemble(&[candidate], |bytes| {
            getrandom::fill(bytes).map_err(|_| refineid_rapp::WithdrawalError::RandomUnavailable)
        })
        .unwrap();
        service(instance, &record.txt_entries())
    }

    fn names(services: &[StreamService]) -> Vec<&str> {
        services.iter().map(|svc| svc.instance.as_str()).collect()
    }

    #[test]
    fn named_custodians_come_first_and_foreign_ones_are_never_dialed() {
        let mine = keys(MINE);
        let epoch = discovery_epoch(unix_seconds());
        let ordered = sessions_for(
            &mine,
            &[
                session("refineid-unhinted", None),
                session(
                    "refineid-foreign",
                    Some(hex(&keys(THEIRS).discovery.hint(epoch))),
                ),
                session("refineid-mine", Some(hex(&mine.discovery.hint(epoch)))),
            ],
        )
        .unwrap();
        assert_eq!(names(&ordered), ["refineid-mine", "refineid-unhinted"]);
    }

    #[test]
    fn a_withdrawal_for_the_pairing_ends_the_search() {
        let mine = keys(MINE);
        assert_eq!(
            sessions_for(
                &mine,
                &[
                    withdrawn("refineid-gone", &mine.withdrawal),
                    session("refineid-unhinted", None),
                ],
            )
            .map(|found| names(&found).len()),
            Err(RemoteError::Withdrawn)
        );
    }

    #[test]
    fn a_session_record_naming_the_pairing_outranks_its_withdrawal() {
        let mine = keys(MINE);
        let epoch = discovery_epoch(unix_seconds());
        let found = sessions_for(
            &mine,
            &[
                withdrawn("refineid-old", &mine.withdrawal),
                session("refineid-new", Some(hex(&mine.discovery.hint(epoch)))),
            ],
        )
        .unwrap();
        assert_eq!(names(&found), ["refineid-new"]);
    }

    #[test]
    fn another_pairings_withdrawal_is_ignored() {
        let mine = keys(MINE);
        let found = sessions_for(
            &mine,
            &[
                withdrawn("refineid-other", &keys(THEIRS).withdrawal),
                session("refineid-unhinted", None),
            ],
        )
        .unwrap();
        assert_eq!(names(&found), ["refineid-unhinted"]);
    }

    #[test]
    fn a_session_record_on_the_withdrawn_instance_is_never_dialed() {
        let mine = keys(MINE);
        let epoch = discovery_epoch(unix_seconds());
        let stale = session("refineid-gone", Some(hex(&mine.discovery.hint(epoch))));
        assert_eq!(
            sessions_for(
                &mine,
                &[withdrawn("refineid-gone", &mine.withdrawal), stale]
            )
            .map(|found| found.len()),
            Err(RemoteError::Withdrawn)
        );
    }

    #[test]
    fn an_ended_session_reports_its_reason_unless_a_result_arrived() {
        let certificate = CardOperationResult::Certificate(CERTIFICATE.to_vec());
        assert_eq!(
            operation_result(
                Ok(OperationOutcome::Completed(certificate.clone())),
                Some(RemoteError::Withdrawn)
            ),
            Ok(certificate)
        );
        assert_eq!(
            operation_result(Ok(OperationOutcome::Lost), Some(RemoteError::Withdrawn)),
            Err(RemoteError::Withdrawn)
        );
        assert_eq!(
            operation_result(
                Ok(OperationOutcome::Lost),
                Some(RemoteError::RevokedByPhone)
            ),
            Err(RemoteError::RevokedByPhone)
        );
        assert_eq!(
            operation_result(
                Err(AdmissionError::SessionNotHealthy),
                Some(RemoteError::Withdrawn)
            ),
            Err(RemoteError::Withdrawn)
        );
        let cancelled = OperationOutcome::Cancelled(ResultError::OperationExpired);
        assert_eq!(
            operation_result(Ok(cancelled.clone()), None),
            Err(RemoteError::Outcome(Box::new(cancelled)))
        );
    }

    #[test]
    fn every_session_preamble_is_fresh() {
        let mine = keys(MINE);
        assert_ne!(
            mine.session_preamble().unwrap(),
            mine.session_preamble().unwrap()
        );
    }

    #[test]
    fn a_failed_session_names_its_peer_and_transport() {
        let directory = scratch();
        let reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        let peer = pairing_peer_label(reader.requester.store(), pair_id);
        assert_eq!(peer, PHONE_NAME);
        let line = session_failure_message("Session(HandshakeFailed)", &peer);
        assert!(line.contains(&peer));
        assert!(line.contains(SESSION_TRANSPORT_LABEL));
        assert_eq!(
            line,
            format!("Session(HandshakeFailed), {peer}, {SESSION_TRANSPORT_LABEL}")
        );
        let unknown = pairing_peer_label(
            reader.requester.store(),
            PairId::from_array(UNKNOWN_PAIR_ID),
        );
        assert_eq!(unknown, UNKNOWN_PAIRING_LABEL);
        let unknown_line = session_failure_message("Session(Transport)", &unknown);
        assert!(unknown_line.contains(UNKNOWN_PAIRING_LABEL));
        assert!(unknown_line.contains(SESSION_TRANSPORT_LABEL));
        let _ = std::fs::remove_dir_all(directory);
    }
}
