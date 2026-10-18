//! The workstation's remote card reader: pairing by code and one operation
//! per session, over the stream tier.
//!
//! This is the surface the CLI, the GUI, and the TLS client use. Pairing
//! browses for a custodian in `mode=pairing`; every operation browses for
//! custodians in `mode=session`, dials each, and opens with a routing value
//! that is fresh per dial and keyed by the pairing's static agreement. A
//! custodian that does not hold the pairing closes the connection, and the
//! next one is tried. A withdrawn record announcing the pairing, or a session
//! close carrying `service_withdrawn`, ends the search at once; the
//! withdrawn instance is never dialed, and the pairing is dialed again only
//! when a session record on another instance names it. A session record
//! whose `revoked` entries name the pairing is the phone's word that it
//! forgot this computer: the pairing is revoked here and the user told.
//!
//! An open session reports whether the phone can serve a card (section
//! 8.4); an operation is sent only on a session that reports one, and a
//! consumer that offers the phone's identity holds the session it was
//! reported on.

use std::time::{Duration, Instant};

use crate::engine::Session;
use crate::engine::SessionEnd;
use crate::engine::{
    AdmissionError, OperationOutcome, PairingError, Reconciliation, Requester, RequesterConfig,
    SessionError,
};
use crate::file_journal::FileOperationJournal;
use crate::file_store::FilePairingStore;
use crate::ids::OperationId;
use crate::ids::PairId;
use crate::message::CloseReason;
use crate::operations::{CardOperation, CardOperationResult, CertificateKind};
use crate::store::PairingRecord;
use crate::store::{PairingDisposition, PairingStore, StoreError};
use crate::stream::{
    DiscoveryMode, HintMatch, RoutingPreamble, STREAM_CANDIDATE_ID, StreamService, browse,
    browse_stream_services, dial,
};
use crate::transport::TcpFrameTransport;
use refineid_rapp::{DiscoveryKey, RevocationKey, RoutingKey, TransportProfile, WithdrawalKey};

/// The names a phone gives when its system hands the app only the
/// device type.
const DEVICE_TYPE_NAMES: [&str; 2] = ["iPhone", "iPad"];

/// The name a custodian is listed under: the one it introduced itself
/// with, or its host name on the network when the introduction was only
/// its device type and the host name is known.
fn custodian_name(introduced: &str, host: &str) -> String {
    if DEVICE_TYPE_NAMES.contains(&introduced) && !host.is_empty() {
        host.to_owned()
    } else {
        introduced.to_owned()
    }
}

/// How long one discovery round listens for answers.
const BROWSE_ROUND: Duration = Duration::from_secs(2);
/// How long pairing waits for each custodian message; the holder may be
/// reading the screen.
const PAIRING_RECEIVE_DEADLINE: Duration = Duration::from_secs(60);
/// How long an operation waits for each custodian message; consent, PIN
/// entry, and the card tap all happen on the phone in that time.
const OPERATION_RECEIVE_DEADLINE: Duration = Duration::from_secs(120);
/// The lifetime each request asks for (section 8.2.1).
const OPERATION_LIFETIME_MS: u64 = 120_000;

/// The keys one stored pairing uses to find and reach its custodian.
struct PairingKeys {
    discovery: DiscoveryKey,
    routing: RoutingKey,
    withdrawal: WithdrawalKey,
    revocation: RevocationKey,
}

impl PairingKeys {
    fn derive(record: &PairingRecord) -> Result<Self, RemoteError> {
        if record.disposition != PairingDisposition::Paired {
            return Err(RemoteError::NotPaired);
        }
        let core = record
            .to_core_pair_record()
            .map_err(|_| RemoteError::NotPaired)?;
        Ok(Self {
            discovery: DiscoveryKey::derive(&core).map_err(|_| RemoteError::NotPaired)?,
            routing: RoutingKey::derive(&core).map_err(|_| RemoteError::NotPaired)?,
            withdrawal: WithdrawalKey::derive(&core).map_err(|_| RemoteError::NotPaired)?,
            revocation: RevocationKey::derive(&core).map_err(|_| RemoteError::NotPaired)?,
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

/// The session custodians worth dialing for the pairing keyed by `keys`,
/// best first: those whose rotating hint names the pairing, then those
/// publishing no hints. A custodian whose hints all name other pairings is
/// never dialed, and neither is an instance that announced its withdrawal
/// for the pairing.
///
/// # Errors
/// [`RemoteError::RevokedByPhone`] when a session record announces that
/// the custodian forgot the pairing, and [`RemoteError::Withdrawn`] when a
/// custodian announced its withdrawal for the pairing and no session record
/// on another instance names it.
fn sessions_for(
    keys: &PairingKeys,
    services: Vec<StreamService>,
) -> Result<Vec<StreamService>, RemoteError> {
    let now = unix_seconds();
    if services
        .iter()
        .any(|service| service.revokes(&keys.revocation, now))
    {
        return Err(RemoteError::RevokedByPhone);
    }
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
            HintMatch::Named => named.push(service),
            HintMatch::Unhinted => unhinted.push(service),
            HintMatch::Other => {}
        }
    }
    if !withdrawn.is_empty() && named.is_empty() {
        return Err(RemoteError::Withdrawn);
    }
    named.extend(unhinted);
    Ok(named)
}

/// The answer of one operation whose session ended with `withdrawn` telling
/// whether the peer announced its withdrawal. A delivered result stands; any
/// other ending of a withdrawn session reports the withdrawal.
fn operation_result(
    outcome: Result<OperationOutcome, AdmissionError>,
    withdrawn: bool,
) -> Result<CardOperationResult, RemoteError> {
    match outcome {
        Ok(OperationOutcome::Completed(result)) => Ok(result),
        _ if withdrawn => Err(RemoteError::Withdrawn),
        Ok(other) => Err(RemoteError::Outcome(Box::new(other))),
        Err(error) => Err(RemoteError::Admission(error)),
    }
}

/// Whether the peer ended `end` by announcing its withdrawal.
const fn withdrawn_by(end: Option<SessionEnd>) -> bool {
    matches!(
        end,
        Some(SessionEnd::PeerClose(CloseReason::ServiceWithdrawn))
    )
}

/// Why a remote reader call ended without its answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteError {
    /// The pairing store could not be read or written.
    Store(StoreError),
    /// No stored pairing matches.
    NotPaired,
    /// No custodian advertised the needed mode before the deadline.
    NotFound,
    /// The phone announced that it stopped serving the pairing.
    Withdrawn,
    /// The phone announced that it forgot this computer; the pairing is
    /// revoked here and the user pairs again.
    RevokedByPhone,
    /// The phone opened the session but reports no card it can serve.
    CardAbsent,
    /// The system random source failed.
    RandomUnavailable,
    /// Pairing failed.
    Pairing(PairingError),
    /// No custodian opened a session for the pairing.
    Session(SessionError),
    /// The operation could not be admitted.
    Admission(AdmissionError),
    /// The operation ended without a result.
    Outcome(Box<OperationOutcome>),
}

impl core::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "pairing store: {error:?}"),
            Self::NotPaired => f.write_str("no paired phone"),
            Self::NotFound => f.write_str("no phone found on the local network"),
            Self::Withdrawn => f.write_str("the phone turned remote card access off"),
            Self::RevokedByPhone => f.write_str("the phone forgot this computer; pair it again"),
            Self::CardAbsent => f.write_str("the phone has no card on it"),
            Self::RandomUnavailable => f.write_str("the system random source failed"),
            Self::Pairing(error) => write!(f, "pairing: {error}"),
            Self::Session(error) => write!(f, "session: {error}"),
            Self::Admission(error) => write!(f, "operation: {error}"),
            Self::Outcome(outcome) if **outcome == OperationOutcome::Refused => {
                f.write_str("the phone's message was not understood")
            }
            Self::Outcome(outcome) => write!(f, "operation ended: {outcome:?}"),
        }
    }
}

impl core::error::Error for RemoteError {}

/// What a stored pairing shows to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairSummary {
    /// The pair identifier.
    pub pair_id: PairId,
    /// The phone's display label.
    pub peer_display_name: String,
    /// The phone's platform label.
    pub peer_platform: String,
    /// The granted credential profiles.
    pub granted_profiles: Vec<String>,
    /// The cached authentication certificate, if read.
    pub auth_cert: Option<Vec<u8>>,
    /// Whether the pairing is revoked.
    pub revoked: bool,
    /// Whether the record was stored before the phone confirmed its own
    /// storage (section 4.3 item 4): it opens no session until pairing
    /// is run again.
    pub unconfirmed: bool,
    /// Whether the phone ended the pairing: it forgot this computer, or
    /// rejected the credential (section 4.6).
    pub forgotten_by_phone: bool,
}

impl PairSummary {
    /// Whether the pairing can open a session: neither revoked nor
    /// unconfirmed.
    #[must_use]
    pub const fn usable(&self) -> bool {
        !self.revoked && !self.unconfirmed
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

/// The workstation's remote reader over its durable pairing store.
#[derive(Debug)]
pub struct RemoteReader {
    requester: Requester<FilePairingStore, FileOperationJournal>,
}

/// One open session to a phone that reported a card it can serve.
#[derive(Debug)]
pub struct RemoteSession {
    session: Session<TcpFrameTransport>,
}

impl RemoteSession {
    /// Whether the phone still reports a card it can serve.
    #[must_use]
    pub fn card_present(&self) -> bool {
        self.session.card_present() == Some(true)
    }

    /// Whether the phone reported its consent view on screen during the
    /// last operation.
    #[must_use]
    pub const fn consent_shown(&self) -> bool {
        self.session.consent_shown()
    }
}

/// The platform label this workstation introduces itself with.
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
/// what `uname -n` prints, or `RefineID` when the system has no name of
/// its own.
#[must_use]
pub fn local_host_name() -> String {
    let printed = std::process::Command::new("uname")
        .arg("-n")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
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

impl RemoteReader {
    /// Opens the per-user pairing store, introducing this workstation by
    /// its host name and platform.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the store cannot be opened.
    pub fn open_local() -> Result<Self, RemoteError> {
        Self::open(&local_host_name(), local_platform())
    }

    /// Opens the per-user pairing store.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the store cannot be opened.
    pub fn open(display_name: &str, platform: &str) -> Result<Self, RemoteError> {
        let store = FilePairingStore::open_default().map_err(RemoteError::Store)?;
        let journal = FileOperationJournal::open_default().map_err(RemoteError::Store)?;
        Ok(Self::with_stores(display_name, platform, store, journal))
    }

    /// Uses `store` for pairings and `journal` for operations.
    #[must_use]
    pub fn with_stores(
        display_name: &str,
        platform: &str,
        store: FilePairingStore,
        journal: FileOperationJournal,
    ) -> Self {
        let mut requester = Requester::new(
            RequesterConfig {
                display_name: display_name.to_owned(),
                platform: platform.to_owned(),
            },
            store,
            journal,
        );
        requester.revoke_unconfirmed_pairings();
        Self { requester }
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
                pair_id: record.pair_id,
                peer_display_name: record.peer_display_name.clone(),
                peer_platform: record.peer_platform.clone(),
                granted_profiles: record.granted_profiles.clone(),
                auth_cert: record.auth_cert.clone(),
                revoked: record.disposition == PairingDisposition::Revoked,
                unconfirmed: record.disposition == PairingDisposition::Unconfirmed,
                forgotten_by_phone: record.disposition == PairingDisposition::Revoked
                    && record.peer_initiated_termination,
            })
            .collect()
    }

    /// The newest pairing that can open a session.
    #[must_use]
    pub fn selected(&self) -> Option<PairSummary> {
        self.pairs().into_iter().find(PairSummary::usable)
    }

    /// Forgets one pairing locally.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the record is unknown or cannot be removed.
    pub fn remove(&mut self, pair_id: PairId) -> Result<(), RemoteError> {
        self.requester
            .store_mut()
            .remove(pair_id)
            .map_err(RemoteError::Store)?;
        self.requester
            .journal_mut()
            .forget_pair(pair_id)
            .map_err(RemoteError::Store)
    }

    /// Operations of `pair_id` that ended ambiguous and await section 8.3
    /// reconciliation, oldest first.
    #[must_use]
    pub fn unreconciled(&self, pair_id: PairId) -> Vec<OperationId> {
        self.requester
            .journal()
            .unreconciled(pair_id)
            .into_iter()
            .map(|entry| entry.operation_id)
            .collect()
    }

    /// Asks the phone holding `pair_id` for the state of each operation
    /// that ended ambiguous (section 8.3), one session per operation, and
    /// annotates the journal with each answer. Nothing is ever retried.
    ///
    /// Returns each reconciled operation with what the phone reported and
    /// any result it re-delivered; a re-delivered completed result is
    /// acknowledged.
    ///
    /// # Errors
    /// [`RemoteError`] when the pairing is unknown or no phone opens a
    /// session for it before `discovery_timeout`.
    pub fn reconcile(
        &mut self,
        pair_id: PairId,
        discovery_timeout: Duration,
    ) -> Result<Vec<(OperationId, Reconciliation)>, RemoteError> {
        let record = self
            .requester
            .store()
            .get(pair_id)
            .map_err(|_| RemoteError::NotPaired)?;
        if record.disposition != PairingDisposition::Paired {
            return Err(RemoteError::NotPaired);
        }
        let keys = PairingKeys::derive(record)?;
        let mut answers = Vec::new();
        for operation_id in self.unreconciled(pair_id) {
            let deadline = Instant::now() + discovery_timeout;
            let mut answer = Err(RemoteError::NotFound);
            'search: while Instant::now() < deadline {
                for service in self.sessions_for(pair_id, &keys)? {
                    let Ok(transport) = dial(
                        &service.endpoints,
                        STREAM_CANDIDATE_ID,
                        OPERATION_RECEIVE_DEADLINE,
                        &keys.session_preamble()?,
                    ) else {
                        continue;
                    };
                    let mut session = match self.requester.connect(pair_id, transport) {
                        Ok(session) => session,
                        Err(SessionError::ClosedByPeer(CloseReason::ServiceWithdrawn)) => {
                            return Err(RemoteError::Withdrawn);
                        }
                        Err(SessionError::ClosedByPeer(CloseReason::PairingRevoked)) => {
                            return Err(RemoteError::RevokedByPhone);
                        }
                        Err(error) => {
                            answer = Err(RemoteError::Session(error));
                            continue;
                        }
                    };
                    answer = self
                        .requester
                        .reconcile_status(&mut session, operation_id)
                        .map_err(RemoteError::Session);
                    let withdrawn = withdrawn_by(
                        Requester::<FilePairingStore, FileOperationJournal>::session_end(&session),
                    );
                    self.requester
                        .disconnect(&mut session, CloseReason::Complete);
                    if withdrawn && answer.is_err() {
                        return Err(RemoteError::Withdrawn);
                    }
                    break 'search;
                }
            }
            answers.push((operation_id, answer?));
        }
        Ok(answers)
    }

    /// Pairs with the phone showing `code`, browsing for it until
    /// `discovery_timeout` passes.
    ///
    /// Every profile the code-derived offer names is requested and granted;
    /// the phone decides what it grants and the sets must agree.
    ///
    /// # Errors
    /// [`RemoteError::Pairing`] for a malformed or mistyped code and other
    /// pairing failures, [`RemoteError::NotFound`] when no phone in a
    /// pairing ceremony answered, and [`RemoteError::Store`] when the
    /// record of a completed ceremony cannot be written.
    pub fn pair_with_code(
        &mut self,
        code: &str,
        discovery_timeout: Duration,
    ) -> Result<PairSummary, RemoteError> {
        if crate::offer::normalize_pairing_code(code).is_none() {
            return Err(RemoteError::Pairing(PairingError::InvalidCode));
        }
        let deadline = Instant::now() + discovery_timeout;
        let mut last = RemoteError::NotFound;
        while Instant::now() < deadline {
            for service in browse(DiscoveryMode::Pairing, BROWSE_ROUND) {
                let Ok(transport) = dial(
                    &service.endpoints,
                    STREAM_CANDIDATE_ID,
                    PAIRING_RECEIVE_DEADLINE,
                    &RoutingPreamble::Pairing,
                ) else {
                    continue;
                };
                match self
                    .requester
                    .pair_with_code(code, transport, |_, requested| Some(requested.to_vec()))
                {
                    Ok(pair_id) => {
                        // The name is for display; a refused rewrite keeps
                        // the introduced one, the pairing stands either way.
                        let host = service.host.clone();
                        let _ = self.requester.store_mut().update(pair_id, &mut |entry| {
                            entry.peer_display_name =
                                custodian_name(&entry.peer_display_name, &host);
                        });
                        return self
                            .pairs()
                            .into_iter()
                            .find(|pair| pair.pair_id == pair_id)
                            .ok_or(RemoteError::NotPaired);
                    }
                    // A mistyped code spent one of the phone's attempts;
                    // trying another phone would spend that one's too.
                    Err(PairingError::CodeMismatch) => {
                        return Err(RemoteError::Pairing(PairingError::CodeMismatch));
                    }
                    Err(error) => last = RemoteError::Pairing(error),
                }
            }
        }
        Err(last)
    }

    /// The session custodians worth dialing for `pair_id`, applying the
    /// phone's announcements: a withdrawal ends the search, and a
    /// revocation revokes the pairing here before reporting it.
    fn sessions_for(
        &mut self,
        pair_id: PairId,
        keys: &PairingKeys,
    ) -> Result<Vec<StreamService>, RemoteError> {
        match sessions_for(keys, browse_stream_services(BROWSE_ROUND)) {
            Err(RemoteError::RevokedByPhone) => {
                self.requester.revoke_announced_by_peer(pair_id);
                Err(RemoteError::RevokedByPhone)
            }
            other => other,
        }
    }

    /// Opens a session to the phone holding `pair_id`, or the selected
    /// pairing when `None`, browsing until `discovery_timeout` passes, and
    /// waits for the phone's word on its card (section 8.4). A phone that
    /// first reports no card is given the rest of `discovery_timeout` to
    /// report one, so a card tapped after the dial still serves.
    ///
    /// A consumer that offers the phone's identity keeps the session for
    /// as long as it offers it: the offer is withdrawn with the session.
    ///
    /// # Errors
    /// [`RemoteError`] when no pairing matches, no phone opens a session
    /// for it, the phone forgot this computer, or no card is reported
    /// before the timeout.
    pub fn open_session(
        &mut self,
        pair_id: Option<PairId>,
        discovery_timeout: Duration,
    ) -> Result<RemoteSession, RemoteError> {
        let pair_id = match pair_id {
            Some(pair_id) => pair_id,
            None => self.selected().ok_or(RemoteError::NotPaired)?.pair_id,
        };
        let record = self
            .requester
            .store()
            .get(pair_id)
            .map_err(|_| RemoteError::NotPaired)?;
        let keys = PairingKeys::derive(record)?;
        let deadline = Instant::now() + discovery_timeout;
        let mut last = RemoteError::NotFound;
        while Instant::now() < deadline {
            for service in self.sessions_for(pair_id, &keys)? {
                let Ok(transport) = dial(
                    &service.endpoints,
                    STREAM_CANDIDATE_ID,
                    OPERATION_RECEIVE_DEADLINE,
                    &keys.session_preamble()?,
                ) else {
                    continue;
                };
                let mut session = match self.requester.connect(pair_id, transport) {
                    Ok(session) => session,
                    Err(SessionError::ClosedByPeer(CloseReason::ServiceWithdrawn)) => {
                        return Err(RemoteError::Withdrawn);
                    }
                    Err(SessionError::ClosedByPeer(CloseReason::PairingRevoked)) => {
                        return Err(RemoteError::RevokedByPhone);
                    }
                    Err(error) => {
                        last = RemoteError::Session(error);
                        continue;
                    }
                };
                let reported = match self.requester.await_card_status(&mut session) {
                    Ok(true) => Ok(true),
                    Ok(false) => self.requester.await_card_present(
                        &mut session,
                        deadline.saturating_duration_since(Instant::now()),
                    ),
                    Err(error) => Err(error),
                };
                match reported {
                    Ok(true) => return Ok(RemoteSession { session }),
                    Ok(false) => {
                        self.requester.disconnect(&mut session, CloseReason::Normal);
                        return Err(RemoteError::CardAbsent);
                    }
                    Err(SessionError::ClosedByPeer(CloseReason::ServiceWithdrawn)) => {
                        return Err(RemoteError::Withdrawn);
                    }
                    Err(SessionError::ClosedByPeer(CloseReason::PairingRevoked)) => {
                        return Err(RemoteError::RevokedByPhone);
                    }
                    Err(error) => {
                        last = RemoteError::Session(error);
                        continue;
                    }
                }
            }
        }
        Err(last)
    }

    /// Runs one operation on an open session.
    ///
    /// # Errors
    /// [`RemoteError`] when the phone reports no card, the operation cannot
    /// be admitted, or it ends without a result.
    pub fn execute_on(
        &mut self,
        session: &mut RemoteSession,
        operation: &CardOperation,
    ) -> Result<CardOperationResult, RemoteError> {
        if session.session.card_present() != Some(true) {
            return Err(RemoteError::CardAbsent);
        }
        let outcome =
            self.requester
                .execute(&mut session.session, operation, OPERATION_LIFETIME_MS);
        let withdrawn = withdrawn_by(
            Requester::<FilePairingStore, FileOperationJournal>::session_end(&session.session),
        );
        operation_result(outcome, withdrawn)
    }

    /// Closes a session deliberately; an already ended session is left
    /// as it ended.
    pub fn close_session(&mut self, mut session: RemoteSession) {
        self.requester
            .disconnect(&mut session.session, CloseReason::Complete);
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

    /// Reads the authentication certificate through the phone and caches it
    /// on the pairing.
    ///
    /// # Errors
    /// As [`Self::execute`], and [`RemoteError::Store`] when the cache write
    /// fails.
    pub fn refresh_auth_cert(
        &mut self,
        pair_id: PairId,
        discovery_timeout: Duration,
    ) -> Result<Vec<u8>, RemoteError> {
        let operation = CardOperation::ReadCertificate {
            kind: CertificateKind::Authentication,
        };
        let CardOperationResult::Certificate(der) =
            self.execute(Some(pair_id), &operation, discovery_timeout)?
        else {
            return Err(RemoteError::Outcome(Box::new(OperationOutcome::Rejected(
                None,
            ))));
        };
        let cached = der.clone();
        self.requester
            .store_mut()
            .update(pair_id, &mut |record| {
                record.auth_cert = Some(cached.clone())
            })
            .map_err(RemoteError::Store)?;
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
        AnnouncementCandidate, DiscoveryKey, DiscoveryRecord, InstanceName, PairId, RevocationKey,
        RevokedAnnouncement, RoutingKey, WithdrawalKey, WithdrawnRecord, discovery_epoch,
        withdrawal_counter,
    };

    use super::{
        AdmissionError, CardOperationResult, OperationOutcome, PairingKeys, RemoteError,
        StreamService, operation_result, sessions_for, unix_seconds,
    };

    const PAIR_ID: [u8; 16] = [0x22; 16];
    const PEER_PUBLIC: [u8; 32] = [0x44; 32];
    const MINE: [u8; 32] = [0x11; 32];
    const THEIRS: [u8; 32] = [0x33; 32];

    fn keys(local: [u8; 32]) -> PairingKeys {
        let pair_id = PairId::from_array(PAIR_ID);
        PairingKeys {
            discovery: DiscoveryKey::from_parts(pair_id, &local, &PEER_PUBLIC).unwrap(),
            routing: RoutingKey::from_parts(pair_id, &local, &PEER_PUBLIC).unwrap(),
            withdrawal: WithdrawalKey::from_parts(pair_id, &local, &PEER_PUBLIC).unwrap(),
            revocation: RevocationKey::from_parts(pair_id, &local, &PEER_PUBLIC).unwrap(),
        }
    }

    /// A session record on `instance` whose `revoked` entries name the
    /// pairing keyed by `key` (section 4.6 item 4).
    fn revoking(instance: &str, key: &RevocationKey) -> StreamService {
        let name = InstanceName::new(instance).unwrap();
        let candidate = AnnouncementCandidate {
            hint: key.hint(&name, discovery_epoch(unix_seconds())),
            last_used_ms: 1,
        };
        let announcement = RevokedAnnouncement::assemble(&[candidate], |bytes| {
            getrandom::fill(bytes).map_err(|_| refineid_rapp::RevocationError::RandomUnavailable)
        })
        .unwrap();
        service(
            instance,
            &DiscoveryRecord::assemble(&[], Some(announcement)).txt_entries(),
        )
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

    #[test]
    fn a_device_type_introduction_yields_to_the_host_name() {
        assert_eq!(
            super::custodian_name("iPhone", "alpha-phone"),
            "alpha-phone"
        );
        assert_eq!(super::custodian_name("iPhone", ""), "iPhone");
        assert_eq!(
            super::custodian_name("Alpha Phone", "Android-3"),
            "Alpha Phone"
        );
    }

    fn service(instance: &str, txt: &[(&str, String)]) -> StreamService {
        StreamService {
            instance: instance.to_owned(),
            endpoints: vec!["192.0.2.10:47110".to_owned()],
            host: String::new(),
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
    fn a_revocation_for_the_pairing_is_the_phones_word() {
        let mine = keys(MINE);
        let announced = sessions_for(
            &mine,
            vec![
                session("refineid-unhinted", None),
                revoking("refineid-forgot", &mine.revocation),
            ],
        );
        assert_eq!(announced, Err(RemoteError::RevokedByPhone));
    }

    #[test]
    fn another_pairings_revocation_is_ignored() {
        let mine = keys(MINE);
        let dialable = sessions_for(
            &mine,
            vec![
                session("refineid-unhinted", None),
                revoking("refineid-other", &keys(THEIRS).revocation),
            ],
        )
        .unwrap();
        assert_eq!(names(&dialable), ["refineid-unhinted", "refineid-other"]);
    }

    #[test]
    fn named_custodians_come_first_and_foreign_ones_are_never_dialed() {
        let mine = keys(MINE);
        let epoch = discovery_epoch(unix_seconds());
        let ordered = sessions_for(
            &mine,
            vec![
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
                vec![
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
            vec![
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
            vec![
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
                vec![withdrawn("refineid-gone", &mine.withdrawal), stale]
            )
            .map(|found| found.len()),
            Err(RemoteError::Withdrawn)
        );
    }

    #[test]
    fn a_withdrawn_session_reports_the_withdrawal_unless_a_result_arrived() {
        let certificate = CardOperationResult::Certificate(vec![0x30, 0x00]);
        assert_eq!(
            operation_result(Ok(OperationOutcome::Completed(certificate.clone())), true),
            Ok(certificate)
        );
        assert_eq!(
            operation_result(Ok(OperationOutcome::Cancelled), true),
            Err(RemoteError::Withdrawn)
        );
        assert_eq!(
            operation_result(Err(AdmissionError::SessionNotHealthy), true),
            Err(RemoteError::Withdrawn)
        );
        assert_eq!(
            operation_result(Ok(OperationOutcome::Cancelled), false),
            Err(RemoteError::Outcome(Box::new(OperationOutcome::Cancelled)))
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
}
