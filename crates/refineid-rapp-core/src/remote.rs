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

use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use crate::addresses;

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
use crate::session_lock::{LockError, SessionLock, ceremony_lock_path, session_lock_path};
use crate::store::PairingRecord;
use crate::store::{OperationJournal, PairingDisposition, PairingStore, StoreError};
use crate::stream::{
    DiscoveryMode, HintMatch, RoutingPreamble, STREAM_CANDIDATE_ID, StreamService, browse,
    browse_stream_services, dial,
};
use crate::transport::FrameTransport;
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
/// The lifetime each request asks for unless the caller bounds it
/// (section 8.2.1).
const OPERATION_LIFETIME: Duration = Duration::from_millis(120_000);

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

/// Runs one operation on an open session of any transport, asking the
/// phone to let it expire `lifetime` after the request (section 8.2.1);
/// the runner behind [`RemoteReader::execute_on_with_lifetime`].
///
/// # Errors
/// [`RemoteError`] when the phone reports no card, the operation cannot
/// be admitted, or it ends without a result.
pub fn execute_on_session<Store, Journal, Transport>(
    requester: &mut Requester<Store, Journal>,
    session: &mut Session<Transport>,
    operation: &CardOperation,
    lifetime: Duration,
) -> Result<CardOperationResult, RemoteError>
where
    Store: PairingStore,
    Journal: OperationJournal,
    Transport: FrameTransport,
{
    if session.card_present() != Some(true) {
        return Err(RemoteError::CardAbsent);
    }
    let outcome = requester.execute(session, operation, lifetime_ms(lifetime));
    let withdrawn = withdrawn_by(Requester::<Store, Journal>::session_end(session));
    operation_result(outcome, withdrawn)
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
            Self::Busy => {
                f.write_str("the phone session is held by another program on this computer")
            }
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

    /// Opens the default stores as this computer without sweeping the
    /// pairing store, for a program that reads the records another
    /// program keeps.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when a store cannot be opened.
    pub fn open_local_without_sweep() -> Result<Self, RemoteError> {
        let store = FilePairingStore::open_without_sweep(&FilePairingStore::default_directory())
            .map_err(RemoteError::Store)?;
        let journal = FileOperationJournal::open_default().map_err(RemoteError::Store)?;
        Ok(Self::with_stores(
            &local_host_name(),
            local_platform(),
            store,
            journal,
        ))
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

    /// The paired phone: the one pairing that can open a session. A new
    /// pairing supersedes the one before it, so there is at most one.
    #[must_use]
    pub fn phone(&self) -> Option<PairSummary> {
        self.pairs().into_iter().find(PairSummary::usable)
    }

    /// Forgets the paired phone.
    ///
    /// # Errors
    /// [`RemoteError::NotPaired`] when no phone is paired, and
    /// [`RemoteError::Store`] when the record cannot be removed.
    pub fn forget(&mut self) -> Result<(), RemoteError> {
        let pair_id = self.phone().ok_or(RemoteError::NotPaired)?.pair_id;
        self.requester
            .store_mut()
            .remove(pair_id)
            .map_err(RemoteError::Store)?;
        self.requester
            .journal_mut()
            .forget_pair(pair_id)
            .map_err(RemoteError::Store)
    }

    /// Revokes every usable pairing but `kept`, so one phone is paired.
    fn supersede_others(&mut self, kept: PairId) {
        let older: Vec<PairId> = self
            .pairs()
            .into_iter()
            .filter(|pair| pair.usable() && pair.pair_id != kept)
            .map(|pair| pair.pair_id)
            .collect();
        for pair_id in older {
            self.requester.revoke_locally(pair_id);
        }
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
                        Ok(session) => {
                            self.remember_address(pair_id, &service);
                            session
                        }
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
    /// One ceremony runs at a time on this computer: the store's pairing
    /// lock is held until this returns.
    ///
    /// # Errors
    /// [`RemoteError::Pairing`] for a malformed or mistyped code and other
    /// pairing failures, [`RemoteError::NotFound`] when no phone in a
    /// pairing ceremony answered, [`RemoteError::Busy`] when another
    /// program is pairing, and [`RemoteError::Store`] when the record of a
    /// completed ceremony cannot be written.
    pub fn pair_with_code(
        &mut self,
        code: &str,
        discovery_timeout: Duration,
    ) -> Result<PairSummary, RemoteError> {
        if crate::offer::normalize_pairing_code(code).is_none() {
            return Err(RemoteError::Pairing(PairingError::InvalidCode));
        }
        let _ceremony = take_lock(&ceremony_lock_path(self.requester.store().directory()))?;
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
                        self.supersede_others(pair_id);
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

    /// Listens once for the phone holding `pair_id` without dialing it,
    /// applying what it announces: a revocation hint naming the pairing
    /// (RAPP v26.10.18 section 4.6 item 3) revokes it here, under the
    /// pairing's lock. Returns whether the phone's session record was in
    /// sight.
    ///
    /// # Errors
    /// [`RemoteError::NotPaired`] when no record names `pair_id`,
    /// [`RemoteError::Busy`] when another program holds the pairing's
    /// session and so hears the phone itself,
    /// [`RemoteError::RevokedByPhone`] when the phone announced that it
    /// forgot this computer, [`RemoteError::Withdrawn`] when it withdrew
    /// its service.
    pub fn observe(&mut self, pair_id: PairId) -> Result<bool, RemoteError> {
        let record = self
            .requester
            .store()
            .get(pair_id)
            .map_err(|_| RemoteError::NotPaired)?;
        let keys = PairingKeys::derive(record)?;
        // The listening needs no lock; recording the phone's word does,
        // and the holder of the session hears the phone itself, so an
        // observer that cannot take the lock records nothing.
        match sessions_for(&keys, self.browse_for(pair_id)) {
            Err(RemoteError::RevokedByPhone) => {
                let _lock = take_lock(&session_lock_path(
                    self.requester.store().directory(),
                    pair_id,
                ))?;
                self.requester.revoke_announced_by_peer(pair_id);
                Err(RemoteError::RevokedByPhone)
            }
            Ok(services) => Ok(!services.is_empty()),
            Err(error) => Err(error),
        }
    }

    /// The session custodians worth dialing for `pair_id`, applying the
    /// phone's announcements: a withdrawal ends the search, and a
    /// revocation revokes the pairing here before reporting it.
    fn sessions_for(
        &mut self,
        pair_id: PairId,
        keys: &PairingKeys,
    ) -> Result<Vec<StreamService>, RemoteError> {
        match sessions_for(keys, self.browse_for(pair_id)) {
            Err(RemoteError::RevokedByPhone) => {
                self.requester.revoke_announced_by_peer(pair_id);
                Err(RemoteError::RevokedByPhone)
            }
            other => other,
        }
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
    /// A consumer that offers the phone's identity keeps the session for
    /// as long as it offers it: the offer is withdrawn with the session.
    /// The pairing's lock is held from here until the session is dropped,
    /// so one program at a time on this computer holds the phone.
    ///
    /// # Errors
    /// [`RemoteError`] when no pairing matches, another program holds the
    /// pairing's session, no phone opens a session for it, the phone
    /// forgot this computer, or no card is reported before the timeout.
    pub fn open_session(
        &mut self,
        pair_id: Option<PairId>,
        discovery_timeout: Duration,
    ) -> Result<RemoteSession, RemoteError> {
        let pair_id = match pair_id {
            Some(pair_id) => pair_id,
            None => self.phone().ok_or(RemoteError::NotPaired)?.pair_id,
        };
        let record = self
            .requester
            .store()
            .get(pair_id)
            .map_err(|_| RemoteError::NotPaired)?;
        let keys = PairingKeys::derive(record)?;
        let lock = take_lock(&session_lock_path(
            self.requester.store().directory(),
            pair_id,
        ))?;
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
                    Ok(session) => {
                        self.remember_address(pair_id, &service);
                        session
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
                    Ok(true) => {
                        return Ok(RemoteSession {
                            session,
                            _lock: lock,
                        });
                    }
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
    /// expire `lifetime` after the request (section 8.2.1).
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
        execute_on_session(
            &mut self.requester,
            &mut session.session,
            operation,
            lifetime,
        )
    }

    /// Sends one liveness ping on an open session and waits for its echo,
    /// recording any notice the phone sends meanwhile.
    ///
    /// # Errors
    /// [`RemoteError::Withdrawn`] or [`RemoteError::RevokedByPhone`] when
    /// the phone closed the session with that reason, and
    /// [`RemoteError::Session`] when the session is not healthy or the
    /// transport was lost.
    pub fn check_liveness(&mut self, session: &mut RemoteSession) -> Result<(), RemoteError> {
        match self.requester.check_liveness(&mut session.session) {
            Ok(()) => Ok(()),
            Err(SessionError::ClosedByPeer(CloseReason::ServiceWithdrawn)) => {
                Err(RemoteError::Withdrawn)
            }
            Err(SessionError::ClosedByPeer(CloseReason::PairingRevoked)) => {
                Err(RemoteError::RevokedByPhone)
            }
            Err(error) => Err(RemoteError::Session(error)),
        }
    }

    /// Closes a session deliberately; an already ended session is left
    /// as it ended.
    pub fn close_session(&mut self, mut session: RemoteSession) {
        self.requester
            .disconnect(&mut session.session, CloseReason::Complete);
    }

    /// Closes `session` telling the phone the pairing was revoked here
    /// (RAPP v26.10.18 section 4.6 item 1), for a session holder that
    /// finds the record forgotten by another program on this computer.
    pub fn close_session_revoked(&mut self, mut session: RemoteSession) {
        self.requester
            .disconnect(&mut session.session, CloseReason::PairingRevoked);
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
    /// opened and closed for it, and caches it on the pairing.
    ///
    /// # Errors
    /// As [`Self::execute`], and [`RemoteError::Store`] when the cache write
    /// fails.
    pub fn refresh_auth_cert(
        &mut self,
        pair_id: PairId,
        discovery_timeout: Duration,
    ) -> Result<Vec<u8>, RemoteError> {
        let mut session = self.open_session(Some(pair_id), discovery_timeout)?;
        let result = self.refresh_auth_cert_on(&mut session);
        self.close_session(session);
        result
    }

    /// Reads the authentication certificate through the phone on an open
    /// session and caches it on the session's pairing. Whichever program
    /// holds the session fetches a missing certificate this way; the write
    /// replaces the record file whole, under the session's lock.
    ///
    /// # Errors
    /// As [`Self::execute_on`], and [`RemoteError::Store`] when the cache
    /// write fails.
    pub fn refresh_auth_cert_on(
        &mut self,
        session: &mut RemoteSession,
    ) -> Result<Vec<u8>, RemoteError> {
        let operation = CardOperation::ReadCertificate {
            kind: CertificateKind::Authentication,
        };
        let CardOperationResult::Certificate(der) = self.execute_on(session, &operation)? else {
            return Err(RemoteError::Outcome(Box::new(OperationOutcome::Rejected(
                None,
            ))));
        };
        self.cache_auth_cert(session.session.pair_id(), &der)?;
        Ok(der)
    }

    /// Writes `der` as the pairing's cached authentication certificate.
    fn cache_auth_cert(&mut self, pair_id: PairId, der: &[u8]) -> Result<(), RemoteError> {
        self.requester
            .store_mut()
            .update(pair_id, &mut |record| record.auth_cert = Some(der.to_vec()))
            .map_err(RemoteError::Store)
    }

    /// Drops the cached authentication certificate of `pair_id`, so the
    /// next session reads the card for it again: for a signature that
    /// did not verify against the cached certificate, which says the
    /// card on the phone is not the one cached.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the record cannot be rewritten.
    pub fn forget_auth_cert(&mut self, pair_id: PairId) -> Result<(), RemoteError> {
        self.requester
            .store_mut()
            .update(pair_id, &mut |record| record.auth_cert = None)
            .map_err(RemoteError::Store)
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

    use std::time::Duration;

    use super::{
        AdmissionError, CardOperationResult, OperationOutcome, PairingKeys, RemoteError,
        RemoteReader, StreamService, lifetime_ms, operation_result, sessions_for, unix_seconds,
    };
    use crate::file_journal::FileOperationJournal;
    use crate::file_store::FilePairingStore;
    use crate::session_lock::{SessionLock, ceremony_lock_path, session_lock_path};
    use crate::store::{PairingDisposition, PairingRecord, PairingStore as _};

    const PAIR_ID: [u8; 16] = [0x22; 16];
    const PEER_PUBLIC: [u8; 32] = [0x44; 32];
    const MINE: [u8; 32] = [0x11; 32];
    const THEIRS: [u8; 32] = [0x33; 32];

    fn scratch() -> std::path::PathBuf {
        let mut name = [0u8; 8];
        getrandom::fill(&mut name).unwrap();
        let suffix: String = name.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("refineid-rapp-remote-{suffix}"))
    }

    /// A reader over a store in `directory` holding one paired record.
    fn reader_with_pairing(directory: &std::path::Path) -> RemoteReader {
        let mut store = FilePairingStore::open(directory).unwrap();
        store
            .insert(PairingRecord {
                pair_id: PairId::from_array(PAIR_ID),
                local_private: zeroize::Zeroizing::new(MINE.to_vec()),
                local_public: vec![0x22; 32],
                peer_public: PEER_PUBLIC.to_vec(),
                granted_profiles: vec![crate::profiles::PROFILE_CARD_STATUS.to_owned()],
                grants_hash: [0x44; 32],
                peer_display_name: "Alpha Phone".into(),
                peer_platform: "iOS".into(),
                disposition: PairingDisposition::Paired,
                peer_initiated_termination: false,
                candidate_failures: 0,
                auth_cert: None,
                signature_cert: None,
                root_ca: None,
                intermediate_ca: None,
            })
            .unwrap();
        let journal = FileOperationJournal::open(&directory.join("journal")).unwrap();
        RemoteReader::with_stores("alpha-desk", "Linux", store, journal)
    }

    #[test]
    fn observing_listens_without_the_lock_and_names_an_unknown_pairing() {
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        let held = SessionLock::acquire(&session_lock_path(&directory, pair_id)).unwrap();
        // Listening takes no lock: with the session held elsewhere and no
        // phone announcing this pairing on the test network, not seen.
        assert_eq!(reader.observe(pair_id), Ok(false));
        drop(held);
        assert_eq!(reader.observe(pair_id), Ok(false));
        assert_eq!(
            reader.observe(PairId::from_array([9; 16])).err(),
            Some(RemoteError::NotPaired)
        );
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
        // Released: the search runs and ends on its deadline instead.
        assert_eq!(
            reader.open_session(Some(pair_id), Duration::ZERO).err(),
            Some(RemoteError::NotFound)
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn two_readers_on_one_store_contend_for_the_pairing() {
        let directory = scratch();
        let mut first = reader_with_pairing(&directory);
        let mut second = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        // The first reader searches for a phone for a second, finding none,
        // and holds the pairing's lock for the whole search.
        let (started, searching) = std::sync::mpsc::channel();
        let searcher = std::thread::spawn(move || {
            started.send(()).unwrap();
            first.open_session(Some(pair_id), Duration::from_secs(1))
        });
        searching.recv().unwrap();
        // The second reader, asking during that search, is told the phone
        // is busy. The lock is taken a moment after the start signal, so
        // the ask is repeated until it meets the search, within a bound
        // well inside the search.
        let bound = std::time::Instant::now() + Duration::from_millis(800);
        let mut seen = None;
        while std::time::Instant::now() < bound {
            match second.open_session(Some(pair_id), Duration::ZERO) {
                Err(RemoteError::Busy) => {
                    seen = Some(RemoteError::Busy);
                    break;
                }
                other => seen = other.err(),
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(seen, Some(RemoteError::Busy));
        assert_eq!(searcher.join().unwrap().err(), Some(RemoteError::NotFound));
        assert_eq!(
            second.open_session(Some(pair_id), Duration::ZERO).err(),
            Some(RemoteError::NotFound)
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_ceremony_held_by_another_program_makes_pairing_busy() {
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let held = SessionLock::acquire(&ceremony_lock_path(&directory)).unwrap();
        assert_eq!(
            reader.pair_with_code("7KX4M9", Duration::ZERO).err(),
            Some(RemoteError::Busy)
        );
        drop(held);
        assert_eq!(
            reader.pair_with_code("7KX4M9", Duration::ZERO).err(),
            Some(RemoteError::NotFound)
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_cached_certificate_replaces_the_record_file_and_survives_reopening() {
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        reader
            .cache_auth_cert(pair_id, &[0x30, 0x03, 0x02, 0x01, 0x07])
            .unwrap();
        let record_path = directory.join("22222222222222222222222222222222.pair");
        assert!(record_path.exists());
        assert!(!record_path.with_extension("tmp").exists());
        let reopened = reader_with_pairing(&directory.join("other"));
        drop(reopened);
        let store = FilePairingStore::open_without_sweep(&directory).unwrap();
        let summary = RemoteReader::with_stores(
            "alpha-desk",
            "Linux",
            store,
            FileOperationJournal::open(&directory.join("journal")).unwrap(),
        )
        .pairs();
        assert_eq!(
            summary[0].auth_cert.as_deref(),
            Some(&[0x30, 0x03, 0x02, 0x01, 0x07][..])
        );
        assert_eq!(
            reader
                .cache_auth_cert(PairId::from_array([0x77; 16]), &[])
                .err(),
            Some(RemoteError::Store(crate::store::StoreError::Unknown))
        );
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
        assert_eq!(lifetime_ms(Duration::from_secs(90)), 90_000);
        assert_eq!(lifetime_ms(Duration::from_micros(1_500)), 1);
        assert_eq!(lifetime_ms(Duration::MAX), u64::MAX);
    }

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
