//! The workstation's remote card reader: pairing by code and sessions to
//! the paired phone, over the stream tier.
//!
//! This is the surface the CLI, the GUI, the TLS client, and the PKCS#11
//! module use. Pairing browses for a custodian in `mode=pairing`; a session
//! browses for custodians in `mode=session`, dials each, and opens with a
//! routing value that is fresh per dial and keyed by the pairing's static
//! agreement. A custodian that does not hold the pairing closes the
//! connection, and the next one is tried. A withdrawn record announcing the
//! pairing, or a session close carrying `service_withdrawn`, ends the
//! search at once; the withdrawn instance is never dialed, and the pairing
//! is dialed again only when a session record on another instance names it.
//!
//! The phone's word on the pairing comes only inside a session: a close
//! carrying `pairing_revoked` revokes the pairing here at once (RAPP
//! v26.10.22 section 4.6 item 4). A pairing forgotten here is told to the
//! phone the same way, by the session that holds it or as the first
//! message of the next one (items 1 and 2).
//!
//! An open session reports which card the phone holds, if any (section
//! 8.4); an operation is sent only on a session that reports one, and the
//! phone's identity is offered only on a certificate whose fingerprint the
//! phone confirmed on a session.

use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use crate::addresses;

use crate::engine::{
    AdmissionError, OperationOutcome, PairingError, Requester, RequesterConfig, Session,
    SessionEnd, SessionError, current_time_ms,
};
use crate::file_store::FilePairingStore;
use crate::ids::{CertificateFingerprint, PairId};
use crate::message::{CardStatusMessage, CloseReason};
use crate::operations::{CardOperation, CardOperationResult, CertificateKind};
use crate::session_lock::{LockError, SessionLock, ceremony_lock_path, session_lock_path};
use crate::store::{PairingRecord, PairingStore, PeerIntroduction, StoreError};
use crate::stream::{
    DiscoveryMode, HintMatch, RoutingPreamble, STREAM_CANDIDATE_ID, StreamService, browse,
    browse_stream_services, dial,
};
use crate::transport::FrameTransport;
use crate::transport::TcpFrameTransport;
use refineid_rapp::{
    DiscoveryKey, PairingState, ProfileName, RoutingKey, TransportProfile, WithdrawalKey,
};

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
/// How long a session handshake waits for each custodian message.
const SESSION_RECEIVE_DEADLINE: Duration = Duration::from_secs(30);
/// How long a new session waits for the phone's first card report, which
/// it sends right after `session.ready` (section 8.4 item 1), when the
/// discovery time is spent.
const CARD_REPORT_WAIT: Duration = Duration::from_secs(5);
/// The lifetime each request asks for unless the caller bounds it
/// (section 8.1 item 2).
const OPERATION_LIFETIME: Duration = Duration::from_millis(120_000);

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
    services: Vec<StreamService>,
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
        Some(SessionEnd::PeerClose(CloseReason::ServiceWithdrawn)) => Some(RemoteError::Withdrawn),
        Some(SessionEnd::PeerClose(CloseReason::PairingRevoked)) => {
            Some(RemoteError::RevokedByPhone)
        }
        _ => None,
    }
}

/// A session error as the reader reports it: the phone's withdrawal and
/// its revocation by name, anything else as it came.
const fn session_error(error: SessionError) -> RemoteError {
    match error {
        SessionError::ClosedByPeer(CloseReason::ServiceWithdrawn) => RemoteError::Withdrawn,
        SessionError::ClosedByPeer(CloseReason::PairingRevoked) => RemoteError::RevokedByPhone,
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
        return Err(RemoteError::CardAbsent);
    }
    let outcome = requester.execute(session, operation, lifetime_ms(lifetime));
    operation_result(outcome, ended_by(session.end()))
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
    /// The phone told this computer that it forgot it; the pairing is
    /// revoked here and the user pairs again.
    RevokedByPhone,
    /// The phone opened the session but reports no card it can serve.
    CardAbsent,
    /// The certificate read from the card is not the one the phone
    /// reports serving: the card changed during the read.
    CardChanged,
    /// The system random source failed.
    RandomUnavailable,
    /// Pairing failed.
    Pairing(PairingError),
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
            Self::Withdrawn => f.write_str("the phone turned remote card access off"),
            Self::RevokedByPhone => f.write_str("the phone forgot this computer; pair it again"),
            Self::CardAbsent => f.write_str("the phone has no card on it"),
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
    pub granted_profiles: Vec<ProfileName>,
    /// The cached authentication certificate, if read.
    pub auth_cert: Option<Vec<u8>>,
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

/// The workstation's remote reader over its durable pairing store.
#[derive(Debug)]
pub struct RemoteReader {
    requester: Requester<FilePairingStore>,
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
            Some(CardStatusMessage::Present(fingerprint)) => Some(fingerprint),
            Some(CardStatusMessage::Absent) | None => None,
        }
    }

    /// The pairing this session serves.
    #[must_use]
    pub const fn pair_id(&self) -> PairId {
        self.session.pair_id()
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

    /// Opens the default store as this computer without sweeping it, for
    /// a program that reads the records another program keeps.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the store cannot be opened.
    pub fn open_local_without_sweep() -> Result<Self, RemoteError> {
        let store = FilePairingStore::open_without_sweep(&FilePairingStore::default_directory())
            .map_err(RemoteError::Store)?;
        Ok(Self::with_store(
            &local_host_name(),
            local_platform(),
            store,
        ))
    }

    /// Opens the per-user pairing store.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the store cannot be opened.
    pub fn open(display_name: &str, platform: &str) -> Result<Self, RemoteError> {
        let store = FilePairingStore::open_default().map_err(RemoteError::Store)?;
        let mut reader = Self::with_store(display_name, platform, store);
        reader.sweep();
        Ok(reader)
    }

    /// Uses `store` for pairings, as it stands.
    #[must_use]
    pub fn with_store(display_name: &str, platform: &str, store: FilePairingStore) -> Self {
        Self {
            requester: Requester::new(
                RequesterConfig {
                    display_name: display_name.to_owned(),
                    platform: platform.to_owned(),
                },
                store,
            ),
        }
    }

    /// The owning program's sweep of the store: forgotten records that
    /// waited out their notice window lose their keys (section 4.6 item
    /// 3), and, while no pairing ceremony runs on this computer, records a
    /// past ceremony left unconfirmed are revoked (section 4.3 item 4). A
    /// running ceremony's record is unconfirmed until its phone answers.
    fn sweep(&mut self) {
        self.requester.expire_revocation_notices(current_time_ms());
        if let Ok(_ceremony) = take_lock(&ceremony_lock_path(self.requester.store().directory())) {
            self.requester.revoke_unconfirmed_pairings();
        }
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
                peer_display_name: record.peer().display_name.clone(),
                peer_platform: record.peer().platform.clone(),
                granted_profiles: record.pairing().profiles().to_vec(),
                auth_cert: record.auth_cert().map(<[u8]>::to_vec),
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

    /// Forgets the paired phone (section 4.6): the pairing serves nothing
    /// from now on, and the phone is told by the program holding its
    /// session, or on the next session one of
    /// [`Self::deliver_revocation_notices`] opens.
    ///
    /// # Errors
    /// [`RemoteError::NotPaired`] when no phone is paired, and
    /// [`RemoteError::Store`] when the record cannot be rewritten.
    pub fn forget(&mut self) -> Result<(), RemoteError> {
        let pair_id = self.phone().ok_or(RemoteError::NotPaired)?.pair_id;
        self.requester
            .forget(pair_id, current_time_ms())
            .map_err(RemoteError::Store)
    }

    /// Tells each phone this computer forgot and that is in sight now
    /// (section 4.6 item 2): one session per forgotten pairing, whose first
    /// message is the `pairing_revoked` close, after which the pairing's
    /// key is destroyed. A pairing whose session another program holds is
    /// left to that program, which tells the phone in session. Returns how
    /// many phones were told.
    pub fn deliver_revocation_notices(&mut self) -> usize {
        let forgotten: Vec<PairId> = self
            .pairs()
            .into_iter()
            .filter(|pair| pair.state == PairingState::Revoking)
            .map(|pair| pair.pair_id)
            .collect();
        forgotten
            .into_iter()
            .filter(|pair_id| self.deliver_revocation_notice(*pair_id))
            .count()
    }

    /// Tells the phone holding the forgotten `pair_id` that this computer
    /// forgot it, when one is in sight; whether it was told.
    fn deliver_revocation_notice(&mut self, pair_id: PairId) -> bool {
        let Ok(record) = self.requester.store().get(pair_id) else {
            return false;
        };
        let Ok(keys) = PairingKeys::derive(record) else {
            return false;
        };
        let Ok(_lock) = take_lock(&session_lock_path(
            self.requester.store().directory(),
            pair_id,
        )) else {
            return false;
        };
        let Ok(services) = sessions_for(&keys, self.browse_for(pair_id)) else {
            return false;
        };
        for service in services {
            let Ok(preamble) = keys.session_preamble() else {
                return false;
            };
            let Ok(transport) = dial(
                &service.endpoints,
                STREAM_CANDIDATE_ID,
                SESSION_RECEIVE_DEADLINE,
                &preamble,
            ) else {
                continue;
            };
            if self
                .requester
                .send_revocation_notice(pair_id, transport)
                .is_ok()
            {
                return true;
            }
        }
        false
    }

    /// Forgets every usable pairing but `kept`, so one phone is paired.
    fn supersede_others(&mut self, kept: PairId) {
        let older: Vec<PairId> = self
            .pairs()
            .into_iter()
            .filter(|pair| pair.usable() && pair.pair_id != kept)
            .map(|pair| pair.pair_id)
            .collect();
        for pair_id in older {
            let _ = self.requester.forget(pair_id, current_time_ms());
        }
    }

    /// Pairs with the phone showing `code`, browsing for it until
    /// `discovery_timeout` passes.
    ///
    /// Every profile the offer names is requested and granted; the phone
    /// decides what it grants and the sets must agree.
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
                        let _ = self.requester.store_mut().update(pair_id, &mut |record| {
                            let peer = PeerIntroduction {
                                display_name: custodian_name(&record.peer().display_name, &host),
                                platform: record.peer().platform.clone(),
                            };
                            Some(record.with_peer(peer))
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

    /// Listens once for the phone holding `pair_id` without dialing it.
    /// Returns whether a session record that may serve the pairing was in
    /// sight.
    ///
    /// # Errors
    /// [`RemoteError::NotPaired`] when no usable record names `pair_id`,
    /// and [`RemoteError::Withdrawn`] when the phone withdrew its service.
    pub fn observe(&self, pair_id: PairId) -> Result<bool, RemoteError> {
        let record = self
            .requester
            .store()
            .get(pair_id)
            .map_err(|_| RemoteError::NotPaired)?;
        let keys = PairingKeys::derive(record)?;
        sessions_for(&keys, self.browse_for(pair_id)).map(|services| !services.is_empty())
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
        if record.state() != PairingState::PairedDisconnected {
            return Err(RemoteError::NotPaired);
        }
        let keys = PairingKeys::derive(record)?;
        let lock = take_lock(&session_lock_path(
            self.requester.store().directory(),
            pair_id,
        ))?;
        let deadline = Instant::now() + discovery_timeout;
        let mut last = RemoteError::NotFound;
        while Instant::now() < deadline {
            for service in sessions_for(&keys, self.browse_for(pair_id))? {
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
                    Err(
                        error @ SessionError::ClosedByPeer(
                            CloseReason::ServiceWithdrawn | CloseReason::PairingRevoked,
                        ),
                    ) => return Err(session_error(error)),
                    Err(error) => {
                        last = RemoteError::Session(error);
                        continue;
                    }
                };
                let wait = deadline
                    .saturating_duration_since(Instant::now())
                    .max(CARD_REPORT_WAIT);
                match self.requester.await_card_present(&mut session, wait) {
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
                    Err(
                        error @ SessionError::ClosedByPeer(
                            CloseReason::ServiceWithdrawn | CloseReason::PairingRevoked,
                        ),
                    ) => return Err(session_error(error)),
                    Err(error) => {
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
        execute_on_session(
            &mut self.requester,
            &mut session.session,
            operation,
            lifetime,
        )
    }

    /// Serves an open session for `wait`: answers the phone's pings,
    /// records its card reports, and keeps the liveness rule of section
    /// 8.3.
    ///
    /// # Errors
    /// [`RemoteError::Withdrawn`] or [`RemoteError::RevokedByPhone`] when
    /// the phone closed the session with that reason, and
    /// [`RemoteError::Session`] when the session ended otherwise.
    pub fn service(
        &mut self,
        session: &mut RemoteSession,
        wait: Duration,
    ) -> Result<(), RemoteError> {
        self.requester
            .service(&mut session.session, wait)
            .map_err(session_error)
    }

    /// Closes a session deliberately; an already ended session is left
    /// as it ended.
    pub fn close_session(&mut self, mut session: RemoteSession) {
        self.requester
            .disconnect(&mut session.session, CloseReason::Complete);
    }

    /// Closes `session` telling the phone that this computer forgot the
    /// pairing (section 4.6 item 1), for the session holder that finds the
    /// record forgotten by another program on this computer; once the
    /// close is sent, the pairing's key is destroyed.
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
    /// opened and closed for it, and caches it on the pairing.
    ///
    /// # Errors
    /// As [`Self::confirmed_auth_cert`], and as [`Self::open_session`].
    pub fn refresh_auth_cert(
        &mut self,
        pair_id: PairId,
        discovery_timeout: Duration,
    ) -> Result<Vec<u8>, RemoteError> {
        let mut session = self.open_session(Some(pair_id), discovery_timeout)?;
        let result = self.confirmed_auth_cert(&mut session);
        self.close_session(session);
        result
    }

    /// The authentication certificate of the card the phone reports
    /// serving on `session` (section 8.4 item 2): the cached one when its
    /// fingerprint is the reported one, and otherwise the card's, read
    /// afresh on the session, checked against the report, and cached in
    /// place of the old one. Whichever program holds the session caches
    /// it; the write replaces the record file whole, under the session's
    /// lock.
    ///
    /// # Errors
    /// [`RemoteError::CardAbsent`] while the phone reports no card,
    /// [`RemoteError::CardChanged`] when the certificate read is not the
    /// one reported, as [`Self::execute_on`] for the read, and
    /// [`RemoteError::Store`] when the cache write fails.
    pub fn confirmed_auth_cert(
        &mut self,
        session: &mut RemoteSession,
    ) -> Result<Vec<u8>, RemoteError> {
        let reported = session.card_fingerprint().ok_or(RemoteError::CardAbsent)?;
        let pair_id = session.pair_id();
        let cached = self
            .requester
            .store()
            .get(pair_id)
            .map_err(RemoteError::Store)?
            .auth_cert()
            .map(<[u8]>::to_vec);
        if let Some(cached) = cached
            && CertificateFingerprint::of_certificate(&cached) == reported
        {
            return Ok(cached);
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
        self.cache_auth_cert(pair_id, &der)?;
        Ok(der)
    }

    /// Writes `der` as the pairing's cached authentication certificate.
    fn cache_auth_cert(&mut self, pair_id: PairId, der: &[u8]) -> Result<(), RemoteError> {
        self.requester
            .store_mut()
            .update(pair_id, &mut |record| {
                Some(record.with_auth_cert(Some(der.to_vec())))
            })
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
            .update(pair_id, &mut |record| Some(record.with_auth_cert(None)))
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
        AnnouncementCandidate, DiscoveryKey, InstanceName, PairId, PairingState, ResultError,
        RoutingKey, WithdrawalKey, WithdrawnRecord, X25519_KEY_SIZE, discovery_epoch,
        withdrawal_counter,
    };

    use std::time::Duration;

    use super::{
        AdmissionError, CardOperationResult, OperationOutcome, PairingKeys, RemoteError,
        RemoteReader, StreamService, current_time_ms, lifetime_ms, operation_result, sessions_for,
        unix_seconds,
    };
    use crate::file_store::{FilePairingStore, path_for};
    use crate::session_lock::{SessionLock, ceremony_lock_path, session_lock_path};
    use crate::store::PairingStore as _;
    use crate::store::fixtures::record;

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
        RemoteReader::with_store("alpha-desk", "Linux", store)
    }

    /// A reader over a store in `directory` holding one paired record.
    fn reader_with_pairing(directory: &std::path::Path) -> RemoteReader {
        reader_with(directory, vec![record(PairId::from_array(PAIR_ID))])
    }

    #[test]
    fn observing_listens_without_the_lock_and_names_an_unknown_pairing() {
        let directory = scratch();
        let reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        let held = SessionLock::acquire(&session_lock_path(&directory, pair_id)).unwrap();
        // Listening takes no lock: with the session held elsewhere and no
        // phone announcing this pairing on the test network, not seen.
        assert_eq!(reader.observe(pair_id), Ok(false));
        drop(held);
        assert_eq!(reader.observe(pair_id), Ok(false));
        assert_eq!(
            reader.observe(PairId::from_array(UNKNOWN_PAIR_ID)).err(),
            Some(RemoteError::NotPaired)
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_forgotten_phone_serves_nothing_and_keeps_its_key_for_the_close() {
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        reader.forget().unwrap();
        assert_eq!(reader.phone(), None);
        assert_eq!(reader.forget(), Err(RemoteError::NotPaired));
        let summary = reader.pairs().into_iter().next().unwrap();
        assert_eq!(summary.state, PairingState::Revoking);
        assert!(!summary.usable());
        assert_eq!(
            reader.open_session(Some(pair_id), Duration::ZERO).err(),
            Some(RemoteError::NotPaired)
        );
        // No phone is in sight on the test network: the record waits for
        // the next session with its key.
        assert_eq!(reader.deliver_revocation_notices(), 0);
        let store = FilePairingStore::open_without_sweep(&directory).unwrap();
        let kept = store.get(pair_id).unwrap();
        assert_eq!(kept.state(), PairingState::Revoking);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_forgotten_phone_untold_for_the_notice_window_loses_its_key() {
        let directory = scratch();
        let forgotten = record(PairId::from_array(PAIR_ID))
            .forgotten(current_time_ms().saturating_sub(refineid_rapp::REVOCATION_NOTICE_MS));
        let mut reader = reader_with(&directory, vec![forgotten]);
        assert_eq!(reader.pairs().len(), 1);
        reader.sweep();
        assert!(reader.pairs().is_empty());
        assert!(!path_for(&directory, PairId::from_array(PAIR_ID)).exists());
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
        let mut second = RemoteReader::with_store(
            "alpha-desk",
            "Linux",
            FilePairingStore::open(&directory).unwrap(),
        );
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
            Some(RemoteError::NotFound)
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_cached_certificate_replaces_the_record_file_and_survives_reopening() {
        let directory = scratch();
        let mut reader = reader_with_pairing(&directory);
        let pair_id = PairId::from_array(PAIR_ID);
        reader.cache_auth_cert(pair_id, CERTIFICATE).unwrap();
        let record_path = path_for(&directory, pair_id);
        assert!(record_path.exists());
        assert!(!record_path.with_extension("tmp").exists());
        let store = FilePairingStore::open_without_sweep(&directory).unwrap();
        let summary = RemoteReader::with_store("alpha-desk", "Linux", store).pairs();
        assert_eq!(
            summary.first().unwrap().auth_cert.as_deref(),
            Some(CERTIFICATE)
        );
        assert_eq!(
            reader
                .cache_auth_cert(PairId::from_array(UNKNOWN_PAIR_ID), CERTIFICATE)
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
}
