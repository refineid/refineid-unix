//! The workstation's remote card reader: pairing by code and one operation
//! per session, over the stream tier.
//!
//! This is the surface the CLI, the GUI, and the TLS client use. Pairing
//! browses for a custodian in `mode=pairing`; every operation browses for
//! custodians in `mode=session`, dials each, and presents the pair's
//! rendezvous token only inside the routing preamble. A custodian that does
//! not hold the pairing closes the connection, and the next one is tried.

use std::time::{Duration, Instant};

use crate::engine::{
    AdmissionError, OperationOutcome, PairingError, Requester, RequesterConfig, SessionError,
};
use crate::file_journal::FileOperationJournal;
use crate::file_store::FilePairingStore;
use crate::ids::OperationId;
use crate::ids::PairId;
use crate::ids::RendezvousToken;
use crate::message::CloseReason;
use crate::operations::{CardOperation, CardOperationResult, CertificateKind};
use crate::store::{PairingDisposition, PairingStore, StoreError};
use crate::stream::{
    DiscoveryMode, HintMatch, STREAM_CANDIDATE_ID, StreamRendezvous, StreamService, browse, dial,
};

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

/// The session custodians worth dialing for `token`, best first: those whose
/// rotating hint names the pairing, then those publishing no hints. A
/// custodian whose hints all name other pairings is never dialed, so the
/// token is presented only where it can be served.
fn sessions_for(token: &RendezvousToken, services: Vec<StreamService>) -> Vec<StreamService> {
    let unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let (mut named, mut unhinted) = (Vec::new(), Vec::new());
    for service in services {
        match service.hint_match(token, unix_seconds) {
            HintMatch::Named => named.push(service),
            HintMatch::Unhinted => unhinted.push(service),
            HintMatch::Other => {}
        }
    }
    named.extend(unhinted);
    named
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
            Self::Store(StoreError::SecretsUnavailable) => f.write_str(
                "the desktop secret store is unavailable: install secret-tool (libsecret) and \
                 unlock the keyring",
            ),
            Self::Store(error) => write!(f, "pairing store: {error:?}"),
            Self::NotPaired => f.write_str("no paired phone"),
            Self::NotFound => f.write_str("no phone found on the local network"),
            Self::Pairing(error) => write!(f, "pairing: {error}"),
            Self::Session(error) => write!(f, "session: {error}"),
            Self::Admission(error) => write!(f, "operation: {error}"),
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
}

impl PairSummary {
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

impl RemoteReader {
    /// Opens the per-user pairing store, introducing this workstation as
    /// `RefineID <platform>`.
    ///
    /// # Errors
    /// [`RemoteError::Store`] when the store cannot be opened.
    pub fn open_local() -> Result<Self, RemoteError> {
        let platform = local_platform();
        Self::open(&format!("RefineID {platform}"), platform)
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
        Self {
            requester: Requester::new(
                RequesterConfig {
                    display_name: display_name.to_owned(),
                    platform: platform.to_owned(),
                },
                store,
                journal,
            ),
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
                pair_id: record.pair_id,
                peer_display_name: record.peer_display_name.clone(),
                peer_platform: record.peer_platform.clone(),
                granted_profiles: record.granted_profiles.clone(),
                auth_cert: record.auth_cert.clone(),
                revoked: record.disposition == PairingDisposition::Revoked,
            })
            .collect()
    }

    /// The newest pairing that is not revoked.
    #[must_use]
    pub fn selected(&self) -> Option<PairSummary> {
        self.pairs().into_iter().find(|pair| !pair.revoked)
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
    /// Returns each reconciled operation with the state the phone reported,
    /// `None` when the phone does not know it.
    ///
    /// # Errors
    /// [`RemoteError`] when the pairing is unknown or no phone opens a
    /// session for it before `discovery_timeout`.
    pub fn reconcile(
        &mut self,
        pair_id: PairId,
        discovery_timeout: Duration,
    ) -> Result<Vec<(OperationId, Option<String>)>, RemoteError> {
        let record = self
            .requester
            .store()
            .get(pair_id)
            .map_err(|_| RemoteError::NotPaired)?;
        if record.disposition != PairingDisposition::Paired {
            return Err(RemoteError::NotPaired);
        }
        let token = record.rendezvous_token;
        let mut answers = Vec::new();
        for operation_id in self.unreconciled(pair_id) {
            let deadline = Instant::now() + discovery_timeout;
            let mut answer = Err(RemoteError::NotFound);
            'search: while Instant::now() < deadline {
                for service in sessions_for(&token, browse(DiscoveryMode::Session, BROWSE_ROUND)) {
                    let Ok(transport) = dial(
                        &service.endpoints,
                        STREAM_CANDIDATE_ID,
                        OPERATION_RECEIVE_DEADLINE,
                        &StreamRendezvous::Session(token),
                    ) else {
                        continue;
                    };
                    let mut session = match self.requester.connect(pair_id, transport) {
                        Ok(session) => session,
                        Err(error) => {
                            answer = Err(RemoteError::Session(error));
                            continue;
                        }
                    };
                    answer = self
                        .requester
                        .reconcile_status(&mut session, operation_id)
                        .map_err(RemoteError::Session);
                    // The phone re-delivers a retained result after its
                    // report; closing here leaves it unread.
                    self.requester
                        .disconnect(&mut session, CloseReason::Complete);
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
    /// pairing failures, and [`RemoteError::NotFound`] when no phone in a
    /// pairing ceremony answered.
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
                    &StreamRendezvous::Pairing,
                ) else {
                    continue;
                };
                match self
                    .requester
                    .pair_with_code(code, transport, |_, requested| Some(requested.to_vec()))
                {
                    Ok(pair_id) => {
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

    /// Runs one operation against the phone holding `pair_id`, or the
    /// selected pairing when `None`, browsing until `discovery_timeout`
    /// passes.
    ///
    /// # Errors
    /// [`RemoteError`] when no pairing matches, no phone opens a session for
    /// it, or the operation ends without a result.
    pub fn execute(
        &mut self,
        pair_id: Option<PairId>,
        operation: &CardOperation,
        discovery_timeout: Duration,
    ) -> Result<CardOperationResult, RemoteError> {
        let pair_id = match pair_id {
            Some(pair_id) => pair_id,
            None => self.selected().ok_or(RemoteError::NotPaired)?.pair_id,
        };
        let record = self
            .requester
            .store()
            .get(pair_id)
            .map_err(|_| RemoteError::NotPaired)?;
        if record.disposition != PairingDisposition::Paired {
            return Err(RemoteError::NotPaired);
        }
        let token = record.rendezvous_token;
        let deadline = Instant::now() + discovery_timeout;
        let mut last = RemoteError::NotFound;
        while Instant::now() < deadline {
            for service in sessions_for(&token, browse(DiscoveryMode::Session, BROWSE_ROUND)) {
                let Ok(transport) = dial(
                    &service.endpoints,
                    STREAM_CANDIDATE_ID,
                    OPERATION_RECEIVE_DEADLINE,
                    &StreamRendezvous::Session(token),
                ) else {
                    continue;
                };
                let mut session = match self.requester.connect(pair_id, transport) {
                    Ok(session) => session,
                    Err(error) => {
                        last = RemoteError::Session(error);
                        continue;
                    }
                };
                let outcome = self
                    .requester
                    .execute(&mut session, operation, OPERATION_LIFETIME_MS)
                    .map_err(RemoteError::Admission);
                self.requester
                    .disconnect(&mut session, CloseReason::Complete);
                return match outcome? {
                    OperationOutcome::Completed(result) => Ok(result),
                    other => Err(RemoteError::Outcome(Box::new(other))),
                };
            }
        }
        Err(last)
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
mod tests {
    use std::collections::BTreeMap;

    use super::{RendezvousToken, StreamService, sessions_for};

    fn service(instance: &str, hints: Option<String>) -> StreamService {
        let mut attributes = BTreeMap::from([
            ("v".to_owned(), "1".to_owned()),
            ("mode".to_owned(), "session".to_owned()),
        ]);
        if let Some(hints) = hints {
            attributes.insert("hints".to_owned(), hints);
        }
        StreamService {
            instance: instance.to_owned(),
            endpoints: vec!["192.0.2.10:47110".to_owned()],
            attributes,
        }
    }

    #[test]
    fn named_custodians_come_first_and_foreign_ones_are_never_dialed() {
        let token = RendezvousToken::from_array([0x42; 16]);
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
            / refineid_rapp::DISCOVERY_HINT_EPOCH_SECONDS;
        let hex = |bytes: [u8; refineid_rapp::DISCOVERY_HINT_SIZE]| -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        };
        let mine = hex(refineid_rapp::discovery_hint(&token, epoch));
        let theirs = hex(refineid_rapp::discovery_hint(
            &RendezvousToken::from_array([0x24; 16]),
            epoch,
        ));
        let ordered = sessions_for(
            &token,
            vec![
                service("refineid-unhinted", None),
                service("refineid-foreign", Some(theirs)),
                service("refineid-mine", Some(mine)),
            ],
        );
        let names: Vec<&str> = ordered.iter().map(|svc| svc.instance.as_str()).collect();
        assert_eq!(names, ["refineid-mine", "refineid-unhinted"]);
    }
}
