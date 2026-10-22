//! The requester engine: the workstation side of RAPP v26.10.22.
//!
//! The engine drives pairing, sessions, and operations through the
//! canonical protocol boundaries of `refineid_rapp`: the session handshake
//! and the custodian's `session.ready` (section 7.1 item 5), the liveness
//! rule of section 8.3, the requester operation engine of section 8, and
//! the revocation of section 4.6. Nothing of an operation outlives its
//! session: a lost result is asked for again as a new operation.
//!
//! The engine is blocking and synchronous: the PKCS#11 module, TLS client,
//! CLI, and GUI call it from their own threads.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::ids::{OperationId, PairId, RandomIdExt};
use crate::message::{CardStatusMessage, CloseReason, ResultError, ResultStatus};
use crate::offer::{OfferError, PairingOffer};
use crate::operations::{CardOperation, CardOperationResult, OperationError};
use crate::store::{PairingRecord, PairingStore, PeerIntroduction, RecordError, StoreError};
use crate::transport::{BinaryFrame, FrameTransport, TransportError};
use refineid_rapp::{
    ActivePairing, EndpointRole, EstablishedSessionRuntime, ExplicitUserIntent, OperationRequest,
    OperationViolation, PairingHandshake, PairingState, PairingStorage, PingChallenge, ProfileName,
    ReadyOutcome, RequesterDispatch, RequesterEngineError, RequesterOperationEngine, RuntimePoll,
    RuntimeReceive, SessionAuthentication, SessionHandshake, TransportProfile,
    generate_pair_key_material,
};

/// How long one receive waits before the liveness clock is read again: a
/// ping is due five seconds into a silence (section 8.3), so it leaves
/// within one tick of that.
const LIVENESS_TICK: Duration = Duration::from_secs(1);

/// How long a revocation close waits for the phone to close its side, so
/// the phone reads the close before this side's socket goes.
const CLOSE_LINGER: Duration = Duration::from_secs(2);

/// Local labels sent inside `pairing.hello`. Labels, not identities.
#[derive(Clone, Debug)]
pub struct RequesterConfig {
    /// The display label shown on the proxy.
    pub display_name: String,
    /// The platform label shown on the proxy.
    pub platform: String,
}

/// Uniform bytes drawn for the `CPace` initiator's scalar (RAPP
/// v26.10.22 section 6.1.1: 64 uniform bytes reduced modulo the group
/// order).
const CPACE_SCALAR_ENTROPY_BYTES: usize = 64;

/// Why pairing did not produce a stored record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingError {
    /// The offer failed its structural rules.
    Offer(OfferError),
    /// Key material could not be produced.
    KeyGeneration,
    /// The handshake failed.
    HandshakeFailed,
    /// The input is not a six-character pairing code (section 3.1).
    InvalidCode,
    /// The custodian's confirmation tag did not verify: the code typed here
    /// differs from the one the custodian shows.
    CodeMismatch,
    /// The transport failed during pairing.
    Transport(TransportError),
    /// The peer's parameter echo did not match the local view.
    ParameterMismatch,
    /// The authenticated exchange violated the protocol; the attempt is
    /// aborted and nothing is recorded.
    ProtocolViolation,
    /// The local user denied the confirmation.
    DeniedLocally,
    /// The peer aborted or denied the confirmation.
    AbortedByPeer,
    /// The two granted sets were not equal.
    GrantsMismatch,
    /// The granted set was not a subset of offered and requested profiles.
    GrantsNotSubset,
    /// The pairing store refused the record.
    Store(StoreError),
    /// The engine's record is not one the store holds.
    Record(RecordError),
    /// The channel failed after authentication.
    Channel,
    /// A post-PAKE phase outlived its section 3.3 deadline; nothing is
    /// recorded.
    DeadlineExpired,
    /// The peer never confirmed storing the pairing (section 4.3 item 4);
    /// the record stored here is revoked.
    StorageUnconfirmed,
}

impl core::fmt::Display for PairingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Offer(e) => write!(f, "pairing offer error: {e}"),
            Self::KeyGeneration => f.write_str("key generation failed"),
            Self::HandshakeFailed => f.write_str("handshake failed"),
            Self::InvalidCode => f.write_str("not a pairing code"),
            Self::CodeMismatch => f.write_str("pairing code does not match the phone"),
            Self::Transport(e) => write!(f, "transport error: {e:?}"),
            Self::ParameterMismatch => f.write_str("parameter mismatch"),
            Self::ProtocolViolation => f.write_str("protocol violation"),
            Self::DeniedLocally => f.write_str("pairing denied locally"),
            Self::AbortedByPeer => f.write_str("pairing aborted by peer"),
            Self::DeadlineExpired => f.write_str("pairing step outlived its deadline"),
            Self::StorageUnconfirmed => f.write_str("the phone did not confirm the pairing"),
            Self::GrantsMismatch => f.write_str("grants mismatch"),
            Self::GrantsNotSubset => f.write_str("grants not a valid subset"),
            Self::Store(e) => write!(f, "store error: {e:?}"),
            Self::Record(e) => write!(f, "record refused: {e:?}"),
            Self::Channel => f.write_str("channel error"),
        }
    }
}

impl core::error::Error for PairingError {}

/// Why a session could not be opened or continued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// No pairing record exists.
    UnknownPairing,
    /// The stored pairing's state opens no such session.
    NotPaired(PairingState),
    /// The session handshake failed before authentication: the
    /// connection closed and nothing stored changed (section 10.1 item 1).
    HandshakeFailed,
    /// The transport failed, or thirty seconds passed without a message
    /// from the phone (section 8.3).
    Transport(TransportError),
    /// The phone's authenticated traffic violated the protocol: the
    /// session closed with `protocol_violation`, and the pairing stands
    /// (section 10.1 item 2).
    Violation,
    /// The peer closed the session.
    ClosedByPeer(CloseReason),
    /// The engine encountered an internal fault.
    EngineFault,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownPairing => f.write_str("unknown pairing"),
            Self::NotPaired(d) => write!(f, "pairing not usable ({d:?})"),
            Self::HandshakeFailed => f.write_str("handshake failed"),
            Self::Transport(e) => write!(f, "transport error: {e:?}"),
            Self::Violation => f.write_str("the phone's message was not understood"),
            Self::ClosedByPeer(reason) => write!(f, "session closed by peer: {reason:?}"),
            Self::EngineFault => f.write_str("engine fault"),
        }
    }
}

impl core::error::Error for SessionError {}

/// Why an operation call could not be admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// The session is not healthy.
    SessionNotHealthy,
    /// The profile is not in the granted set.
    ProfileNotGranted,
    /// Identifier generation failed.
    RandomUnavailable,
    /// The typed operation violated an invariant.
    Operation(OperationError),
    /// The session's operation engine refused the request: another
    /// operation is live, or the request failed its validation.
    Engine(RequesterEngineError),
}

impl core::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SessionNotHealthy => f.write_str("session is not healthy"),
            Self::ProfileNotGranted => f.write_str("profile is not in granted set"),
            Self::RandomUnavailable => f.write_str("cryptographic random is unavailable"),
            Self::Operation(e) => write!(f, "operation error: {e:?}"),
            Self::Engine(e) => write!(f, "operation refused: {e}"),
        }
    }
}

impl core::error::Error for AdmissionError {}

/// How a finished operation ended (RAPP v26.10.22 section 8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationOutcome {
    /// The result arrived and answers the request.
    Completed(CardOperationResult),
    /// The phone rejected the operation with a section 10.3 error, in its
    /// `operation.result` or in an `error` refusing the request.
    Rejected(ResultError),
    /// The phone cancelled the operation before the card was commanded.
    Cancelled(ResultError),
    /// The session ended before the result arrived; the operation ended
    /// with it (section 8.1 item 3).
    Lost,
    /// The phone's answer did not fit the operation: the session closed
    /// with `protocol_violation`, and the pairing stands.
    Refused,
}

/// What ended a session, reported after close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// The local side closed deliberately.
    LocalClose,
    /// The peer closed with the carried reason.
    PeerClose(CloseReason),
    /// The transport failed or ended, or the phone fell silent for thirty
    /// seconds (section 8.3).
    TransportLoss,
    /// A frame failed authenticated decryption.
    IntegrityFailure,
    /// The phone's authenticated traffic violated the protocol; the
    /// session closed with `protocol_violation`.
    Violation,
}

/// One healthy session: its transport, its runtime with the liveness
/// clock, and its operation engine.
pub struct Session<Transport: FrameTransport> {
    transport: Transport,
    runtime: EstablishedSessionRuntime,
    operations: RequesterOperationEngine,
    pair_id: PairId,
    granted_profiles: Vec<ProfileName>,
    started: Instant,
    end: Option<SessionEnd>,
    /// What the custodian last said about its card (section 8.4), once it
    /// has said anything on this session.
    card: Option<CardStatusMessage>,
}

impl<Transport: FrameTransport> Session<Transport> {
    /// The card the custodian last reported on this session (section
    /// 8.4); `None` before its first `card.status` and after the session
    /// ended.
    #[must_use]
    pub const fn card_status(&self) -> Option<CardStatusMessage> {
        self.card
    }

    /// Whether the custodian can serve a card, as it last reported; `None`
    /// before its first `card.status` and after the session ended.
    #[must_use]
    pub fn card_present(&self) -> Option<bool> {
        self.card
            .map(|status| matches!(status, CardStatusMessage::Present(_)))
    }

    /// The pairing this session serves.
    #[must_use]
    pub const fn pair_id(&self) -> PairId {
        self.pair_id
    }

    /// How the session ended, once closed.
    #[must_use]
    pub const fn end(&self) -> Option<SessionEnd> {
        self.end
    }

    /// Milliseconds on the session's monotonic clock, which the liveness
    /// rule runs on.
    fn clock_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Walks the session into closed: the channel goes, the live operation
    /// ends with it, and the card report is no longer the phone's word.
    fn finish(&mut self, end: SessionEnd) {
        self.runtime.close_session();
        let _ = self.operations.session_closed();
        self.card = None;
        self.end = Some(end);
    }

    /// Delivers a sealed close, best effort, and finishes the session.
    fn close_with(&mut self, notice: Option<BinaryFrame>, end: SessionEnd) {
        if let Some(notice) = notice {
            let _ = self.transport.send_frame(notice.as_bytes());
        }
        self.finish(end);
    }
}

impl<Transport: FrameTransport> core::fmt::Debug for Session<Transport> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("pair_id", &self.pair_id)
            .field("granted_profiles", &self.granted_profiles)
            .field("end", &self.end)
            .field("card", &self.card)
            .finish_non_exhaustive()
    }
}

/// The requester engine over its durable pairing store.
#[derive(Debug)]
pub struct Requester<Store: PairingStore> {
    config: RequesterConfig,
    store: Store,
}

impl<Store: PairingStore> Requester<Store> {
    /// Creates an engine over its store.
    pub const fn new(config: RequesterConfig, store: Store) -> Self {
        Self { config, store }
    }

    /// The pairing store, for inspection.
    pub const fn store(&self) -> &Store {
        &self.store
    }

    /// Mutable access to the pairing store.
    pub const fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    /// Pairs with the custodian showing `code`, as the requester (RAPP
    /// v26.10.22 sections 3, 4.2 and 6).
    ///
    /// The transport is already past its `"pairing"` routing preamble. The
    /// custodian's first frame is its offer (section 4.2); the requester
    /// binds the offer's entry for the connection's transport profile, sends
    /// `Y_A`, verifies the custodian's `Y_B || T_B`, answers with `T_A`, and
    /// hands the `CPace` key to `Noise_XXpsk3`; the pairing hello and
    /// confirmation follow inside that channel. `confirm` sees the
    /// custodian's introduction and returns the profiles to grant, or `None`
    /// to refuse.
    ///
    /// # Errors
    /// [`PairingError::InvalidCode`] for input that is not a pairing code,
    /// [`PairingError::Offer`] for a bootstrap that is not a usable offer,
    /// [`PairingError::CodeMismatch`] when the custodian's confirmation tag
    /// does not verify (a mistyped code), and the other [`PairingError`]
    /// variants on handshake, deadline, transport, or grant failures.
    pub fn pair_with_code<Transport: FrameTransport>(
        &mut self,
        code: &str,
        mut transport: Transport,
        confirm: impl FnOnce(&PeerIntroduction, &[ProfileName]) -> Option<Vec<ProfileName>>,
    ) -> Result<PairId, PairingError> {
        let normalized = crate::offer::normalize_pairing_code(code)
            .map(Zeroizing::new)
            .ok_or(PairingError::InvalidCode)?;
        let profile = TransportProfile::parse(transport.profile())
            .ok_or(PairingError::Offer(OfferError::InvalidTransport))?;
        let bootstrap = transport.receive_frame().map_err(PairingError::Transport)?;
        let offer =
            crate::offer::offer_from_bootstrap(&bootstrap, profile).map_err(PairingError::Offer)?;
        let candidate_id = offer
            .entry(profile)
            .map(|entry| entry.candidate_id.clone())
            .ok_or(PairingError::Offer(OfferError::TransportNotOffered))?;
        let offer_hash = offer
            .offer_hash()
            .map_err(|_| PairingError::HandshakeFailed)?;
        let context =
            refineid_rapp::standard_pairing_context_v2(&offer_hash, profile.name(), &candidate_id)
                .map_err(|_| PairingError::HandshakeFailed)?;
        let mut entropy = Zeroizing::new([0_u8; CPACE_SCALAR_ENTROPY_BYTES]);
        getrandom::fill(entropy.as_mut()).map_err(|_| PairingError::KeyGeneration)?;
        let (initiator, step_one) =
            refineid_rapp::CpaceKc2Initiator::new(&normalized, &context, &offer.offer_id, &entropy)
                .map_err(|_| PairingError::HandshakeFailed)?;
        drop(entropy);

        let step_one_frame = refineid_rapp::encode_kc2_step1_frame(&step_one)
            .map_err(|_| PairingError::HandshakeFailed)?;
        transport
            .send_frame(step_one_frame.as_bytes())
            .map_err(PairingError::Transport)?;
        let step_two = transport.receive_frame().map_err(PairingError::Transport)?;
        let step_two =
            BinaryFrame::reconstruct(step_two).map_err(|_| PairingError::HandshakeFailed)?;
        let (step_three, pairing_secret) =
            initiator
                .process_step2_frame(&step_two)
                .map_err(|error| match error {
                    refineid_rapp::CpaceError::ConfirmationTagMismatch => {
                        PairingError::CodeMismatch
                    }
                    _ => PairingError::HandshakeFailed,
                })?;
        transport
            .send_frame(step_three.as_bytes())
            .map_err(PairingError::Transport)?;
        let handshake_deadline = PhaseDeadline::after(refineid_rapp::POST_PAKE_HANDSHAKE_MS);

        // The registered profiles the offer names are requested; a name
        // outside the registry is not one this computer can use.
        let requested: Vec<ProfileName> = offer
            .profiles
            .iter()
            .filter_map(|name| ProfileName::parse(name))
            .collect();
        self.complete_pairing(
            offer,
            &candidate_id,
            &pairing_secret,
            &requested,
            transport,
            handshake_deadline,
            confirm,
        )
    }

    /// Runs `Noise_XXpsk3` under the `CPace` key, then the pairing hello and
    /// confirmation, and stores the resulting record.
    #[allow(
        clippy::too_many_lines,
        reason = "pairing handshake walks 7 sequential wire messages"
    )]
    #[allow(
        clippy::too_many_arguments,
        reason = "the pairing continuation carries the bound offer, its entry, the CPace key, and its deadline"
    )]
    fn complete_pairing<Transport: FrameTransport>(
        &mut self,
        offer: PairingOffer,
        candidate_id: &str,
        pairing_secret: &refineid_rapp::PairingSecret,
        requested_profiles: &[ProfileName],
        mut transport: Transport,
        handshake_deadline: PhaseDeadline,
        confirm: impl FnOnce(&PeerIntroduction, &[ProfileName]) -> Option<Vec<ProfileName>>,
    ) -> Result<PairId, PairingError> {
        let local_keys = generate_pair_key_material().map_err(|_| PairingError::KeyGeneration)?;
        let mut handshake = match PairingHandshake::begin(
            EndpointRole::Requester,
            offer,
            candidate_id,
            local_keys,
            pairing_secret,
        ) {
            Ok(h) => h,
            Err(fail) => {
                let (err, _offer) = fail.into_parts();
                return Err(match err {
                    refineid_rapp::PairingError::Offer(e) => PairingError::Offer(e),
                    refineid_rapp::PairingError::CandidateNotUnique => {
                        PairingError::Offer(refineid_rapp::PairingOfferError::InvalidTransport)
                    }
                    _ => PairingError::HandshakeFailed,
                });
            }
        };

        // Noise XX Handshake
        // Message 1 (Requester -> Proxy)
        let m1 = handshake
            .write_message()
            .map_err(|_| PairingError::HandshakeFailed)?;
        transport
            .send_frame(m1.as_bytes())
            .map_err(PairingError::Transport)?;

        // Message 2 (Proxy -> Requester)
        let m2_bytes = transport.receive_frame().map_err(PairingError::Transport)?;
        let m2 = BinaryFrame::reconstruct(m2_bytes).map_err(|_| PairingError::HandshakeFailed)?;
        handshake
            .read_message(&m2)
            .map_err(|_| PairingError::HandshakeFailed)?;

        // Message 3 (Requester -> Proxy)
        let m3 = handshake
            .write_message()
            .map_err(|_| PairingError::HandshakeFailed)?;
        transport
            .send_frame(m3.as_bytes())
            .map_err(PairingError::Transport)?;

        if !handshake.is_complete() {
            return Err(PairingError::HandshakeFailed);
        }
        handshake_deadline.check()?;
        let confirmation_deadline = PhaseDeadline::after(refineid_rapp::POST_PAKE_CONFIRMATION_MS);

        let mut confirmation = handshake
            .into_confirmation()
            .map_err(|_| PairingError::HandshakeFailed)?;
        let pair_id = confirmation.pair_id();

        // Send Requester Hello
        let hello_frame = confirmation
            .send_hello(
                self.config.display_name.clone(),
                self.config.platform.clone(),
            )
            .map_err(|_| PairingError::Channel)?;
        transport
            .send_frame(hello_frame.as_bytes())
            .map_err(PairingError::Transport)?;

        // Receive Proxy Hello
        let peer_hello_bytes = transport.receive_frame().map_err(PairingError::Transport)?;
        confirmation_deadline.check()?;
        let peer_hello_frame =
            BinaryFrame::reconstruct(peer_hello_bytes).map_err(|_| PairingError::Channel)?;
        let now_ms = current_time_ms();
        let peer_hello = confirmation
            .receive_hello(&peer_hello_frame, now_ms)
            .map_err(|err| match err {
                refineid_rapp::PairingError::ParameterMismatch => PairingError::ParameterMismatch,
                _ => PairingError::ProtocolViolation,
            })?;
        let intro = PeerIntroduction {
            display_name: peer_hello.display_name.clone(),
            platform: peer_hello.platform.clone(),
        };

        // Confirmation callback
        let Some(granted_profiles) = confirm(&intro, requested_profiles) else {
            return Err(PairingError::DeniedLocally);
        };
        if granted_profiles.is_empty()
            || !granted_profiles
                .iter()
                .all(|granted| requested_profiles.contains(granted))
        {
            return Err(PairingError::GrantsNotSubset);
        }

        // Send local confirmation
        let confirm_frame = confirmation
            .send_confirmation(granted_profiles)
            .map_err(|err| match err {
                refineid_rapp::PairingError::GrantMismatch => PairingError::GrantsMismatch,
                refineid_rapp::PairingError::InvalidGrantSet => PairingError::GrantsNotSubset,
                _ => PairingError::Channel,
            })?;
        transport
            .send_frame(confirm_frame.as_bytes())
            .map_err(PairingError::Transport)?;

        // Receive peer confirmation
        let peer_confirm_bytes = transport.receive_frame().map_err(PairingError::Transport)?;
        confirmation_deadline.check()?;
        let peer_confirm_frame =
            BinaryFrame::reconstruct(peer_confirm_bytes).map_err(|_| PairingError::Channel)?;
        confirmation
            .receive_confirmation(&peer_confirm_frame, now_ms)
            .map_err(|err| match err {
                refineid_rapp::PairingError::GrantMismatch => PairingError::GrantsMismatch,
                _ => PairingError::ProtocolViolation,
            })?;

        // Store the record, then confirm the storage both ways (section
        // 4.3 item 4). A record the peer never confirms is revoked.
        let (pair_record, storage) = confirmation
            .into_storage(now_ms)
            .map_err(|_| PairingError::Channel)?;
        let local_record = PairingRecord::new(pair_record, intro).map_err(PairingError::Record)?;
        confirmation_deadline.check()?;
        self.store
            .insert(local_record)
            .map_err(PairingError::Store)?;
        let confirmed = Self::confirm_storage(&mut transport, storage, confirmation_deadline)
            .and_then(|active| {
                let mut active = Some(active);
                let mut refused = None;
                self.store
                    .update(pair_id, &mut |record| {
                        let active = active.take()?;
                        record
                            .confirmed(active)
                            .map_err(|error| refused = Some(error))
                            .ok()
                    })
                    .map_err(PairingError::Store)?;
                refused.map_or(Ok(()), |error| Err(PairingError::Record(error)))
            });
        if confirmed.is_err() {
            // Section 4.3 item 4: a pairing the peer never confirmed is
            // revoked here, its key destroyed and nobody told.
            let _ = self.store.remove(pair_id);
        }
        confirmed.map(|()| pair_id)
    }

    /// Sends this side's `pairing.stored`, receives the peer's, and proves
    /// the pairing active; the channel closes with the storage value.
    fn confirm_storage<Transport: FrameTransport>(
        transport: &mut Transport,
        mut storage: PairingStorage,
        confirmation_deadline: PhaseDeadline,
    ) -> Result<ActivePairing, PairingError> {
        let stored_frame = storage.send_stored().map_err(|_| PairingError::Channel)?;
        transport
            .send_frame(stored_frame.as_bytes())
            .map_err(PairingError::Transport)?;
        // Whatever ends the wait, the peer did not confirm: the record
        // stored here is revoked by the caller.
        let peer_stored_bytes = transport
            .receive_frame()
            .map_err(|_| PairingError::StorageUnconfirmed)?;
        confirmation_deadline
            .check()
            .map_err(|_| PairingError::StorageUnconfirmed)?;
        let peer_stored_frame =
            BinaryFrame::reconstruct(peer_stored_bytes).map_err(|_| PairingError::Channel)?;
        storage
            .receive_stored(&peer_stored_frame, current_time_ms())
            .map_err(|err| match err {
                refineid_rapp::PairingError::PairIdMismatch => PairingError::ProtocolViolation,
                _ => PairingError::Channel,
            })?;
        storage
            .into_active()
            .map_err(|_| PairingError::StorageUnconfirmed)
    }

    /// Opens a session to a paired custodian over a connected transport:
    /// the `Noise_KK` handshake, then the custodian's `session.ready`,
    /// verified against the local view (section 7.1 item 5).
    ///
    /// A custodian that revoked the pairing closes with `pairing_revoked`
    /// in place of `session.ready`; the pairing is then revoked here at
    /// once (section 4.6 item 4).
    ///
    /// # Errors
    /// [`SessionError`] on an unknown or unusable pairing, a failed
    /// handshake, a peer close, a protocol violation, or transport loss.
    pub fn connect<Transport: FrameTransport>(
        &mut self,
        pair_id: PairId,
        mut transport: Transport,
    ) -> Result<Session<Transport>, SessionError> {
        let record = self
            .store
            .get(pair_id)
            .map_err(|_| SessionError::UnknownPairing)?;
        if record.state() != PairingState::PairedDisconnected {
            return Err(SessionError::NotPaired(record.state()));
        }
        let granted_profiles = record.pairing().serving_profiles().to_vec();
        let mut authentication = self.authenticate(pair_id, &mut transport)?;
        let first = transport.receive_frame().map_err(SessionError::Transport)?;
        let first = BinaryFrame::reconstruct(first)
            .map_err(|_| SessionError::Transport(TransportError::Failed))?;
        match authentication.receive_ready(&first, current_time_ms()) {
            Ok(ReadyOutcome::Verified) => {}
            Ok(ReadyOutcome::PeerClosed(reason)) => {
                self.apply_peer_close_reason(pair_id, reason);
                return Err(SessionError::ClosedByPeer(reason));
            }
            Ok(ReadyOutcome::ViolationClosed { notice, .. }) => {
                if let Some(notice) = notice {
                    let _ = transport.send_frame(notice.as_bytes());
                }
                return Err(SessionError::Violation);
            }
            Err(refineid_rapp::SessionError::IntegrityFailure) => {
                return Err(SessionError::Transport(TransportError::Failed));
            }
            Err(_) => return Err(SessionError::EngineFault),
        }
        let endpoint = authentication
            .into_established()
            .map_err(|_| SessionError::EngineFault)?;
        let started = Instant::now();
        Ok(Session {
            transport,
            runtime: EstablishedSessionRuntime::new(endpoint, 0),
            operations: RequesterOperationEngine::new(),
            pair_id,
            granted_profiles,
            started,
            end: None,
            card: None,
        })
    }

    /// Tells the custodian that this computer forgot the pairing (section
    /// 4.6 item 2): completes the session handshake, sends `session.close`
    /// with reason `pairing_revoked` as the session's first message, and
    /// destroys the pairing's key. No card session starts.
    ///
    /// # Errors
    /// [`SessionError`] on an unknown pairing, one that was not forgotten,
    /// a failed handshake, or transport loss; the key is kept for a later
    /// session.
    pub fn send_revocation_notice<Transport: FrameTransport>(
        &mut self,
        pair_id: PairId,
        mut transport: Transport,
    ) -> Result<(), SessionError> {
        let record = self
            .store
            .get(pair_id)
            .map_err(|_| SessionError::UnknownPairing)?;
        if record.state() != PairingState::Revoking {
            return Err(SessionError::NotPaired(record.state()));
        }
        let mut authentication = self.authenticate(pair_id, &mut transport)?;
        let notice = authentication
            .send_revocation_notice()
            .map_err(|_| SessionError::EngineFault)?;
        transport
            .send_frame(notice.as_bytes())
            .map_err(SessionError::Transport)?;
        linger(&mut transport);
        let _ = self.store.remove(pair_id);
        Ok(())
    }

    /// Runs the `Noise_KK` handshake for `pair_id` as initiator and enters
    /// the authentication phase. A handshake that fails changes nothing
    /// stored (section 10.1 item 1).
    fn authenticate<Transport: FrameTransport>(
        &mut self,
        pair_id: PairId,
        transport: &mut Transport,
    ) -> Result<SessionAuthentication, SessionError> {
        let profile =
            TransportProfile::parse(transport.profile()).ok_or(SessionError::EngineFault)?;
        let record = self
            .store
            .get(pair_id)
            .map_err(|_| SessionError::UnknownPairing)?;
        let mut handshake = SessionHandshake::begin_requester(
            record.pairing(),
            profile,
            ExplicitUserIntent::record(),
        )
        .map_err(|_| SessionError::EngineFault)?;

        let first = handshake
            .write_message()
            .map_err(|_| SessionError::EngineFault)?;
        transport
            .send_frame(first.as_bytes())
            .map_err(SessionError::Transport)?;

        let answer = transport.receive_frame().map_err(SessionError::Transport)?;
        let answer = BinaryFrame::reconstruct(answer)
            .map_err(|_| SessionError::Transport(TransportError::Failed))?;
        handshake
            .read_message(&answer)
            .map_err(|_| SessionError::HandshakeFailed)?;
        if !handshake.is_complete() {
            return Err(SessionError::EngineFault);
        }
        handshake
            .into_authentication()
            .map_err(|_| SessionError::EngineFault)
    }

    /// Serves an open session for `wait`: answers the custodian's pings,
    /// records its card reports, and keeps the liveness rule of section
    /// 8.3, a ping after five seconds of silence and the end after thirty.
    ///
    /// # Errors
    /// [`SessionError`] once the session ended: a peer close, a protocol
    /// violation, silence, or transport loss.
    pub fn service<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        wait: Duration,
    ) -> Result<(), SessionError> {
        let deadline = Instant::now() + wait;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            self.pump(session, remaining)?;
        }
    }

    /// Waits up to `wait` for the custodian to report a card it can serve
    /// (section 8.4), serving the session meanwhile. Returns whether one
    /// was reported; a wait that runs out leaves the session open, so the
    /// caller decides whether to keep offering nothing or to close.
    ///
    /// # Errors
    /// As [`Self::service`].
    pub fn await_card_present<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        wait: Duration,
    ) -> Result<bool, SessionError> {
        self.await_card(session, wait, |session| {
            session.card_present() == Some(true)
        })
    }

    /// Waits up to `wait` for the custodian's first card report, present or
    /// absent, which it sends right after `session.ready` (section 8.4 item
    /// 1), serving the session meanwhile. Returns whether one arrived.
    ///
    /// # Errors
    /// As [`Self::service`].
    pub fn await_card_report<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        wait: Duration,
    ) -> Result<bool, SessionError> {
        self.await_card(session, wait, |session| session.card_status().is_some())
    }

    /// Serves `session` until `reported` holds of it or `wait` passes;
    /// whether it held.
    fn await_card<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        wait: Duration,
        reported: impl Fn(&Session<Transport>) -> bool,
    ) -> Result<bool, SessionError> {
        let deadline = Instant::now() + wait;
        loop {
            if reported(session) {
                return Ok(true);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            self.pump(session, remaining)?;
        }
    }

    /// Closes a session deliberately with `reason`; an ended session is
    /// left as it ended.
    pub fn disconnect<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        reason: CloseReason,
    ) {
        if session.end.is_some() {
            return;
        }
        let notice = session.runtime.close_with_reason(reason).ok();
        session.close_with(notice, SessionEnd::LocalClose);
    }

    /// Tells the custodian on `session` that this computer forgot the
    /// pairing (section 4.6 item 1): sends `session.close` with reason
    /// `pairing_revoked` and closes the session. Once the close is sent,
    /// the key of a record the store durably holds as forgotten is
    /// destroyed (item 3); a session that already ended leaves the record
    /// for the next session's notice.
    pub fn revoke_in_session<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
    ) {
        if session.end.is_some() {
            return;
        }
        let sent = session
            .runtime
            .close_with_reason(CloseReason::PairingRevoked)
            .is_ok_and(|notice| session.transport.send_frame(notice.as_bytes()).is_ok());
        if sent {
            linger(&mut session.transport);
        }
        session.finish(SessionEnd::LocalClose);
        if sent {
            let _ = self.store.update(session.pair_id, &mut |record| {
                (record.state() != PairingState::Revoking).then_some(record)
            });
        }
    }

    /// Runs one typed operation to its outcome (section 8): the request
    /// goes out under a fresh identifier and the session is served until
    /// the result arrives or the session ends. Liveness bounds a phone
    /// that falls silent; the phone's own deadline bounds the rest.
    ///
    /// # Errors
    /// Returns [`AdmissionError`] when the session cannot carry the
    /// operation.
    pub fn execute<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        operation: &CardOperation,
        expires_after_ms: u64,
    ) -> Result<OperationOutcome, AdmissionError> {
        let profile: ProfileName = operation.required_profile();
        if session.end.is_some() {
            return Err(AdmissionError::SessionNotHealthy);
        }
        if !session.granted_profiles.contains(&profile) {
            return Err(AdmissionError::ProfileNotGranted);
        }
        let operation_id = OperationId::random().map_err(|_| AdmissionError::RandomUnavailable)?;
        let request = OperationRequest::reconstruct(
            operation_id,
            profile,
            session.clock_ms(),
            expires_after_ms,
            operation.clone(),
        )
        .map_err(AdmissionError::Operation)?;
        let message = session
            .operations
            .begin(request)
            .map_err(AdmissionError::Engine)?;
        let sent = session
            .runtime
            .endpoint_mut()
            .send(&message)
            .is_ok_and(|frame| session.transport.send_frame(frame.as_bytes()).is_ok());
        if !sent {
            session.finish(SessionEnd::TransportLoss);
            return Ok(OperationOutcome::Lost);
        }
        loop {
            match self.pump(session, LIVENESS_TICK) {
                Ok(Some(RequesterDispatch::Completed { result, .. })) => {
                    return Ok(OperationOutcome::Completed(result));
                }
                Ok(Some(RequesterDispatch::Ended {
                    status: ResultStatus::Cancelled,
                    error,
                    ..
                })) => return Ok(OperationOutcome::Cancelled(error)),
                Ok(Some(
                    RequesterDispatch::Ended { error, .. }
                    | RequesterDispatch::Refused { error, .. },
                )) => return Ok(OperationOutcome::Rejected(error)),
                Ok(_) => {}
                Err(SessionError::Violation) => return Ok(OperationOutcome::Refused),
                Err(_) => return Ok(OperationOutcome::Lost),
            }
        }
    }

    /// Receives at most one frame within `wait`, after keeping the
    /// liveness rule. Pings, pongs, and card reports are handled here; the
    /// live operation's progress and end are returned.
    fn pump<Transport: FrameTransport>(
        &mut self,
        session: &mut Session<Transport>,
        wait: Duration,
    ) -> Result<Option<RequesterDispatch>, SessionError> {
        if session.end.is_some() {
            return Err(SessionError::EngineFault);
        }
        Self::keep_alive(session)?;
        if let Err(error) = session
            .transport
            .set_receive_deadline(wait.min(LIVENESS_TICK))
        {
            session.finish(SessionEnd::TransportLoss);
            return Err(SessionError::Transport(error));
        }
        let bytes = match session.transport.receive_frame() {
            Ok(bytes) => bytes,
            Err(TransportError::TimedOut) => return Ok(None),
            Err(error) => {
                session.finish(SessionEnd::TransportLoss);
                return Err(SessionError::Transport(error));
            }
        };
        let Ok(frame) = BinaryFrame::reconstruct(bytes) else {
            session.finish(SessionEnd::IntegrityFailure);
            return Err(SessionError::Transport(TransportError::Failed));
        };
        let now_ms = session.clock_ms();
        let received = match session.runtime.receive(&frame, now_ms) {
            Ok(received) => received,
            Err(_) => {
                session.finish(SessionEnd::IntegrityFailure);
                return Err(SessionError::Transport(TransportError::Failed));
            }
        };
        match received {
            RuntimeReceive::Send(pong) => {
                if let Err(error) = session.transport.send_frame(pong.as_bytes()) {
                    session.finish(SessionEnd::TransportLoss);
                    return Err(SessionError::Transport(error));
                }
                Ok(None)
            }
            RuntimeReceive::LivenessConfirmed | RuntimeReceive::IgnoredStalePong => Ok(None),
            RuntimeReceive::PeerClosed(reason) => {
                session.finish(SessionEnd::PeerClose(reason));
                self.apply_peer_close_reason(session.pair_id, reason);
                Err(SessionError::ClosedByPeer(reason))
            }
            RuntimeReceive::SessionClosed(_) => {
                session.finish(SessionEnd::IntegrityFailure);
                Err(SessionError::Transport(TransportError::Failed))
            }
            RuntimeReceive::ViolationClosed { notice, .. } => {
                session.close_with(notice, SessionEnd::Violation);
                Err(SessionError::Violation)
            }
            RuntimeReceive::Message(message) => Self::dispatch(session, message),
        }
    }

    /// Hands one authenticated message to the session's operation engine.
    fn dispatch<Transport: FrameTransport>(
        session: &mut Session<Transport>,
        message: refineid_rapp::TypedMessage,
    ) -> Result<Option<RequesterDispatch>, SessionError> {
        match session.operations.receive(message) {
            Ok(RequesterDispatch::CardStatus(status)) => {
                session.card = Some(status);
                Ok(None)
            }
            Ok(RequesterDispatch::Ignored(_) | RequesterDispatch::PeerError(_)) => Ok(None),
            Ok(RequesterDispatch::NotOperation(_)) => {
                let notice = session
                    .runtime
                    .close_with_reason(CloseReason::ProtocolViolation)
                    .ok();
                session.close_with(notice, SessionEnd::Violation);
                Err(SessionError::Violation)
            }
            Ok(dispatch) => Ok(Some(dispatch)),
            Err(RequesterEngineError::AuthenticatedProtocolViolation(violation)) => {
                let notice = match session
                    .runtime
                    .close_for_operation_violation(OperationViolation::Requester(violation))
                {
                    RuntimeReceive::ViolationClosed { notice, .. } => notice,
                    _ => None,
                };
                session.close_with(notice, SessionEnd::Violation);
                Err(SessionError::Violation)
            }
            Err(_) => {
                session.finish(SessionEnd::Violation);
                Err(SessionError::EngineFault)
            }
        }
    }

    /// Advances the session's liveness clock: a ping after five seconds of
    /// silence, the end after thirty (section 8.3).
    fn keep_alive<Transport: FrameTransport>(
        session: &mut Session<Transport>,
    ) -> Result<(), SessionError> {
        let Ok(challenge) = PingChallenge::random() else {
            return Err(SessionError::EngineFault);
        };
        let now_ms = session.clock_ms();
        match session.runtime.poll(now_ms, challenge) {
            Ok(RuntimePoll::NoAction) => Ok(()),
            Ok(RuntimePoll::Send(ping)) => {
                session
                    .transport
                    .send_frame(ping.as_bytes())
                    .map_err(|error| {
                        session.finish(SessionEnd::TransportLoss);
                        SessionError::Transport(error)
                    })
            }
            Ok(RuntimePoll::SessionClosed(_)) => {
                session.finish(SessionEnd::TransportLoss);
                Err(SessionError::Transport(TransportError::TimedOut))
            }
            Ok(RuntimePoll::AlreadyClosed) | Err(_) => {
                session.finish(SessionEnd::TransportLoss);
                Err(SessionError::EngineFault)
            }
        }
    }

    /// Revokes every record stored before the peer confirmed its storage
    /// (section 4.3 item 4): such a record was written inside a
    /// confirmation window this endpoint did not complete, and its key is
    /// destroyed at once, nobody told (section 4.6 item 3). Returns how
    /// many were revoked.
    pub fn revoke_unconfirmed_pairings(&mut self) -> usize {
        self.remove_where(|record| record.state() == PairingState::StorageConfirming)
    }

    /// Forgets a pairing at the user's word (section 4.6) at `now_ms`, the
    /// wall clock. A usable pairing is marked forgotten: it serves nothing
    /// from now on and keeps its key only for the `pairing_revoked` close,
    /// which a session holding it sends at once and otherwise the next
    /// session sends first. A pairing the peer never confirmed is removed
    /// with its key, and nobody is told.
    ///
    /// # Errors
    /// [`StoreError`] when no record names `pair_id` or the store refuses
    /// the write.
    pub fn forget(&mut self, pair_id: PairId, now_ms: u64) -> Result<(), StoreError> {
        self.store
            .update(pair_id, &mut |record| match record.state() {
                PairingState::PairedDisconnected => Some(record.forgotten(now_ms)),
                PairingState::Revoking => Some(record),
                _ => None,
            })
    }

    /// Destroys, untold, every forgotten pairing whose key has waited the
    /// notice window for a session since its user forgot it (section 4.6
    /// item 3); `now_ms` is the wall clock. Returns how many were
    /// destroyed.
    pub fn expire_revocation_notices(&mut self, now_ms: u64) -> usize {
        self.remove_where(|record| record.pairing().revocation_notice_expired(now_ms))
    }

    /// Removes every record `doomed` names, as the store durably holds it,
    /// its key with it; returns how many went.
    fn remove_where(&mut self, doomed: impl Fn(&PairingRecord) -> bool) -> usize {
        let candidates: Vec<PairId> = self
            .store
            .pair_ids()
            .into_iter()
            .filter(|pair_id| self.store.get(*pair_id).is_ok_and(&doomed))
            .collect();
        candidates
            .into_iter()
            .filter(|pair_id| {
                let mut removed = false;
                let _ = self.store.update(*pair_id, &mut |record| {
                    removed = doomed(&record);
                    (!removed).then_some(record)
                });
                removed
            })
            .count()
    }

    /// Applies a peer close reason's pairing effect: `pairing_revoked`
    /// revokes the pairing at once, its key and record destroyed (section
    /// 4.6 item 4). No other reason, and no failure, touches the pairing
    /// (section 10.1).
    fn apply_peer_close_reason(&mut self, pair_id: PairId, reason: CloseReason) {
        if reason == CloseReason::PairingRevoked {
            let _ = self.store.remove(pair_id);
        }
    }
}

/// Waits up to [`CLOSE_LINGER`] for the peer to close its side after a
/// close this side sent, discarding whatever it still sends.
fn linger<Transport: FrameTransport>(transport: &mut Transport) {
    if transport.set_receive_deadline(CLOSE_LINGER).is_err() {
        return;
    }
    let deadline = Instant::now() + CLOSE_LINGER;
    while Instant::now() < deadline && transport.receive_frame().is_ok() {}
}

/// A monotonic deadline for one post-PAKE pairing phase (section 3.3).
#[derive(Clone, Copy, Debug)]
struct PhaseDeadline(Instant);

impl PhaseDeadline {
    fn after(window_ms: u64) -> Self {
        Self(Instant::now() + Duration::from_millis(window_ms))
    }

    fn check(self) -> Result<(), PairingError> {
        if Instant::now() > self.0 {
            Err(PairingError::DeadlineExpired)
        } else {
            Ok(())
        }
    }
}

/// Milliseconds since the Unix epoch: the wall clock that dates stored
/// pairing events, and the receipt time handed to the message decoder.
#[must_use]
pub fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod phase_deadline_tests {
    use std::time::{Duration, Instant};

    use super::{PairingError, PhaseDeadline};

    #[test]
    fn a_phase_past_its_window_fails_closed() {
        let open = PhaseDeadline::after(refineid_rapp::POST_PAKE_HANDSHAKE_MS);
        assert_eq!(open.check(), Ok(()));
        let elapsed = PhaseDeadline(Instant::now() - Duration::from_millis(1));
        assert_eq!(elapsed.check(), Err(PairingError::DeadlineExpired));
    }
}
