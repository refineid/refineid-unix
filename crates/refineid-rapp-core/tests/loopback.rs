//! Loopback conformance tests: the requester engine against a scripted
//! custodian running the engine's custodian half over the same wire.
//!
//! The custodian here is test scaffolding, not a product: the real
//! custodians are the holder's phones. It speaks the exact wire of RAPP
//! v26.10.29 so the requester is exercised end to end - code pairing
//! through `CPace` KC2 and `Noise_XXpsk3` with grant agreement, `Noise_KK`
//! sessions opened by the custodian's `session.ready`, card reports with
//! the certificate fingerprint, operations and their results, the
//! revocation close in both directions, liveness, and the
//! `protocol_violation` close that keeps the pairing.

#![allow(
    clippy::unwrap_used,
    reason = "test scaffolding is constructed to be infallible"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "tests panic to fail; documenting each panic adds nothing"
)]

use std::collections::VecDeque;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use refineid_rapp::{
    BinaryFrame, CPACE_ATTEMPT_WINDOW_MS, CardInspection, CardKeyProfile as KeyProfile,
    CardOperation, CardOperationResult, CardPresence, CardReader, CardStatusMessage,
    CertificateFingerprint, CloseReason, CpaceKc2Responder, DEFAULT_OPERATION_LIFETIME_MS,
    EndpointRole, EstablishedSessionRuntime, LIVENESS_CHALLENGE_SIZE,
    LIVENESS_PING_AFTER_SILENCE_MS, OFFER_ID_SIZE, OfferId, OperationId, OperationRequest,
    OperationResultMessage, PAIRING_BUSY_RETRY_AFTER_MIN_MS, PAIRING_CANDIDATES_MAX,
    PAIRING_IDLE_EXPIRY_MS, PairId, PairRecord, PairingBusy, PairingHandshake, PairingOffer,
    PairingState, PingChallenge, ProfileName, ProgressEvent, ProtocolErrorMessage, ProxyDispatch,
    ProxyFailure, ProxyOperationEngine, QUIT_WITHDRAWAL_BOUND_MS, REVOCATION_NOTICE_MS,
    ResultError, RuntimePoll, RuntimeReceive, SESSION_READY_NONCE_SIZE, SessionHandshake,
    SignatureAlgorithm, SweepError, SweepOutcome, TransportProfile, TypedMessage, UserApproval,
    decode_pair_record, encode_pair_record, generate_pair_key_material,
    standard_pairing_context_v2,
};
use refineid_rapp_core::engine::{
    AdmissionError, OpenedConnection, OperationOutcome, PairingCandidateSource, PairingConnection,
    PairingError, PairingSearchError, Requester, RequesterConfig, Session, SessionEnd,
    SessionError, Withdrawal, current_time_ms,
};
use refineid_rapp_core::file_store::FilePairingStore;
use refineid_rapp_core::profiles::{
    PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS, PROFILE_DOCUMENT_SIGNING,
};
use refineid_rapp_core::remote::{CardRequest, RemoteError, RemoteReader, execute_on_session};
use refineid_rapp_core::store::{MemoryPairingStore, PairingRecord, PairingStore, StoreError};
use refineid_rapp_core::transport::{FrameTransport, MemoryTransport, TransportError};

/// A generous deadline for scripted exchanges.
const DEADLINE: Duration = Duration::from_secs(2);
/// The candidate identifier used by every loopback test.
const CANDIDATE: &str = "loopback-1";
/// The custodian's clock at the start of every scripted session.
const SESSION_START_MS: u64 = 1_000_000;
/// The code the scripted custodian shows.
const SHOWN_CODE: &str = "7KX4M9";
/// The name the scripted custodian introduces itself with.
const CUSTODIAN_NAME: &str = "Phone";
/// The name a phone introduces itself with when its system hands the app
/// only the device type.
const DEVICE_TYPE_NAME: &str = "iPhone";
/// The code another phone in pairing mode shows.
const OTHER_CODE: &str = "7KX4MA";
/// The offer one custodian serves on each endpoint it is found on.
const SHARED_OFFER_ID: [u8; OFFER_ID_SIZE] = *b"synthetic offer of one custodian";
/// The endpoint of the second scripted custodian a search finds.
const SECOND_ENDPOINT: usize = 1;
/// How long a scripted custodian waits for the requester while it tries
/// another custodian first: longer than the attempt deadline.
const OUTLASTS_ATTEMPT: Duration = Duration::from_secs(10);
/// The wait a busy scripted custodian asks for when a test measures it.
const BUSY_WAIT_MS: u64 = 300;
/// Uniform bytes a `CPace` scalar is drawn from (section 6.1.1).
const CPACE_SCALAR_ENTROPY_BYTES: usize = 64;
/// Fixed custodian scalar entropy for the scripted exchange.
const CUSTODIAN_ENTROPY: [u8; CPACE_SCALAR_ENTROPY_BYTES] =
    *b"synthetic custodian cpace scalar entropy: sixty-four bytes long.";
/// The nonce of the scripted custodian's `session.ready`.
const READY_NONCE: [u8; SESSION_READY_NONCE_SIZE] = *b"synthetic session.ready nonce 32";
/// The challenge of the scripted custodian's ping.
const PING_CHALLENGE: [u8; LIVENESS_CHALLENGE_SIZE] = *b"synthetic liveness challenge 32b";
/// A synthetic answer to reset.
const SYNTHETIC_ATR: &[u8] = b"synthetic answer to reset";
/// A synthetic authentication certificate of the card on the phone.
const CERTIFICATE: &[u8] = b"synthetic authentication certificate";
/// A synthetic authentication certificate of another card.
const OTHER_CERTIFICATE: &[u8] = b"synthetic certificate of another card";
/// Bytes of a SHA-256 digest, as `rsa_pkcs1_sha256` signs (section 9.2).
const SHA256_DIGEST_BYTES: usize = 32;
/// The byte a synthetic digest repeats.
const DIGEST_BYTE: u8 = b'd';
/// The byte a synthetic signature repeats.
const SIGNATURE_BYTE: u8 = b's';
/// The lifetime the requester asks for.
const LIFETIME_MS: u64 = 30_000;
/// A signature stand-in sized for an RSA 3072-bit key.
const RSA_3072_SIGNATURE_BYTES: usize = 384;
/// How long a test waits for the requester's liveness ping: a ping is due
/// five seconds into a silence and leaves within one second of that.
const PING_WAIT: Duration = Duration::from_secs(7);
/// How long a test serves a session to take in a report sent at once.
const SERVICE_WAIT: Duration = Duration::from_millis(500);
/// How long the scripted phone takes to report its card in the waiting
/// tests.
const SHORT_DELAY: Duration = Duration::from_millis(150);
const LONG_DELAY: Duration = Duration::from_millis(400);
/// The extension of a pairing record file.
const RECORD_EXTENSION: &str = "pair";
/// How many failed session handshakes a test runs in a row.
const HANDSHAKE_FAILURES: usize = 3;
/// A wait for a card shorter than [`LONG_DELAY`].
const SHORT_WAIT: Duration = Duration::from_millis(100);
/// How long a requester that quits waits for its withdrawal closes to
/// leave (section 4.5 item 8).
const QUIT_BOUND: Duration = Duration::from_millis(QUIT_WITHDRAWAL_BOUND_MS);

/// The custodian's random stream offer and its bootstrap bytes (section
/// 4.2), and the CPace context it binds.
fn custodian_offer() -> (PairingOffer, Vec<u8>, Vec<u8>) {
    let mut offer_id = [0_u8; OFFER_ID_SIZE];
    getrandom::fill(&mut offer_id).unwrap();
    custodian_offer_with(OfferId::from_array(offer_id))
}

/// As [`custodian_offer`], under `offer_id`.
fn custodian_offer_with(offer_id: OfferId) -> (PairingOffer, Vec<u8>, Vec<u8>) {
    let offer = PairingOffer::create(
        offer_id,
        vec![
            PROFILE_CARD_STATUS.to_owned(),
            PROFILE_AUTHENTICATION.to_owned(),
            PROFILE_DOCUMENT_SIGNING.to_owned(),
        ],
        &[TransportProfile::Stream],
    )
    .unwrap();
    let bytes = offer.to_cbor().unwrap();
    let context = standard_pairing_context_v2(
        &offer.offer_hash().unwrap(),
        TransportProfile::Stream.name(),
        TransportProfile::Stream.candidate_id(),
    )
    .unwrap();
    (offer, bytes, context)
}

/// The requester engine type under test.
type TestRequester = Requester<MemoryPairingStore>;

/// A store whose writes can be refused, standing for a computer that
/// stopped before it could rewrite a record.
#[derive(Debug, Default)]
struct HaltingStore {
    inner: MemoryPairingStore,
    halted: bool,
}

impl PairingStore for HaltingStore {
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        self.inner.insert(record)
    }

    fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError> {
        self.inner.get(pair_id)
    }

    fn update(
        &mut self,
        pair_id: PairId,
        change: &mut dyn FnMut(PairingRecord) -> Option<PairingRecord>,
    ) -> Result<(), StoreError> {
        if self.halted {
            return Err(StoreError::WriteRefused);
        }
        self.inner.update(pair_id, change)
    }

    fn sweep(
        &mut self,
        pair_id: PairId,
        now_ms: u64,
        session_established: bool,
    ) -> Result<SweepOutcome, SweepError<StoreError>> {
        if self.halted {
            return Err(SweepError::Store(StoreError::WriteRefused));
        }
        self.inner.sweep(pair_id, now_ms, session_established)
    }

    fn pair_ids(&self) -> Vec<PairId> {
        self.inner.pair_ids()
    }
}

fn test_requester() -> TestRequester {
    requester_over(MemoryPairingStore::new())
}

/// A fresh directory for a file store.
fn scratch_directory() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "refineid-rapp-loopback-{:x}",
        getrandom::u64().unwrap()
    ))
}

/// The pairing record files in `directory`, each with its bytes, in name
/// order.
fn record_files(directory: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut files: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == RECORD_EXTENSION))
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    files.sort();
    files
}

/// A requester engine over `store`.
fn requester_over<Store: PairingStore>(store: Store) -> Requester<Store> {
    Requester::new(
        RequesterConfig {
            display_name: "Workstation".into(),
            platform: "Linux".into(),
        },
        store,
    )
}

/// A registered consequential operation for the authentication tests.
fn authentication_operation() -> CardOperation {
    CardOperation::BrowserAuthenticate {
        origin: "login.example.com".into(),
        key_profile: KeyProfile::Rsa3072,
        algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
        digest: vec![DIGEST_BYTE; SHA256_DIGEST_BYTES],
    }
}

/// The card report of a phone serving the card whose certificate is
/// `certificate` over NFC, with no card reader attached.
fn present(certificate: &[u8]) -> CardStatusMessage {
    CardStatusMessage {
        card: CardPresence::Present(CertificateFingerprint::of_certificate(certificate)),
        reader: CardReader::Absent,
    }
}

/// The card report of a phone holding no card, with `reader` as its card
/// reader stands.
const fn absent(reader: CardReader) -> CardStatusMessage {
    CardStatusMessage {
        card: CardPresence::Absent,
        reader,
    }
}

/// Whether the scripted custodian confirms its storage (section 4.3 item
/// 4) or goes silent after the grant exchange.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StorageConfirmation {
    Confirmed,
    Silent,
}

/// Runs the custodian half of code pairing and returns its stored half:
/// `CPace` KC2 as responder, then `Noise_XXpsk3` under its key, then the
/// hello, confirmation, and storage exchanges.
fn proxy_pair<T: FrameTransport>(transport: T, shown_code: &str) -> PairRecord {
    proxy_pair_confirming(
        transport,
        shown_code,
        CUSTODIAN_NAME,
        StorageConfirmation::Confirmed,
    )
    .expect("the confirming custodian stores its record")
}

/// As [`proxy_pair`], introducing the custodian as `display_name`; a
/// `Silent` custodian stores nothing and leaves the requester without its
/// `pairing.stored`.
fn proxy_pair_confirming<T: FrameTransport>(
    transport: T,
    shown_code: &str,
    display_name: &str,
    confirmation_mode: StorageConfirmation,
) -> Option<PairRecord> {
    proxy_pair_serving(
        transport,
        shown_code,
        display_name,
        confirmation_mode,
        custodian_offer(),
    )
}

/// As [`proxy_pair_confirming`], serving `offer`.
fn proxy_pair_serving<T: FrameTransport>(
    mut transport: T,
    shown_code: &str,
    display_name: &str,
    confirmation_mode: StorageConfirmation,
    (offer, bootstrap, context): (PairingOffer, Vec<u8>, Vec<u8>),
) -> Option<PairRecord> {
    let now_ms = SESSION_START_MS;
    let candidate = TransportProfile::Stream.candidate_id();
    transport.send_frame(&bootstrap).unwrap();

    let step_one = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    let (step_two, waiting) = CpaceKc2Responder::process_step1_frame(
        shown_code,
        &context,
        &offer.offer_id,
        &step_one,
        &CUSTODIAN_ENTROPY,
    )
    .unwrap();
    transport.send_frame(step_two.as_bytes()).unwrap();
    let step_three = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    let secret = waiting.process_step3_frame(&step_three).unwrap();

    let local_keys = generate_pair_key_material().unwrap();
    let mut handshake =
        PairingHandshake::begin(EndpointRole::Proxy, offer, candidate, local_keys, &secret)
            .unwrap();

    let m1 = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    handshake.read_message(&m1).unwrap();
    let m2 = handshake.write_message().unwrap();
    transport.send_frame(m2.as_bytes()).unwrap();
    let m3 = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    handshake.read_message(&m3).unwrap();

    let mut confirmation = handshake.into_confirmation().unwrap();
    let hello = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    confirmation.receive_hello(&hello, now_ms).unwrap();
    let proxy_hello = confirmation
        .send_hello(display_name.into(), "iOS".into())
        .unwrap();
    transport.send_frame(proxy_hello.as_bytes()).unwrap();
    let requester_confirmation =
        BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    let granted = confirmation
        .receive_confirmation(&requester_confirmation, now_ms)
        .unwrap()
        .to_vec();
    let proxy_confirmation = confirmation.send_confirmation(granted).unwrap();
    transport.send_frame(proxy_confirmation.as_bytes()).unwrap();
    let (record, mut storage) = confirmation.into_storage(now_ms).unwrap();
    let requester_stored = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    storage.receive_stored(&requester_stored, now_ms).unwrap();
    if confirmation_mode == StorageConfirmation::Silent {
        return None;
    }
    let proxy_stored = storage.send_stored().unwrap();
    transport.send_frame(proxy_stored.as_bytes()).unwrap();
    Some(storage.into_active().unwrap().confirm(record).unwrap())
}

/// The custodian half of one healthy session: its runtime and the
/// engine's custodian operation engine.
struct Custodian<T: FrameTransport> {
    runtime: EstablishedSessionRuntime,
    operations: ProxyOperationEngine,
    transport: T,
}

impl<T: FrameTransport> Custodian<T> {
    fn send(&mut self, message: &TypedMessage) {
        let frame = self.runtime.endpoint_mut().send(message).unwrap();
        self.transport.send_frame(frame.as_bytes()).unwrap();
    }

    fn report_card(&mut self, status: CardStatusMessage) {
        self.send(&ProxyOperationEngine::report_card_status(status));
    }

    /// The next frame from the requester, opened by the runtime.
    fn receive(&mut self) -> RuntimeReceive {
        let frame = BinaryFrame::reconstruct(self.transport.receive_frame().unwrap()).unwrap();
        self.runtime.receive(&frame, SESSION_START_MS).unwrap()
    }

    /// The next message that is not liveness traffic, answering pings.
    fn receive_message(&mut self) -> TypedMessage {
        loop {
            match self.receive() {
                RuntimeReceive::Message(message) => return message,
                RuntimeReceive::Send(pong) => self.transport.send_frame(pong.as_bytes()).unwrap(),
                RuntimeReceive::LivenessConfirmed | RuntimeReceive::IgnoredStalePong => {}
                other => panic!("expected a message, got {other:?}"),
            }
        }
    }

    /// The requester's close, answering pings until it arrives.
    fn receive_close(&mut self) -> CloseReason {
        loop {
            match self.receive() {
                RuntimeReceive::PeerClosed(reason) => return reason,
                RuntimeReceive::Send(pong) => self.transport.send_frame(pong.as_bytes()).unwrap(),
                RuntimeReceive::LivenessConfirmed | RuntimeReceive::IgnoredStalePong => {}
                other => panic!("expected the requester's close, got {other:?}"),
            }
        }
    }

    /// Admits the next request into the custodian's engine.
    fn admit(&mut self) -> OperationRequest {
        let TypedMessage::OperationRequest(request) = self.receive_message() else {
            panic!("expected an operation request");
        };
        let dispatch = self
            .operations
            .receive(TypedMessage::OperationRequest(request.clone()))
            .unwrap();
        assert!(matches!(
            dispatch,
            ProxyDispatch::InspectPrerequisites(id) if id == request.operation_id
        ));
        request
    }

    /// Sends what the custodian's engine produced.
    fn send_dispatch(&mut self, dispatch: ProxyDispatch) {
        let ProxyDispatch::Send(message) = dispatch else {
            panic!("expected a message to send, got {dispatch:?}");
        };
        self.send(&message);
    }

    /// Runs an admitted read to the card's `answer`.
    fn answer_read(&mut self, operation_id: OperationId, answer: &CardOperationResult) {
        let dispatch = self
            .operations
            .prerequisites_complete(
                operation_id,
                SESSION_START_MS,
                DEFAULT_OPERATION_LIFETIME_MS,
            )
            .unwrap();
        assert!(matches!(dispatch, ProxyDispatch::ExecuteSafeRead { .. }));
        let result = OperationResultMessage::completed(operation_id, answer);
        let finished = self
            .operations
            .finish_completed(operation_id, result)
            .unwrap();
        self.send_dispatch(finished);
    }

    /// Takes an admitted consequential request to the holder's PIN prompt,
    /// which is the holder's consent (section 8.2 item 3), and reports the
    /// prompt on screen.
    fn show_pin_prompt(&mut self, request: &OperationRequest) {
        let dispatch = self
            .operations
            .prerequisites_complete(
                request.operation_id,
                SESSION_START_MS,
                DEFAULT_OPERATION_LIFETIME_MS,
            )
            .unwrap();
        assert!(matches!(dispatch, ProxyDispatch::AwaitConsent(_)));
        let shown = self
            .operations
            .report_progress(request.operation_id, ProgressEvent::ConsentShown)
            .unwrap();
        self.send(&shown);
    }
}

/// Accepts one session as the custodian: the `Noise_KK` handshake, then
/// `session.ready`, the custodian's first message (section 7.1 item 5).
fn custodian_session<T: FrameTransport>(record: &PairRecord, mut transport: T) -> Custodian<T> {
    let mut handshake = SessionHandshake::begin_proxy(record, TransportProfile::Stream).unwrap();
    let m1 = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    handshake.read_message(&m1).unwrap();
    let m2 = handshake.write_message().unwrap();
    transport.send_frame(m2.as_bytes()).unwrap();
    let mut authentication = handshake.into_authentication().unwrap();
    let ready = authentication.send_ready(READY_NONCE).unwrap();
    transport.send_frame(ready.as_bytes()).unwrap();
    Custodian {
        runtime: EstablishedSessionRuntime::new(
            authentication.into_established().unwrap(),
            SESSION_START_MS,
        ),
        operations: ProxyOperationEngine::new(record.serving_profiles().to_vec()),
        transport,
    }
}

/// As [`custodian_session`], reporting the card at once (section 8.4).
fn custodian_with_card<T: FrameTransport>(record: &PairRecord, transport: T) -> Custodian<T> {
    let mut custodian = custodian_session(record, transport);
    custodian.report_card(present(CERTIFICATE));
    custodian
}

/// Pairs a fresh requester with a custodian thread and returns both halves.
fn paired<Store: PairingStore>(
    requester: &mut Requester<Store>,
    granted: &[ProfileName],
) -> (PairId, PairRecord) {
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || proxy_pair(proxy_transport, SHOWN_CODE));
    let (pair_id, ()) = requester
        .pair_with_code(
            "7k x4-m9",
            &mut OpenedConnection::new(requester_transport),
            |peer, _requested| {
                assert_eq!(peer.display_name, CUSTODIAN_NAME);
                Some(granted.to_vec())
            },
        )
        .unwrap();
    let proxy_record = proxy.join().unwrap();
    assert_eq!(proxy_record.pair_id(), pair_id);
    (pair_id, proxy_record)
}

/// Opens a session with the custodian thread running `script` on its
/// half, and waits for the custodian's first card report.
fn connected<Store: PairingStore, F>(
    requester: &mut Requester<Store>,
    pair_id: PairId,
    record: PairRecord,
    script: F,
) -> (Session<MemoryTransport>, JoinHandle<()>)
where
    F: FnOnce(Custodian<MemoryTransport>) + Send + 'static,
{
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let custodian = std::thread::spawn(move || {
        script(custodian_with_card(&record, proxy_transport));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    assert_eq!(
        requester.await_card_present(&mut session, DEADLINE),
        Ok(true)
    );
    (session, custodian)
}

#[test]
fn pairing_stores_matching_records_on_both_sides() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, _proxy) = paired(&mut requester, &granted);
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.pairing().profiles(), granted);
    assert_eq!(record.state(), PairingState::PairedDisconnected);
    assert_eq!(record.peer().display_name, CUSTODIAN_NAME);
}

#[test]
fn a_phone_is_listed_under_the_name_it_gave_inside_the_pairing_channel() {
    let directory = scratch_directory();
    let mut requester = requester_over(FilePairingStore::open(&directory).unwrap());
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    // The phone's system hands its app only the device type, so that is
    // the name its `pairing.hello` carries.
    let proxy = std::thread::spawn(move || {
        proxy_pair_confirming(
            proxy_transport,
            SHOWN_CODE,
            DEVICE_TYPE_NAME,
            StorageConfirmation::Confirmed,
        )
    });
    let (pair_id, ()) = requester
        .pair_with_code(
            SHOWN_CODE,
            &mut OpenedConnection::new(requester_transport),
            |peer, requested| {
                assert_eq!(peer.display_name, DEVICE_TYPE_NAME);
                Some(requested.to_vec())
            },
        )
        .unwrap();
    proxy.join().unwrap().unwrap();
    // The listed name is the one from the authenticated exchange alone;
    // nothing a discovery record names stands in for it.
    let reader = RemoteReader::with_store(
        "Workstation",
        "Linux",
        FilePairingStore::open_without_sweep(&directory).unwrap(),
    );
    let phone = reader.phone().unwrap();
    assert_eq!(phone.pair_id, pair_id);
    assert_eq!(phone.peer_display_name, DEVICE_TYPE_NAME);
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn a_custodian_that_never_confirms_its_storage_leaves_no_record() {
    let mut requester = test_requester();
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        proxy_pair_confirming(
            proxy_transport,
            SHOWN_CODE,
            CUSTODIAN_NAME,
            StorageConfirmation::Silent,
        )
    });
    let outcome = requester.pair_with_code(
        SHOWN_CODE,
        &mut OpenedConnection::new(requester_transport),
        |_, requested| Some(requested.to_vec()),
    );
    assert!(proxy.join().unwrap().is_none());
    assert_eq!(
        outcome,
        Err(PairingSearchError::Ceremony(
            PairingError::StorageUnconfirmed
        ))
    );
    // Section 4.3 item 4: the record stored here is revoked, its key
    // destroyed at once.
    assert!(requester.store().pair_ids().is_empty());
}

#[test]
fn an_unconfirmed_record_found_at_start_up_is_revoked() {
    let mut requester = Requester::new(
        RequesterConfig {
            display_name: "Workstation".into(),
            platform: "Linux".into(),
        },
        HaltingStore::default(),
    );
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        proxy_pair_confirming(
            proxy_transport,
            SHOWN_CODE,
            CUSTODIAN_NAME,
            StorageConfirmation::Silent,
        )
    });
    // The computer stops after storing its record, before the record of a
    // pairing the phone never confirmed could go: it stays unconfirmed.
    requester.store_mut().halted = true;
    let outcome = requester.pair_with_code(
        SHOWN_CODE,
        &mut OpenedConnection::new(requester_transport),
        |_, requested| Some(requested.to_vec()),
    );
    assert!(proxy.join().unwrap().is_none());
    assert_eq!(
        outcome,
        Err(PairingSearchError::Ceremony(
            PairingError::StorageUnconfirmed
        ))
    );
    let pair_ids = requester.store().pair_ids();
    let [pair_id] = pair_ids.as_slice() else {
        panic!("one unconfirmed record");
    };
    assert_eq!(
        requester.store().get(*pair_id).unwrap().state(),
        PairingState::StorageConfirming
    );
    let (unused, _other) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert!(matches!(
        requester.connect(*pair_id, unused),
        Err(SessionError::NotPaired(PairingState::StorageConfirming))
    ));
    // At the next start, section 4.3 item 4 revokes it.
    requester.store_mut().halted = false;
    assert_eq!(requester.revoke_unconfirmed_pairings(), 1);
    assert!(requester.store().pair_ids().is_empty());
}

#[test]
fn a_session_reports_which_card_the_phone_serves() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut custodian = custodian_session(&proxy_pairing, proxy_transport);
        custodian.report_card(absent(CardReader::Absent));
        std::thread::sleep(SHORT_DELAY);
        custodian.report_card(present(CERTIFICATE));
        custodian.report_card(present(OTHER_CERTIFICATE));
        assert_eq!(custodian.receive_close(), CloseReason::Normal);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    assert_eq!(session.card_status(), None);
    // Section 8.4: a card reported after the dial is waited for, and the
    // report names the card by its certificate's fingerprint.
    assert_eq!(
        requester.await_card_present(&mut session, DEADLINE),
        Ok(true)
    );
    assert_eq!(session.card_status(), Some(present(CERTIFICATE)));
    requester.service(&mut session, SERVICE_WAIT).unwrap();
    assert_eq!(session.card_status(), Some(present(OTHER_CERTIFICATE)));
    requester.disconnect(&mut session, CloseReason::Normal);
    proxy.join().unwrap();
}

#[test]
fn a_wait_for_a_card_that_runs_out_leaves_the_session_open() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut custodian = custodian_session(&proxy_pairing, proxy_transport);
        custodian.report_card(absent(CardReader::Absent));
        std::thread::sleep(LONG_DELAY);
        custodian.report_card(present(CERTIFICATE));
        custodian.receive_close();
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    // The phone's first report is absence: a report all the same.
    assert_eq!(
        requester.await_card_report(&mut session, SHORT_WAIT),
        Ok(true)
    );
    // The wait runs out before the phone reports a card; the session is
    // neither closed nor marked lost.
    assert_eq!(
        requester.await_card_present(&mut session, SHORT_WAIT),
        Ok(false)
    );
    assert_eq!(session.card_present(), Some(false));
    assert!(session.end().is_none());
    assert_eq!(
        requester.await_card_present(&mut session, DEADLINE),
        Ok(true)
    );
    requester.disconnect(&mut session, CloseReason::Normal);
    proxy.join().unwrap();
}

#[test]
fn a_custodian_that_revoked_closes_in_place_of_ready_and_the_pairing_goes_here() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut handshake =
            SessionHandshake::begin_proxy(&proxy_pairing, TransportProfile::Stream).unwrap();
        let m1 = BinaryFrame::reconstruct(proxy_transport.receive_frame().unwrap()).unwrap();
        handshake.read_message(&m1).unwrap();
        let m2 = handshake.write_message().unwrap();
        proxy_transport.send_frame(m2.as_bytes()).unwrap();
        let mut authentication = handshake.into_authentication().unwrap();
        let notice = authentication.send_revocation_notice().unwrap();
        proxy_transport.send_frame(notice.as_bytes()).unwrap();
    });
    assert_eq!(
        requester.connect(pair_id, requester_transport).err(),
        Some(SessionError::ClosedByPeer(CloseReason::PairingRevoked))
    );
    proxy.join().unwrap();
    // Section 4.6 item 4: the pairing is revoked at once and its key goes.
    assert!(requester.store().get(pair_id).is_err());
}

#[test]
fn a_pairing_revoked_close_in_session_revokes_here() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) =
        connected(&mut requester, pair_id, proxy_pairing, |mut custodian| {
            let notice = custodian
                .runtime
                .close_with_reason(CloseReason::PairingRevoked)
                .unwrap();
            custodian.transport.send_frame(notice.as_bytes()).unwrap();
        });
    assert_eq!(
        requester.service(&mut session, DEADLINE),
        Err(SessionError::ClosedByPeer(CloseReason::PairingRevoked))
    );
    proxy.join().unwrap();
    assert_eq!(
        session.end(),
        Some(SessionEnd::PeerClose(CloseReason::PairingRevoked))
    );
    assert_eq!(session.card_status(), None);
    assert!(requester.store().get(pair_id).is_err());
}

#[test]
fn a_pairing_forgotten_while_disconnected_tells_the_phone_first_and_loses_its_key() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    requester.forget(pair_id, current_time_ms()).unwrap();
    // Section 4.6 item 2: the forgotten record serves nothing.
    let (unused, _other) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert!(matches!(
        requester.connect(pair_id, unused),
        Err(SessionError::NotPaired(PairingState::Revoking))
    ));
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut custodian = custodian_with_card(&proxy_pairing, proxy_transport);
        assert_eq!(custodian.receive_close(), CloseReason::PairingRevoked);
    });
    requester
        .send_revocation_notice(pair_id, requester_transport)
        .unwrap();
    proxy.join().unwrap();
    // Section 4.6 item 3: the key is destroyed once the close is sent.
    assert!(requester.store().get(pair_id).is_err());
}

#[test]
fn a_pairing_forgotten_during_a_session_is_closed_on_it() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) =
        connected(&mut requester, pair_id, proxy_pairing, |mut custodian| {
            assert_eq!(custodian.receive_close(), CloseReason::PairingRevoked);
        });
    requester.forget(pair_id, current_time_ms()).unwrap();
    requester.revoke_in_session(&mut session);
    proxy.join().unwrap();
    assert_eq!(session.end(), Some(SessionEnd::LocalClose));
    assert!(requester.store().get(pair_id).is_err());
}

#[test]
fn a_pairing_another_program_forgot_during_a_session_loses_its_key_file_with_the_close() {
    let directory = scratch_directory();
    let mut requester = requester_over(FilePairingStore::open(&directory).unwrap());
    let (pair_id, proxy_pairing) = paired(&mut requester, &[ProfileName::CardStatus]);
    let (mut session, proxy) =
        connected(&mut requester, pair_id, proxy_pairing, |mut custodian| {
            assert_eq!(custodian.receive_close(), CloseReason::PairingRevoked);
        });
    // Another program on this computer forgets the phone while this one
    // holds the session; this program's copy of the record still reads
    // usable.
    FilePairingStore::open(&directory)
        .unwrap()
        .update(pair_id, &mut |record| {
            Some(record.forgotten(current_time_ms()))
        })
        .unwrap();
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
    requester.revoke_in_session(&mut session);
    proxy.join().unwrap();
    // Section 4.6 item 3: the key is destroyed once the close is sent,
    // file and all.
    assert!(requester.store().get(pair_id).is_err());
    assert!(
        FilePairingStore::open(&directory)
            .unwrap()
            .pair_ids()
            .is_empty()
    );
    assert!(record_files(&directory).is_empty());
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn a_session_handshake_that_fails_changes_nothing_stored() {
    /// What the scripted phone answers in place of `Noise_KK` message 2.
    const FORGED_ANSWER: &[u8] = b"synthetic answer that opens no session";
    let directory = scratch_directory();
    let mut requester = requester_over(FilePairingStore::open(&directory).unwrap());
    let (pair_id, _proxy) = paired(&mut requester, &[ProfileName::CardStatus]);
    let stored = record_files(&directory);
    assert!(
        !stored.is_empty(),
        "the pairing is stored before the failures"
    );
    for _ in 0..HANDSHAKE_FAILURES {
        let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
        let proxy = std::thread::spawn(move || {
            proxy_transport.receive_frame().unwrap();
            proxy_transport.send_frame(FORGED_ANSWER).unwrap();
        });
        assert_eq!(
            requester.connect(pair_id, requester_transport).err(),
            Some(SessionError::HandshakeFailed)
        );
        proxy.join().unwrap();
    }
    // Section 10.1 item 1: before authentication the connection closes
    // and nothing stored changes.
    assert_eq!(record_files(&directory), stored);
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn a_forgotten_pairing_untold_for_thirty_days_loses_its_key() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, _proxy) = paired(&mut requester, &granted);
    let forgotten_at = current_time_ms();
    requester.forget(pair_id, forgotten_at).unwrap();
    let window = REVOCATION_NOTICE_MS;
    assert_eq!(
        requester.expire_revocation_notices(forgotten_at + window - 1),
        0
    );
    assert!(requester.store().get(pair_id).is_ok());
    assert_eq!(
        requester.expire_revocation_notices(forgotten_at + window),
        1
    );
    assert!(requester.store().get(pair_id).is_err());
}

/// A second copy of the custodian's `record`, for a second session.
fn copy_of(record: &PairRecord) -> PairRecord {
    decode_pair_record(&encode_pair_record(record).unwrap()).unwrap()
}

/// The latest session time `requester` holds for `pair_id`.
fn last_session<Store: PairingStore>(requester: &Requester<Store>, pair_id: PairId) -> Option<u64> {
    requester
        .store()
        .get(pair_id)
        .unwrap()
        .pairing()
        .last_session_at_ms()
}

#[test]
fn a_session_notes_its_time_when_it_opens_and_when_it_ends() {
    let mut requester = test_requester();
    let (pair_id, proxy_pairing) = paired(&mut requester, &[ProfileName::CardStatus]);
    assert_eq!(last_session(&requester, pair_id), None);
    let before = current_time_ms();
    let (mut session, proxy) = connected(
        &mut requester,
        pair_id,
        copy_of(&proxy_pairing),
        |mut custodian| {
            assert_eq!(custodian.receive_close(), CloseReason::Normal);
        },
    );
    let opened = last_session(&requester, pair_id).unwrap();
    assert!(opened >= before);
    std::thread::sleep(SHORT_DELAY);
    requester.disconnect(&mut session, CloseReason::Normal);
    proxy.join().unwrap();
    let closed_here = last_session(&requester, pair_id).unwrap();
    assert!(closed_here > opened);
    // A session the phone ends is noted as well.
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, |custodian| {
        std::thread::sleep(SHORT_DELAY);
        let Custodian {
            mut runtime,
            mut transport,
            ..
        } = custodian;
        let notice = runtime.close_with_reason(CloseReason::Normal).unwrap();
        transport.send_frame(notice.as_bytes()).unwrap();
    });
    assert_eq!(
        requester.service(&mut session, DEADLINE),
        Err(SessionError::ClosedByPeer(CloseReason::Normal))
    );
    proxy.join().unwrap();
    assert!(last_session(&requester, pair_id).unwrap() > closed_here);
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
}

#[test]
fn a_pairing_without_a_session_for_thirty_days_expires_silently() {
    let mut requester = test_requester();
    let (pair_id, _proxy) = paired(&mut requester, &[ProfileName::CardStatus]);
    let created = requester
        .store()
        .get(pair_id)
        .unwrap()
        .pairing()
        .created_at_ms();
    assert_eq!(
        requester.expire_idle_pairings(created + PAIRING_IDLE_EXPIRY_MS - 1),
        Ok(0)
    );
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
    assert_eq!(
        requester.expire_idle_pairings(created + PAIRING_IDLE_EXPIRY_MS),
        Ok(1)
    );
    // Section 4.6 item 5: the pairing is revoked, serves nothing, and keeps
    // its key only for the close of a later session.
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.state(), PairingState::Revoking);
    assert!(record.pairing().serving_profiles().is_empty());
    let (unused, _other) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert!(matches!(
        requester.connect(pair_id, unused),
        Err(SessionError::NotPaired(PairingState::Revoking))
    ));
}

#[test]
fn the_idle_time_runs_from_the_latest_session() {
    let mut requester = test_requester();
    let (pair_id, proxy_pairing) = paired(&mut requester, &[ProfileName::CardStatus]);
    let created = requester
        .store()
        .get(pair_id)
        .unwrap()
        .pairing()
        .created_at_ms();
    std::thread::sleep(SHORT_DELAY);
    let (mut session, proxy) =
        connected(&mut requester, pair_id, proxy_pairing, |mut custodian| {
            assert_eq!(custodian.receive_close(), CloseReason::Normal);
        });
    requester.disconnect(&mut session, CloseReason::Normal);
    proxy.join().unwrap();
    let last = last_session(&requester, pair_id).unwrap();
    assert!(last > created);
    assert_eq!(
        requester.expire_idle_pairings(created + PAIRING_IDLE_EXPIRY_MS),
        Ok(0)
    );
    assert_eq!(
        requester.expire_idle_pairings(last + PAIRING_IDLE_EXPIRY_MS - 1),
        Ok(0)
    );
    assert_eq!(
        requester.expire_idle_pairings(last + PAIRING_IDLE_EXPIRY_MS),
        Ok(1)
    );
}

#[test]
fn a_pairing_in_session_never_expires() {
    let mut requester = test_requester();
    let (pair_id, proxy_pairing) = paired(&mut requester, &[ProfileName::CardStatus]);
    let (mut session, proxy) =
        connected(&mut requester, pair_id, proxy_pairing, |mut custodian| {
            assert_eq!(custodian.receive_close(), CloseReason::Normal);
        });
    let far = current_time_ms() + PAIRING_IDLE_EXPIRY_MS * 2;
    // The sweep notes the open session instead of expiring its pairing.
    assert_eq!(requester.expire_idle_pairings(far), Ok(0));
    assert_eq!(last_session(&requester, pair_id), Some(far));
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
    requester.disconnect(&mut session, CloseReason::Normal);
    proxy.join().unwrap();
    // Once it ended, the idle time runs from the latest time noted.
    assert_eq!(last_session(&requester, pair_id), Some(far));
    assert_eq!(
        requester.expire_idle_pairings(far + PAIRING_IDLE_EXPIRY_MS - 1),
        Ok(0)
    );
    assert_eq!(
        requester.expire_idle_pairings(far + PAIRING_IDLE_EXPIRY_MS),
        Ok(1)
    );
}

#[test]
fn an_idle_sweep_the_store_refused_is_repeated_by_the_next() {
    let mut requester = requester_over(HaltingStore::default());
    let (pair_id, _proxy) = paired(&mut requester, &[ProfileName::CardStatus]);
    let created = requester
        .store()
        .get(pair_id)
        .unwrap()
        .pairing()
        .created_at_ms();
    let expiry = created + PAIRING_IDLE_EXPIRY_MS;
    requester.store_mut().halted = true;
    assert_eq!(
        requester.expire_idle_pairings(expiry),
        Err(StoreError::WriteRefused)
    );
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
    requester.store_mut().halted = false;
    assert_eq!(requester.expire_idle_pairings(expiry), Ok(1));
    assert_eq!(
        requester
            .store()
            .get(pair_id)
            .unwrap()
            .pairing()
            .forgotten_at_ms(),
        Some(expiry)
    );
}

#[test]
fn a_mistyped_code_fails_at_the_custodian_tag_and_stores_nothing() {
    let mut requester = test_requester();
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let (offer, bootstrap, context) = custodian_offer();
        proxy_transport.send_frame(&bootstrap).unwrap();
        let step_one = BinaryFrame::reconstruct(proxy_transport.receive_frame().unwrap()).unwrap();
        let (step_two, _waiting) = CpaceKc2Responder::process_step1_frame(
            SHOWN_CODE,
            &context,
            &offer.offer_id,
            &step_one,
            &CUSTODIAN_ENTROPY,
        )
        .unwrap();
        proxy_transport.send_frame(step_two.as_bytes()).unwrap();
        // The requester refuses T_B and never answers with T_A.
        assert!(proxy_transport.receive_frame().is_err());
    });
    let outcome = requester.pair_with_code(
        OTHER_CODE,
        &mut OpenedConnection::new(requester_transport),
        |_, _| panic!("an unauthenticated attempt must never reach confirmation"),
    );
    proxy.join().unwrap();
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
    assert!(requester.store().pair_ids().is_empty());
}

#[test]
fn an_offer_without_the_connection_transport_is_refused_before_cpace() {
    let mut requester = test_requester();
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut offer_id = [0_u8; OFFER_ID_SIZE];
        getrandom::fill(&mut offer_id).unwrap();
        let ble_only = PairingOffer::create(
            OfferId::from_array(offer_id),
            vec![PROFILE_AUTHENTICATION.to_owned()],
            &[TransportProfile::Ble],
        )
        .unwrap();
        proxy_transport
            .send_frame(&ble_only.to_cbor().unwrap())
            .unwrap();
        // The requester refuses the offer and never sends Y_A.
        assert!(proxy_transport.receive_frame().is_err());
    });
    let outcome = requester.pair_with_code(
        SHOWN_CODE,
        &mut OpenedConnection::new(requester_transport),
        |_, _| panic!("a refused offer must never reach confirmation"),
    );
    proxy.join().unwrap();
    // A custodian whose offer is refused is not tried (section 4.2, "Trying
    // Each Custodian in Pairing Mode" item 2).
    assert_eq!(outcome, Err(PairingSearchError::NoneInPairingMode));
    assert!(requester.store().pair_ids().is_empty());
}

#[test]
fn input_that_is_not_a_code_never_touches_the_transport() {
    let mut requester = test_requester();
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let outcome = requester.pair_with_code(
        "7KX4MU",
        &mut OpenedConnection::new(requester_transport),
        |_, _| None,
    );
    assert_eq!(outcome, Err(PairingSearchError::InvalidCode));
    assert!(proxy_transport.receive_frame().is_err());
}

/// What a scripted custodian does on its half of one pairing connection.
type CustodianScript = Box<dyn FnOnce(MemoryTransport) + Send>;

/// Custodians in pairing mode at scripted endpoints, all found in the
/// first discovery round: endpoint `n` serves its scripted connections in
/// turn, one per opening.
struct ScriptedCustodians {
    connections: Vec<VecDeque<MemoryTransport>>,
    discovered: bool,
    /// The endpoints opened, in the order opened.
    opened: Vec<usize>,
}

impl PairingCandidateSource for ScriptedCustodians {
    type Endpoint = usize;
    type Transport = MemoryTransport;

    fn discover(&mut self) -> Option<Vec<usize>> {
        (!std::mem::replace(&mut self.discovered, true))
            .then(|| (0..self.connections.len()).collect())
    }

    fn open(&mut self, endpoint: &usize) -> Option<PairingConnection<MemoryTransport>> {
        let transport = self.connections.get_mut(*endpoint)?.pop_front()?;
        self.opened.push(*endpoint);
        PairingConnection::read(transport).ok()
    }
}

/// One scripted endpoint per script, each custodian on its own thread.
fn scripted(scripts: Vec<CustodianScript>) -> (ScriptedCustodians, Vec<JoinHandle<()>>) {
    scripted_openings(scripts.into_iter().map(|script| vec![script]).collect())
}

/// One scripted endpoint per list, serving one connection per script in
/// the list, each on its own thread.
fn scripted_openings(
    endpoints: Vec<Vec<CustodianScript>>,
) -> (ScriptedCustodians, Vec<JoinHandle<()>>) {
    let mut connections = Vec::new();
    let mut custodians = Vec::new();
    for scripts in endpoints {
        let mut openings = VecDeque::new();
        for script in scripts {
            let (requester_side, custodian_side) = MemoryTransport::pair(CANDIDATE, DEADLINE);
            openings.push_back(requester_side);
            custodians.push(std::thread::spawn(move || script(custodian_side)));
        }
        connections.push(openings);
    }
    let source = ScriptedCustodians {
        connections,
        discovered: false,
        opened: Vec::new(),
    };
    (source, custodians)
}

fn join(custodians: Vec<JoinHandle<()>>) {
    for custodian in custodians {
        custodian.join().unwrap();
    }
}

/// A custodian showing `shown_code` and serving `offer`: it answers `CPace`
/// step 1, and the requester, refusing its `T_B`, closes the connection.
fn refusing_custodian(
    mut transport: MemoryTransport,
    (offer, bootstrap, context): (PairingOffer, Vec<u8>, Vec<u8>),
    shown_code: &str,
) {
    transport.send_frame(&bootstrap).unwrap();
    let step_one = BinaryFrame::reconstruct(transport.receive_frame().unwrap()).unwrap();
    let (step_two, _waiting) = CpaceKc2Responder::process_step1_frame(
        shown_code,
        &context,
        &offer.offer_id,
        &step_one,
        &CUSTODIAN_ENTROPY,
    )
    .unwrap();
    transport.send_frame(step_two.as_bytes()).unwrap();
    assert_eq!(transport.receive_frame(), Err(TransportError::Eof));
}

/// A custodian showing another code, as a script.
fn refusing() -> CustodianScript {
    Box::new(|transport| refusing_custodian(transport, custodian_offer(), OTHER_CODE))
}

/// The custodian showing the code, as a script that waits out the tries
/// of the custodians before it.
fn accepting() -> CustodianScript {
    Box::new(|mut transport| {
        transport.set_receive_deadline(OUTLASTS_ATTEMPT).unwrap();
        proxy_pair(transport, SHOWN_CODE);
    })
}

/// A custodian serving `bootstrap` whose connection the requester closes
/// without sending `CPace` step 1.
fn untried_custodian(mut transport: MemoryTransport, bootstrap: &[u8]) {
    transport.send_frame(bootstrap).unwrap();
    assert_eq!(transport.receive_frame(), Err(TransportError::Eof));
}

#[test]
fn a_refusal_moves_on_to_the_phone_that_shows_the_code() {
    let mut requester = test_requester();
    let (mut custodians, threads) = scripted(vec![refusing(), accepting()]);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |peer, requested| {
        assert_eq!(peer.display_name, CUSTODIAN_NAME);
        Some(requested.to_vec())
    });
    join(threads);
    let (pair_id, endpoint) = outcome.unwrap();
    assert_eq!(endpoint, SECOND_ENDPOINT);
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
}

#[test]
fn the_code_is_not_accepted_only_after_every_phone_refused_it() {
    let mut requester = test_requester();
    let (mut custodians, threads) = scripted(vec![refusing(), refusing()]);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, _| {
        panic!("no phone showing another code reaches confirmation")
    });
    join(threads);
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
    assert_eq!(custodians.opened.len(), custodians.connections.len());
    assert_eq!(
        PairingSearchError::NotAccepted.to_string(),
        "the code was not accepted"
    );
    assert!(requester.store().pair_ids().is_empty());
}

#[test]
fn a_phone_found_on_two_endpoints_receives_one_guess() {
    let mut requester = test_requester();
    let offer = custodian_offer_with(OfferId::from_array(SHARED_OFFER_ID));
    let bootstrap = offer.1.clone();
    let (mut custodians, threads) = scripted(vec![
        Box::new(move |transport| refusing_custodian(transport, offer, OTHER_CODE)),
        Box::new(move |transport| untried_custodian(transport, &bootstrap)),
    ]);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, _| {
        panic!("a refused phone never reaches confirmation")
    });
    join(threads);
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
}

#[test]
fn a_phone_silent_past_the_attempt_deadline_is_passed_over() {
    let mut requester = test_requester();
    let silent: CustodianScript = Box::new(|mut transport| {
        let (_offer, bootstrap, _context) = custodian_offer();
        transport.set_receive_deadline(OUTLASTS_ATTEMPT).unwrap();
        transport.send_frame(&bootstrap).unwrap();
        assert!(transport.receive_frame().is_ok());
        assert_eq!(transport.receive_frame(), Err(TransportError::Eof));
    });
    let (mut custodians, threads) = scripted(vec![silent, accepting()]);
    let started = Instant::now();
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, requested| {
        Some(requested.to_vec())
    });
    join(threads);
    assert_eq!(outcome.map(|(_, endpoint)| endpoint), Ok(SECOND_ENDPOINT));
    assert!(started.elapsed() >= Duration::from_millis(CPACE_ATTEMPT_WINDOW_MS));
}

#[test]
fn a_search_opens_at_most_the_limit_of_connections() {
    let mut requester = test_requester();
    let mut scripts: Vec<CustodianScript> =
        (0..PAIRING_CANDIDATES_MAX).map(|_| refusing()).collect();
    scripts.push(Box::new(drop));
    let (mut custodians, threads) = scripted(scripts);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, _| {
        panic!("no phone showing another code reaches confirmation")
    });
    join(threads);
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
    assert_eq!(custodians.opened.len(), PAIRING_CANDIDATES_MAX);
}

#[test]
fn a_search_that_tried_no_phone_finds_none_in_pairing_mode() {
    let mut requester = test_requester();
    let (mut nobody, _) = scripted(Vec::new());
    assert_eq!(
        requester.pair_with_code(SHOWN_CODE, &mut nobody, |_, _| None),
        Err(PairingSearchError::NoneInPairingMode)
    );
    let (mut offerless, threads) = scripted(vec![Box::new(drop)]);
    assert_eq!(
        requester.pair_with_code(SHOWN_CODE, &mut offerless, |_, _| None),
        Err(PairingSearchError::NoneInPairingMode)
    );
    join(threads);
    assert_eq!(
        PairingSearchError::NoneInPairingMode.to_string(),
        "no phone in pairing mode was found"
    );
}

/// A custodian that cannot admit an attempt: it answers `pairing-busy`
/// asking for `wait_ms` at bootstrap and closes (section 4.2, "Busy
/// Refusal" item 1).
fn busy_for(wait_ms: u64) -> CustodianScript {
    Box::new(move |mut transport| {
        let busy = PairingBusy::new(wait_ms).unwrap().to_cbor().unwrap();
        transport.send_frame(&busy).unwrap();
    })
}

/// A custodian that served `offer` and can no longer admit the attempt
/// when step 1 arrives: it answers `pairing-busy` in place of step 2 and
/// closes (section 4.2, "Busy Refusal" item 2).
fn busy_after_step_one(offer: (PairingOffer, Vec<u8>, Vec<u8>)) -> CustodianScript {
    Box::new(move |mut transport| {
        let (_offer, bootstrap, _context) = offer;
        transport.send_frame(&bootstrap).unwrap();
        assert!(transport.receive_frame().is_ok());
        let busy = PairingBusy::new(PAIRING_BUSY_RETRY_AFTER_MIN_MS)
            .unwrap()
            .to_cbor()
            .unwrap();
        transport.send_frame(&busy).unwrap();
    })
}

#[test]
fn a_busy_phone_is_opened_again_after_the_phones_waiting() {
    let mut requester = test_requester();
    let (mut custodians, threads) = scripted_openings(vec![
        vec![busy_for(PAIRING_BUSY_RETRY_AFTER_MIN_MS), accepting()],
        vec![refusing()],
    ]);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, requested| {
        Some(requested.to_vec())
    });
    join(threads);
    assert_eq!(outcome.map(|(_, endpoint)| endpoint), Ok(0));
    assert_eq!(custodians.opened, [0, SECOND_ENDPOINT, 0]);
}

#[test]
fn a_busy_phone_is_opened_again_no_sooner_than_its_wait() {
    let mut requester = test_requester();
    let (mut custodians, threads) =
        scripted_openings(vec![vec![busy_for(BUSY_WAIT_MS), accepting()]]);
    let started = Instant::now();
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, requested| {
        Some(requested.to_vec())
    });
    join(threads);
    assert_eq!(outcome.map(|(_, endpoint)| endpoint), Ok(0));
    assert_eq!(custodians.opened, [0, 0]);
    assert!(started.elapsed() >= Duration::from_millis(BUSY_WAIT_MS));
}

#[test]
fn a_phone_busy_in_place_of_step_two_keeps_its_guess() {
    let mut requester = test_requester();
    let offer = custodian_offer_with(OfferId::from_array(SHARED_OFFER_ID));
    let served = offer.clone();
    let (mut custodians, threads) = scripted_openings(vec![vec![
        busy_after_step_one(offer),
        Box::new(move |mut transport| {
            transport.set_receive_deadline(OUTLASTS_ATTEMPT).unwrap();
            proxy_pair_serving(
                transport,
                SHOWN_CODE,
                CUSTODIAN_NAME,
                StorageConfirmation::Confirmed,
                served,
            )
            .unwrap();
        }),
    ]]);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, requested| {
        Some(requested.to_vec())
    });
    join(threads);
    assert_eq!(outcome.map(|(_, endpoint)| endpoint), Ok(0));
    assert_eq!(custodians.opened, [0, 0]);
}

#[test]
fn a_phone_busy_at_the_limit_has_not_accepted_the_code() {
    let mut requester = test_requester();
    let mut openings: Vec<CustodianScript> = (0..PAIRING_CANDIDATES_MAX)
        .map(|_| busy_for(PAIRING_BUSY_RETRY_AFTER_MIN_MS))
        .collect();
    openings.push(accepting_never_reached());
    let (mut custodians, threads) = scripted_openings(vec![openings]);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, _| {
        panic!("a busy phone never reaches confirmation")
    });
    drop(custodians.connections);
    join(threads);
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
    assert_eq!(custodians.opened.len(), PAIRING_CANDIDATES_MAX);
}

#[test]
fn a_search_that_saw_a_busy_answer_and_tried_no_phone_is_not_accepted() {
    let mut requester = test_requester();
    let (mut custodians, threads) = scripted_openings(vec![vec![
        busy_for(PAIRING_BUSY_RETRY_AFTER_MIN_MS),
        Box::new(drop),
    ]]);
    let outcome = requester.pair_with_code(SHOWN_CODE, &mut custodians, |_, _| {
        panic!("no phone was tried")
    });
    join(threads);
    assert_eq!(outcome, Err(PairingSearchError::NotAccepted));
    assert_eq!(custodians.opened, [0, 0]);
}

/// A custodian connection the requester never opens: it sees the
/// connection close unanswered.
fn accepting_never_reached() -> CustodianScript {
    Box::new(|mut transport| {
        transport.set_receive_deadline(OUTLASTS_ATTEMPT).unwrap();
        assert_eq!(transport.receive_frame(), Err(TransportError::Eof));
    })
}

#[test]
fn card_inspection_completes_as_a_read_without_a_prompt() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let answer = CardOperationResult::Inspection(CardInspection {
        answer_to_reset: SYNTHETIC_ATR.to_vec(),
    });
    let sent = answer.clone();
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, move |mut c| {
        let request = c.admit();
        c.answer_read(request.operation_id, &sent);
        c.receive_close();
    });
    let outcome = requester
        .execute(&mut session, &CardOperation::InspectCard, LIFETIME_MS)
        .unwrap();
    assert_eq!(outcome, OperationOutcome::Completed(answer));
    requester.disconnect(&mut session, CloseReason::Complete);
    proxy.join().unwrap();
}

#[test]
fn authentication_runs_through_the_pin_prompt_to_its_signature() {
    let mut requester = test_requester();
    let granted = [ProfileName::Authentication];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let signature = vec![SIGNATURE_BYTE; RSA_3072_SIGNATURE_BYTES];
    let sent = signature.clone();
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, move |mut c| {
        let request = c.admit();
        assert_eq!(request.operation, authentication_operation());
        c.show_pin_prompt(&request);
        let approval = UserApproval::for_request(&request, SESSION_START_MS);
        let ProxyDispatch::ExecuteCardCommand { command, .. } = c
            .operations
            .approve(
                request.operation_id,
                approval,
                SESSION_START_MS,
                DEFAULT_OPERATION_LIFETIME_MS,
            )
            .unwrap()
        else {
            panic!("an approval gives the card command");
        };
        command.execute(|authorized| assert_eq!(authorized.operation, request.operation));
        let result = OperationResultMessage::completed(
            request.operation_id,
            &CardOperationResult::Signature(sent),
        );
        let finished = c
            .operations
            .finish_completed(request.operation_id, result)
            .unwrap();
        c.send_dispatch(finished);
        c.receive_close();
    });
    let outcome = requester
        .execute(&mut session, &authentication_operation(), LIFETIME_MS)
        .unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Completed(CardOperationResult::Signature(signature))
    );
    requester.disconnect(&mut session, CloseReason::Complete);
    proxy.join().unwrap();
}

#[test]
fn the_lifetime_asked_for_reaches_the_wire() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, |mut c| {
        let request = c.admit();
        assert_eq!(request.expires_after_ms, LIFETIME_MS);
        let failed = c
            .operations
            .finish_failure(request.operation_id, ProxyFailure::OperationFailed)
            .unwrap();
        c.send_dispatch(failed);
        c.receive_close();
    });
    let outcome = requester
        .execute(&mut session, &CardOperation::ReadIdentity, LIFETIME_MS)
        .unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Rejected(ResultError::OperationFailed)
    );
    requester.disconnect(&mut session, CloseReason::Complete);
    proxy.join().unwrap();
}

#[test]
fn a_denial_ends_the_operation_and_the_session_carries_the_next() {
    let mut requester = test_requester();
    let granted = [ProfileName::Authentication, ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, |mut c| {
        let request = c.admit();
        c.show_pin_prompt(&request);
        let denied = c
            .operations
            .finish_failure(request.operation_id, ProxyFailure::UserDenied)
            .unwrap();
        c.send_dispatch(denied);
        let next = c.admit();
        assert_ne!(next.operation_id, request.operation_id);
        c.answer_read(
            next.operation_id,
            &CardOperationResult::Certificate(CERTIFICATE.to_vec()),
        );
        c.receive_close();
    });
    assert_eq!(
        requester
            .execute(&mut session, &authentication_operation(), LIFETIME_MS)
            .unwrap(),
        OperationOutcome::Rejected(ResultError::UserCancelled)
    );
    assert!(session.end().is_none());
    let read = CardOperation::ReadCertificate {
        kind: refineid_rapp::CertificateKind::Authentication,
    };
    assert_eq!(
        requester.execute(&mut session, &read, LIFETIME_MS).unwrap(),
        OperationOutcome::Completed(CardOperationResult::Certificate(CERTIFICATE.to_vec()))
    );
    requester.disconnect(&mut session, CloseReason::Complete);
    proxy.join().unwrap();
}

#[test]
fn a_request_past_its_deadline_is_cancelled_before_the_card() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, |mut c| {
        let request = c.admit();
        let expired = c
            .operations
            .prerequisites_complete(
                request.operation_id,
                SESSION_START_MS + LIFETIME_MS + 1,
                DEFAULT_OPERATION_LIFETIME_MS,
            )
            .unwrap();
        c.send_dispatch(expired);
        c.receive_close();
    });
    assert_eq!(
        requester
            .execute(&mut session, &CardOperation::InspectCard, LIFETIME_MS)
            .unwrap(),
        OperationOutcome::Cancelled(ResultError::OperationExpired)
    );
    requester.disconnect(&mut session, CloseReason::Complete);
    proxy.join().unwrap();
}

#[test]
fn a_refused_request_ends_with_the_error_the_phone_named() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, |mut c| {
        let TypedMessage::OperationRequest(request) = c.receive_message() else {
            panic!("expected an operation request");
        };
        c.send(&TypedMessage::Error(ProtocolErrorMessage::busy(
            request.operation_id,
        )));
        c.receive_close();
    });
    assert_eq!(
        requester
            .execute(&mut session, &CardOperation::InspectCard, LIFETIME_MS)
            .unwrap(),
        OperationOutcome::Rejected(ResultError::Busy)
    );
    requester.disconnect(&mut session, CloseReason::Complete);
    proxy.join().unwrap();
}

#[test]
fn an_unanswered_operation_ends_with_its_session() {
    let mut requester = test_requester();
    let granted = [ProfileName::Authentication];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, |mut c| {
        c.admit();
        // The phone goes away with the operation live: nothing of it
        // survives the session (section 8.1 item 3).
    });
    assert_eq!(
        requester
            .execute(&mut session, &authentication_operation(), LIFETIME_MS)
            .unwrap(),
        OperationOutcome::Lost
    );
    proxy.join().unwrap();
    assert_eq!(session.end(), Some(SessionEnd::TransportLoss));
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
}

#[test]
fn a_withdrawn_session_keeps_the_pairing_and_reports_the_reason() {
    let mut requester = test_requester();
    let granted = [ProfileName::Authentication];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, |mut c| {
        c.admit();
        let notice = c
            .runtime
            .close_with_reason(CloseReason::ServiceWithdrawn)
            .unwrap();
        c.transport.send_frame(notice.as_bytes()).unwrap();
    });
    let outcome = execute_on_session(
        &mut requester,
        &mut session,
        &authentication_operation(),
        Duration::from_millis(LIFETIME_MS),
    );
    proxy.join().unwrap();
    assert_eq!(outcome, Err(RemoteError::Withdrawn));
    assert_eq!(
        session.end(),
        Some(SessionEnd::PeerClose(CloseReason::ServiceWithdrawn))
    );
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
}

#[test]
fn quitting_during_the_pin_prompt_tells_the_phone_within_the_quit_bound() {
    let mut requester = test_requester();
    let withdrawal = Withdrawal::new();
    requester.follow(withdrawal.clone());
    let granted = [ProfileName::Authentication];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, move |mut c| {
        let request = c.admit();
        c.show_pin_prompt(&request);
        // The computer quits while the holder reads the prompt.
        let quit_at = Instant::now();
        withdrawal.raise();
        assert_eq!(c.receive_close(), CloseReason::ServiceWithdrawn);
        assert!(quit_at.elapsed() < QUIT_BOUND);
    });
    // The operation ends with its session (section 8.1 item 3).
    assert_eq!(
        requester
            .execute(&mut session, &authentication_operation(), LIFETIME_MS)
            .unwrap(),
        OperationOutcome::Lost
    );
    proxy.join().unwrap();
    assert_eq!(session.end(), Some(SessionEnd::LocalClose));
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
}

#[test]
fn a_withdrawal_closes_an_idle_session_keeps_the_pairing_and_dials_no_more() {
    let mut requester = test_requester();
    let withdrawal = Withdrawal::new();
    requester.follow(withdrawal.clone());
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, |mut c| {
        assert_eq!(c.receive_close(), CloseReason::ServiceWithdrawn);
    });
    withdrawal.raise();
    assert_eq!(
        requester.service(&mut session, DEADLINE),
        Err(SessionError::WithdrawnHere)
    );
    proxy.join().unwrap();
    assert_eq!(session.end(), Some(SessionEnd::LocalClose));
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
    // A connection made after the withdrawal closes without a notice.
    let (unused, mut custodian_side) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert!(matches!(
        requester.connect(pair_id, unused),
        Err(SessionError::WithdrawnHere)
    ));
    assert_eq!(custodian_side.receive_frame(), Err(TransportError::Eof));
}

#[test]
fn a_withdrawn_requester_sends_no_new_operation() {
    let mut requester = test_requester();
    let withdrawal = Withdrawal::new();
    requester.follow(withdrawal.clone());
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, |mut c| {
        // The close comes in place of the request.
        assert_eq!(c.receive_close(), CloseReason::ServiceWithdrawn);
    });
    withdrawal.raise();
    assert_eq!(
        requester.execute(&mut session, &CardOperation::InspectCard, LIFETIME_MS),
        Err(AdmissionError::SessionNotHealthy)
    );
    proxy.join().unwrap();
    assert_eq!(session.end(), Some(SessionEnd::LocalClose));
}

#[test]
fn a_result_that_does_not_answer_its_request_closes_the_session_and_keeps_the_pairing() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, |mut c| {
        let TypedMessage::OperationRequest(request) = c.receive_message() else {
            panic!("expected an operation request");
        };
        // A certificate is no answer to an inspection.
        c.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                request.operation_id,
                &CardOperationResult::Certificate(CERTIFICATE.to_vec()),
            ),
        ));
        assert_eq!(c.receive_close(), CloseReason::ProtocolViolation);
    });
    assert_eq!(
        requester
            .execute(&mut session, &CardOperation::InspectCard, LIFETIME_MS)
            .unwrap(),
        OperationOutcome::Refused
    );
    proxy.join().unwrap();
    assert_eq!(session.end(), Some(SessionEnd::Violation));
    assert_eq!(
        requester.store().get(pair_id).unwrap().state(),
        PairingState::PairedDisconnected
    );
}

#[test]
fn an_operation_needs_a_card_the_phone_reports() {
    // Section 8.4 item 6: the phone's reader is named only while the phone
    // reports one attached.
    for (reader, request) in [
        (CardReader::Attached, CardRequest::InPhoneReader),
        (CardReader::Absent, CardRequest::ToPhone),
    ] {
        let mut requester = test_requester();
        let granted = [ProfileName::CardStatus];
        let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
        let (mut session, proxy) =
            connected(&mut requester, pair_id, proxy_pairing, move |mut c| {
                c.report_card(absent(reader));
                c.receive_close();
            });
        requester.service(&mut session, SERVICE_WAIT).unwrap();
        assert_eq!(session.card_present(), Some(false));
        assert_eq!(
            execute_on_session(
                &mut requester,
                &mut session,
                &CardOperation::InspectCard,
                Duration::from_millis(LIFETIME_MS),
            ),
            Err(RemoteError::CardAbsent(request))
        );
        requester.disconnect(&mut session, CloseReason::Complete);
        proxy.join().unwrap();
    }
}

#[test]
fn the_phones_ping_is_answered_and_a_silence_brings_this_sides_ping() {
    let mut requester = test_requester();
    let granted = [ProfileName::CardStatus];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (mut session, proxy) = connected(&mut requester, pair_id, proxy_pairing, |mut c| {
        let challenge = PingChallenge::reconstruct(PING_CHALLENGE);
        let RuntimePoll::Send(ping) = c
            .runtime
            .poll(SESSION_START_MS + LIVENESS_PING_AFTER_SILENCE_MS, challenge)
            .unwrap()
        else {
            panic!("a silence of five seconds brings a ping");
        };
        c.transport.send_frame(ping.as_bytes()).unwrap();
        assert!(matches!(c.receive(), RuntimeReceive::LivenessConfirmed));
        // Silent from here: the requester pings within the wait.
        c.transport.set_receive_deadline(PING_WAIT).unwrap();
        let RuntimeReceive::Send(pong) = c.receive() else {
            panic!("expected the requester's ping");
        };
        c.transport.send_frame(pong.as_bytes()).unwrap();
        c.receive_close();
    });
    requester.service(&mut session, PING_WAIT).unwrap();
    assert!(session.end().is_none());
    requester.disconnect(&mut session, CloseReason::Complete);
    proxy.join().unwrap();
}

#[test]
fn stream_pairing_and_session_route_only_by_their_preambles() {
    use refineid_rapp::{RoutingKey, TransportProfile, route_session};
    use refineid_rapp_core::stream::{
        RoutingPreamble, STREAM_CANDIDATE_ID, StreamAccept, StreamListener, dial,
    };

    let listener = StreamListener::bind("127.0.0.1:0", STREAM_CANDIDATE_ID, DEADLINE).unwrap();
    let endpoints = vec![format!("127.0.0.1:{}", listener.local_port().unwrap())];
    let custodian = std::thread::spawn(move || {
        let StreamAccept::Pairing(transport) = listener.accept().unwrap() else {
            panic!("pairing opens with the pairing preamble");
        };
        let record = proxy_pair(transport, SHOWN_CODE);
        let StreamAccept::Session { routing, transport } = listener.accept().unwrap() else {
            panic!("a session opens with the session preamble");
        };
        let keys = [RoutingKey::derive(&record).unwrap()];
        assert_eq!(
            route_session(&keys, TransportProfile::Stream, &routing),
            Some(0)
        );
        let mut c = custodian_with_card(&record, transport);
        let request = c.admit();
        c.answer_read(
            request.operation_id,
            &CardOperationResult::Certificate(CERTIFICATE.to_vec()),
        );
        c.receive_close();
    });

    let mut requester = test_requester();
    let pairing = dial(
        &endpoints,
        STREAM_CANDIDATE_ID,
        DEADLINE,
        &RoutingPreamble::Pairing,
    )
    .unwrap();
    let (pair_id, ()) = requester
        .pair_with_code(
            SHOWN_CODE,
            &mut OpenedConnection::new(pairing),
            |_, requested| Some(requested.to_vec()),
        )
        .unwrap();
    let routing = RoutingKey::derive(requester.store().get(pair_id).unwrap().pairing())
        .unwrap()
        .route(TransportProfile::Stream, |nonce| {
            getrandom::fill(nonce).map_err(|_| refineid_rapp::RandomUnavailable)
        })
        .unwrap();
    let transport = dial(
        &endpoints,
        STREAM_CANDIDATE_ID,
        DEADLINE,
        &RoutingPreamble::Session(routing),
    )
    .unwrap();
    let mut session = requester.connect(pair_id, transport).unwrap();
    assert_eq!(
        requester.await_card_present(&mut session, DEADLINE),
        Ok(true)
    );
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::ReadCertificate {
                kind: refineid_rapp::CertificateKind::Authentication,
            },
            LIFETIME_MS,
        )
        .unwrap();
    requester.disconnect(&mut session, CloseReason::Complete);
    custodian.join().unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Completed(CardOperationResult::Certificate(CERTIFICATE.to_vec()))
    );
}
