//! Loopback conformance tests: the requester engine against a scripted
//! authorization proxy running the proxy projection over the same wire.
//!
//! The proxy here is test scaffolding, not a product: the real proxies are
//! the holder's phones. It speaks the exact wire so the requester is
//! exercised end to end - code pairing through `CPace` KC2 and
//! `Noise_XXpsk3` with grant agreement, `Noise_KK` sessions with the
//! parameter echo, direct operations and their results, denial, credential
//! rejection revoking the pairing, immediate revocation on the first
//! authenticated violation, and ambiguity on an unanswered consequential
//! request.

#![allow(
    clippy::unwrap_used,
    reason = "test scaffolding is constructed to be infallible"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "tests panic to fail; documenting each panic adds nothing"
)]

use std::time::Duration;

use refineid_rapp::{
    BinaryFrame, CardInspection, CardKeyProfile as KeyProfile, CardOperation, CardOperationResult,
    CardStatusMessage, CloseReason, CpaceKc2Responder, EndpointRole, EstablishedEndpoint,
    OperationReference, OperationResultMessage, PairId, PairRecord, PairStore, PairStoreError,
    PairTombstone, PairingHandshake, PairingOffer, ProxyFailure, ReceiveOutcome,
    SessionCloseMessage, SessionHandshake, SignatureAlgorithm, StatusReport, TransportProfile,
    TypedMessage, generate_pair_key_material, standard_pairing_context_v2,
};
use refineid_rapp_core::engine::{
    OperationOutcome, PairingError, ReconciledResult, Requester, RequesterConfig, SessionEnd,
    SessionError,
};
use refineid_rapp_core::file_journal::FileOperationJournal;
use refineid_rapp_core::operations::SignatureAlgorithmExt as _;
use refineid_rapp_core::profiles::{PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS};
use refineid_rapp_core::remote::execute_on_session;
use refineid_rapp_core::store::{
    MemoryJournal, MemoryPairingStore, OperationJournal, PairingDisposition, PairingStore,
};
use refineid_rapp_core::transport::{FrameTransport, MemoryTransport};

/// A generous deadline for scripted exchanges.
const DEADLINE: Duration = Duration::from_secs(2);
/// The candidate identifier used by every loopback test.
const CANDIDATE: &str = "loopback-1";
/// Test monotonic timestamp in milliseconds.
const TEST_MONOTONIC_TIMESTAMP_MS: u64 = 1_000_000;
/// The code the scripted custodian shows.
const SHOWN_CODE: &str = "7KX4M9";
/// Fixed custodian scalar entropy for the scripted exchange.
const CUSTODIAN_ENTROPY: [u8; 64] = [0x24; 64];

/// The custodian's random stream offer and its bootstrap bytes (section
/// 4.2), and the CPace context it binds.
fn custodian_offer() -> (PairingOffer, Vec<u8>, Vec<u8>) {
    let mut offer_id = [0_u8; refineid_rapp::OFFER_ID_SIZE];
    getrandom::fill(&mut offer_id).unwrap();
    let offer = PairingOffer::create(
        refineid_rapp::OfferId::from_array(offer_id),
        vec![
            PROFILE_CARD_STATUS.to_owned(),
            PROFILE_AUTHENTICATION.to_owned(),
            refineid_rapp_core::profiles::PROFILE_DOCUMENT_SIGNING.to_owned(),
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
type TestRequester = Requester<MemoryPairingStore, MemoryJournal>;

fn test_requester() -> TestRequester {
    Requester::new(
        RequesterConfig {
            display_name: "Workstation".into(),
            platform: "Linux".into(),
        },
        MemoryPairingStore::new(),
        MemoryJournal::new(),
    )
}

/// A registered consequential operation for the authentication tests.
fn authentication_operation() -> CardOperation {
    CardOperation::BrowserAuthenticate {
        origin: "kortti.tunnistautuminen.suomi.fi".into(),
        key_profile: KeyProfile::Rsa3072,
        algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
        digest: vec![0x2a; SignatureAlgorithm::RsaPkcs1Sha256.digest_length()],
    }
}

#[derive(Default)]
struct MockProxyStore;

impl PairStore for MockProxyStore {
    type Error = core::convert::Infallible;
    fn load(&mut self, _pair_id: PairId) -> Result<Option<PairRecord>, Self::Error> {
        Ok(None)
    }
    fn insert(&mut self, _record: PairRecord) -> Result<(), PairStoreError<Self::Error>> {
        Ok(())
    }
    fn revoke(&mut self, _tombstone: PairTombstone) -> Result<(), PairStoreError<Self::Error>> {
        Ok(())
    }
    fn is_revoked(&mut self, _pair_id: PairId) -> Result<bool, Self::Error> {
        Ok(false)
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
    proxy_pair_confirming(transport, shown_code, StorageConfirmation::Confirmed)
        .expect("the confirming custodian stores its record")
}

/// As [`proxy_pair`]; a `Silent` custodian stores nothing and leaves the
/// requester without its `pairing.stored`.
fn proxy_pair_confirming<T: FrameTransport>(
    mut transport: T,
    shown_code: &str,
    confirmation_mode: StorageConfirmation,
) -> Option<PairRecord> {
    let now_ms = TEST_MONOTONIC_TIMESTAMP_MS;
    let candidate = TransportProfile::Stream.candidate_id();
    let (offer, bootstrap, context) = custodian_offer();
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
        .send_hello("Phone".into(), "iOS".into())
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

struct ProxySession<T: FrameTransport> {
    endpoint: EstablishedEndpoint,
    transport: T,
}

impl<T: FrameTransport> ProxySession<T> {
    fn send(&mut self, message: &TypedMessage) {
        let frame = self.endpoint.send(message).unwrap();
        self.transport.send_frame(frame.as_bytes()).unwrap();
    }

    fn receive(&mut self) -> TypedMessage {
        let frame_bytes = self.transport.receive_frame().unwrap();
        let frame = BinaryFrame::reconstruct(frame_bytes).unwrap();
        let mut store = MockProxyStore;
        let outcome = self
            .endpoint
            .receive(&mut store, &frame, TEST_MONOTONIC_TIMESTAMP_MS)
            .unwrap();
        match outcome {
            ReceiveOutcome::Message(m) => m,
            other => panic!("expected message, got {other:?}"),
        }
    }
}

/// Accepts one session as the proxy, completes the ready exchange, and
/// reports a card it can serve (section 8.4).
fn proxy_accept_session<T: FrameTransport>(
    pair_record: &PairRecord,
    transport: T,
) -> ProxySession<T> {
    let mut session = proxy_accept_session_with_card(pair_record, transport, true);
    session.send(&TypedMessage::CardStatus(CardStatusMessage {
        card_present: true,
    }));
    session
}

/// Accepts one session as the proxy and completes the ready exchange; the
/// card status is reported by the caller.
fn proxy_accept_session_with_card<T: FrameTransport>(
    pair_record: &PairRecord,
    mut transport: T,
    _card_present: bool,
) -> ProxySession<T> {
    let now_ms = TEST_MONOTONIC_TIMESTAMP_MS;
    let mut handshake =
        SessionHandshake::begin_proxy(pair_record, TransportProfile::Stream).unwrap();

    // Message 1 (Requester -> Proxy)
    let m1_bytes = transport.receive_frame().unwrap();
    let m1 = BinaryFrame::reconstruct(m1_bytes).unwrap();
    handshake.read_message(&m1).unwrap();

    // Message 2 (Proxy -> Requester)
    let m2 = handshake.write_message().unwrap();
    transport.send_frame(m2.as_bytes()).unwrap();

    let mut auth = handshake.into_authentication().unwrap();

    // Receive Ready
    let req_ready_bytes = transport.receive_frame().unwrap();
    let req_ready_frame = BinaryFrame::reconstruct(req_ready_bytes).unwrap();
    let mut store = MockProxyStore;
    auth.receive_ready(&mut store, &req_ready_frame, now_ms)
        .unwrap();

    // Send Ready
    let proxy_ready = auth.send_ready([0x55; 32]).unwrap();
    transport.send_frame(proxy_ready.as_bytes()).unwrap();

    let endpoint = auth.into_established().unwrap();
    ProxySession {
        endpoint,
        transport,
    }
}

/// Pairs a fresh requester with a custodian thread and returns both halves.
fn paired<J: OperationJournal>(
    requester: &mut Requester<MemoryPairingStore, J>,
    granted: &[String],
) -> (PairId, PairRecord) {
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || proxy_pair(proxy_transport, SHOWN_CODE));
    let pair_id = requester
        .pair_with_code("7k x4-m9", requester_transport, |peer, _requested| {
            assert_eq!(peer.display_name, "Phone");
            Some(granted.to_vec())
        })
        .unwrap();
    let proxy_record = proxy.join().unwrap();
    assert_eq!(proxy_record.pair_id(), pair_id);
    (pair_id, proxy_record)
}

#[test]
fn pairing_stores_matching_records_on_both_sides() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, _proxy) = paired(&mut requester, &granted);
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.granted_profiles, granted);
    assert_eq!(record.disposition, PairingDisposition::Paired);
    assert_eq!(record.peer_display_name, "Phone");
}

#[test]
fn a_custodian_that_never_confirms_its_storage_leaves_a_revoked_record() {
    let mut requester = test_requester();
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        proxy_pair_confirming(proxy_transport, SHOWN_CODE, StorageConfirmation::Silent)
    });
    let outcome = requester.pair_with_code(SHOWN_CODE, requester_transport, |_, requested| {
        Some(requested.to_vec())
    });
    assert!(proxy.join().unwrap().is_none());
    assert_eq!(outcome, Err(PairingError::StorageUnconfirmed));
    // Section 4.3 item 4: the record stored here is revoked, never dialed.
    let pair_ids = requester.store().pair_ids();
    assert_eq!(pair_ids.len(), 1);
    let record = requester.store().get(pair_ids[0]).unwrap();
    assert_eq!(record.disposition, PairingDisposition::Revoked);
    assert!(record.local_private.is_empty());
}

#[test]
fn an_unconfirmed_record_found_at_start_up_is_revoked() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, _proxy) = paired(&mut requester, &granted);
    requester
        .store_mut()
        .update(pair_id, &mut |record| {
            record.disposition = PairingDisposition::Unconfirmed;
        })
        .unwrap();
    assert_eq!(requester.revoke_unconfirmed_pairings(), 1);
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.disposition, PairingDisposition::Revoked);
    let (requester_transport, _other) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    assert!(matches!(
        requester.connect(pair_id, requester_transport),
        Err(SessionError::NotPaired(PairingDisposition::Revoked))
    ));
}

#[test]
fn a_session_reports_whether_the_phone_has_a_card() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session_with_card(&proxy_pairing, proxy_transport, false);
        session.send(&TypedMessage::CardStatus(CardStatusMessage {
            card_present: false,
        }));
        session.send(&TypedMessage::CardStatus(CardStatusMessage {
            card_present: true,
        }));
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request once the card is reported");
        };
        let reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: request.request_hash().unwrap(),
        };
        session.send(&TypedMessage::OperationProgress(
            refineid_rapp::OperationProgressMessage {
                reference,
                event: refineid_rapp::ProgressEvent::ConsentShown,
            },
        ));
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::failure(reference, ProxyFailure::UserDenied),
        ));
        let TypedMessage::OperationResultAck(acknowledged) = session.receive() else {
            panic!("a denial must be acknowledged");
        };
        assert_eq!(acknowledged, reference);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    assert_eq!(session.card_present(), None);
    // Section 8.4: the first card.status is the phone's word on its card.
    assert_eq!(requester.await_card_status(&mut session), Ok(false));
    // A later report replaces it; the operation loop records it on the way.
    let outcome = requester
        .execute(&mut session, &CardOperation::InspectCard, 30_000)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::Denied);
    assert_eq!(session.card_present(), Some(true));
    // Section 8.2 item 3: the consent view was reported on screen.
    assert!(session.consent_shown());
}

#[test]
fn a_card_reported_after_the_dial_is_waited_for() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session_with_card(&proxy_pairing, proxy_transport, false);
        session.send(&TypedMessage::CardStatus(CardStatusMessage {
            card_present: false,
        }));
        std::thread::sleep(Duration::from_millis(150));
        session.send(&TypedMessage::CardStatus(CardStatusMessage {
            card_present: true,
        }));
        let TypedMessage::SessionClose(close) = session.receive() else {
            panic!("expected the requester's close");
        };
        assert_eq!(close.reason, CloseReason::Normal);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    assert_eq!(requester.await_card_status(&mut session), Ok(false));
    // Section 8.4: a later card.status reporting presence is waited for.
    assert_eq!(
        requester.await_card_present(&mut session, Duration::from_secs(1)),
        Ok(true)
    );
    assert_eq!(session.card_present(), Some(true));
    requester.disconnect(&mut session, CloseReason::Normal);
    proxy.join().unwrap();
}

#[test]
fn a_wait_for_a_card_that_runs_out_leaves_the_session_open() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session_with_card(&proxy_pairing, proxy_transport, false);
        session.send(&TypedMessage::CardStatus(CardStatusMessage {
            card_present: false,
        }));
        std::thread::sleep(Duration::from_millis(400));
        session.send(&TypedMessage::CardStatus(CardStatusMessage {
            card_present: true,
        }));
        let TypedMessage::SessionClose(_) = session.receive() else {
            panic!("expected the requester's close");
        };
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    assert_eq!(requester.await_card_status(&mut session), Ok(false));
    // The wait runs out before the phone reports a card; the session is
    // neither closed nor marked lost, and the transport keeps its deadline.
    assert_eq!(
        requester.await_card_present(&mut session, Duration::from_millis(100)),
        Ok(false)
    );
    assert!(Requester::<MemoryPairingStore, MemoryJournal>::session_end(&session).is_none());
    assert_eq!(
        requester.await_card_present(&mut session, Duration::from_secs(1)),
        Ok(true)
    );
    requester.disconnect(&mut session, CloseReason::Normal);
    proxy.join().unwrap();
}

#[test]
fn a_pairing_revoked_close_while_awaiting_the_card_revokes_here() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session_with_card(&proxy_pairing, proxy_transport, false);
        session.send(&TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::PairingRevoked,
            last_received_sequence: 0,
        }));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    assert_eq!(
        requester.await_card_status(&mut session),
        Err(SessionError::ClosedByPeer(CloseReason::PairingRevoked))
    );
    proxy.join().unwrap();
    // Section 4.6 item 1: the in-session notice is the phone's word; the
    // pairing is revoked here as one it ended.
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.disposition, PairingDisposition::Revoked);
    assert!(record.peer_initiated_termination);
    assert!(record.local_private.is_empty());
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
    let outcome = requester.pair_with_code("7KX4MA", requester_transport, |_, _| {
        panic!("an unauthenticated attempt must never reach confirmation")
    });
    proxy.join().unwrap();
    assert_eq!(outcome, Err(PairingError::CodeMismatch));
    assert!(requester.store().pair_ids().is_empty());
}

#[test]
fn an_offer_without_the_connection_transport_is_refused_before_cpace() {
    let mut requester = test_requester();
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut offer_id = [0_u8; refineid_rapp::OFFER_ID_SIZE];
        getrandom::fill(&mut offer_id).unwrap();
        let ble_only = PairingOffer::create(
            refineid_rapp::OfferId::from_array(offer_id),
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
    let outcome = requester.pair_with_code(SHOWN_CODE, requester_transport, |_, _| {
        panic!("a refused offer must never reach confirmation")
    });
    proxy.join().unwrap();
    assert_eq!(
        outcome,
        Err(PairingError::Offer(
            refineid_rapp::PairingOfferError::TransportNotOffered
        ))
    );
    assert!(requester.store().pair_ids().is_empty());
}

#[test]
fn input_that_is_not_a_code_never_touches_the_transport() {
    let mut requester = test_requester();
    let (requester_transport, mut proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let outcome = requester.pair_with_code("7KX4MU", requester_transport, |_, _| None);
    assert_eq!(outcome, Err(PairingError::InvalidCode));
    assert!(proxy_transport.receive_frame().is_err());
}

#[test]
fn card_status_completes_as_a_safe_read() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        assert_eq!(request.profile.as_str(), PROFILE_CARD_STATUS);
        let reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: request.request_hash().unwrap(),
        };
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                reference,
                &CardOperationResult::Inspection(CardInspection {
                    answer_to_reset: Vec::new(),
                    pin1_factory: false,
                    pin2_factory: false,
                    pin1_attempts: Some(5),
                    pin2_attempts: Some(5),
                    puk_attempts: None,
                }),
            ),
        ));
        let TypedMessage::OperationResultAck(ack_ref) = session.receive() else {
            panic!("expected the completed result to be acknowledged");
        };
        assert_eq!(ack_ref, reference);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &CardOperation::InspectCard, 30_000)
        .unwrap();
    proxy.join().unwrap();
    let OperationOutcome::Completed(result) = outcome else {
        panic!("expected completion, got {outcome:?}");
    };
    assert_eq!(
        result,
        CardOperationResult::Inspection(CardInspection {
            answer_to_reset: Vec::new(),
            pin1_factory: false,
            pin2_factory: false,
            pin1_attempts: Some(5),
            pin2_attempts: Some(5),
            puk_attempts: None,
        })
    );
}

#[test]
fn authentication_executes_directly_to_its_result() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        let reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: request.request_hash().unwrap(),
        };
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                reference,
                &CardOperationResult::Signature(vec![0xAB; 96]),
            ),
        ));
        let TypedMessage::OperationResultAck(ack_ref) = session.receive() else {
            panic!("expected result ack");
        };
        assert_eq!(ack_ref, reference);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 60_000)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Completed(CardOperationResult::Signature(vec![0xAB; 96]))
    );
}

#[test]
fn the_lifetime_asked_for_reaches_the_wire() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        let reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: request.request_hash().unwrap(),
        };
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                reference,
                &CardOperationResult::Signature(vec![0xAB; 96]),
            ),
        ));
        let TypedMessage::OperationResultAck(_) = session.receive() else {
            panic!("expected result ack");
        };
        request.expires_after_ms
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    assert_eq!(requester.await_card_status(&mut session), Ok(true));
    let result = execute_on_session(
        &mut requester,
        &mut session,
        &authentication_operation(),
        Duration::from_secs(45),
    )
    .unwrap();
    assert_eq!(result, CardOperationResult::Signature(vec![0xAB; 96]));
    assert_eq!(proxy.join().unwrap(), 45_000);
}

#[test]
fn denial_leaves_the_session_healthy() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        for _ in 0..2 {
            let TypedMessage::OperationRequest(request) = session.receive() else {
                panic!("expected an operation request");
            };
            let reference = OperationReference {
                operation_id: request.operation_id,
                request_hash: request.request_hash().unwrap(),
            };
            let failure_msg = OperationResultMessage::failure(reference, ProxyFailure::UserDenied);
            session.send(&TypedMessage::OperationResult(failure_msg));
            // Section 8.2 item 5: a denial is acknowledged like a result.
            let TypedMessage::OperationResultAck(acknowledged) = session.receive() else {
                panic!("a denial must be acknowledged");
            };
            assert_eq!(acknowledged, reference);
        }
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    for _ in 0..2 {
        let outcome = requester
            .execute(&mut session, &authentication_operation(), 30_000)
            .unwrap();
        assert_eq!(outcome, OperationOutcome::Denied);
    }
    proxy.join().unwrap();
}

#[test]
fn credential_rejection_revokes_the_pairing() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        let reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: request.request_hash().unwrap(),
        };
        let failure_msg =
            OperationResultMessage::failure(reference, ProxyFailure::CredentialRejected);
        session.send(&TypedMessage::OperationResult(failure_msg));
        let TypedMessage::OperationResultAck(acknowledged) = session.receive() else {
            panic!("a credential rejection must be acknowledged");
        };
        assert_eq!(acknowledged, reference);
        session.send(&TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::CredentialRejected,
            last_received_sequence: 2,
        }));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 30_000)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::CredentialRejected);
    // Section 13.4: the authenticated credential_rejected result durably
    // revokes the pairing before the terminal outcome is reported, and the
    // phone is the one that ended it (section 4.6).
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.disposition, PairingDisposition::Revoked);
    assert!(record.peer_initiated_termination);
    assert!(record.local_private.is_empty());
    assert!(record.peer_public.is_empty());

    // Recovery requires a new manual pairing ceremony.
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    drop(proxy_transport);
    assert!(matches!(
        requester.connect(pair_id, requester_transport),
        Err(SessionError::NotPaired(PairingDisposition::Revoked))
    ));
}

#[test]
fn a_withdrawn_session_keeps_the_pairing_and_reports_the_reason() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(_) = session.receive() else {
            panic!("expected an operation request");
        };
        session.send(&TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::ServiceWithdrawn,
            last_received_sequence: 1,
        }));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester.execute(&mut session, &authentication_operation(), 30_000);
    proxy.join().unwrap();
    assert!(!matches!(outcome, Ok(OperationOutcome::Completed(_))));
    assert_eq!(
        TestRequester::session_end(&session),
        Some(SessionEnd::PeerClose(CloseReason::ServiceWithdrawn))
    );
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.disposition, PairingDisposition::Paired);
}

#[test]
fn unanswered_consequential_close_classifies_as_ambiguous() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        assert!(request.operation.is_consequential());
        // The transport dies with the request delivered and unanswered.
        drop(session);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 30_000)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::Ambiguous);
    // The journal remembers the prohibition on automatic retry (INV-06).
    let open = requester.journal().open_entries();
    assert!(open.is_empty());
}

#[test]
fn an_unanswered_signature_survives_restart_and_reconciles_by_status() {
    let directory = std::env::temp_dir().join(format!(
        "refineid-loopback-journal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let config = || RequesterConfig {
        display_name: "Workstation".into(),
        platform: "Linux".into(),
    };
    let mut requester = Requester::new(
        config(),
        MemoryPairingStore::new(),
        FileOperationJournal::open(&directory).unwrap(),
    );
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);

    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        // The transport dies with the request delivered and unanswered.
        drop(session);
        (request, proxy_pairing)
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 30_000)
        .unwrap();
    let (request, proxy_pairing) = proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::Ambiguous);
    let store = std::mem::take(requester.store_mut());
    drop(requester);

    // A new process finds the operation ambiguous and unreconciled.
    let mut requester = Requester::new(
        config(),
        store,
        FileOperationJournal::open(&directory).unwrap(),
    );
    let pending = requester.journal().unreconciled(pair_id);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].operation_id, request.operation_id);
    assert!(pending[0].retry_prohibited);

    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let reference = OperationReference {
        operation_id: request.operation_id,
        request_hash: request.request_hash().unwrap(),
    };
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationStatusRequest(asked) = session.receive() else {
            panic!("expected a status request");
        };
        assert_eq!(asked, reference.operation_id);
        session.send(&TypedMessage::OperationStatus(StatusReport {
            operation_id: asked,
            known: true,
            state: Some(refineid_rapp::OperationState::Ambiguous),
            request_hash: Some(reference.request_hash),
            retired: false,
        }));
        // Section 8.3: the retained terminal result follows the report and
        // is acknowledged whatever its status.
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::failure(reference, ProxyFailure::CardCompletionAmbiguous),
        ));
        let TypedMessage::OperationResultAck(acknowledged) = session.receive() else {
            panic!("a re-delivered ambiguous result must be acknowledged");
        };
        assert_eq!(acknowledged, reference);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let answer = requester
        .reconcile_status(&mut session, request.operation_id)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(
        answer.reported_state,
        Some(refineid_rapp::OperationState::Ambiguous)
    );
    assert!(matches!(
        answer.result,
        Some(ReconciledResult::Failed {
            status: refineid_rapp::ResultStatus::Ambiguous,
            ..
        })
    ));
    assert!(requester.journal().unreconciled(pair_id).is_empty());
    let reopened = FileOperationJournal::open(&directory).unwrap();
    assert!(reopened.unreconciled(pair_id).is_empty());
    assert!(
        reopened
            .get(request.operation_id)
            .unwrap()
            .reconciled_proxy_state
            .is_some()
    );
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn a_redelivered_completed_result_is_acknowledged_and_the_session_continues() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);

    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        drop(session);
        (request, proxy_pairing)
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 30_000)
        .unwrap();
    let (request, proxy_pairing) = proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::Ambiguous);

    let reference = OperationReference {
        operation_id: request.operation_id,
        request_hash: request.request_hash().unwrap(),
    };
    let signature = CardOperationResult::Signature(vec![0x5c; 384]);
    let delivered = OperationResultMessage::completed(reference, &signature);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationStatusRequest(asked) = session.receive() else {
            panic!("expected a status request");
        };
        session.send(&TypedMessage::OperationStatus(StatusReport {
            operation_id: asked,
            known: true,
            state: Some(refineid_rapp::OperationState::Completed),
            request_hash: Some(reference.request_hash),
            retired: false,
        }));
        session.send(&TypedMessage::OperationResult(delivered));
        let TypedMessage::OperationResultAck(acknowledged) = session.receive() else {
            panic!("a re-delivered completed result must be acknowledged");
        };
        assert_eq!(acknowledged, reference);
        // The session stays usable after reconciliation.
        let TypedMessage::OperationStatusRequest(again) = session.receive() else {
            panic!("expected a second status request");
        };
        session.send(&TypedMessage::OperationStatus(StatusReport {
            operation_id: again,
            known: true,
            state: Some(refineid_rapp::OperationState::Completed),
            request_hash: Some(reference.request_hash),
            retired: true,
        }));
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let answer = requester
        .reconcile_status(&mut session, request.operation_id)
        .unwrap();
    let Some(ReconciledResult::Completed(response)) = answer.result else {
        panic!("expected the completed result, got {answer:?}");
    };
    assert_eq!(
        response.typed_for(&authentication_operation()).unwrap(),
        signature
    );
    assert_eq!(
        requester.journal().get(request.operation_id).unwrap().state,
        refineid_rapp::OperationState::Completed
    );
    let retired = requester
        .reconcile_status(&mut session, request.operation_id)
        .unwrap();
    proxy.join().unwrap();
    assert!(retired.retired);
    assert_eq!(retired.result, None);
}

#[test]
fn a_result_that_does_not_match_its_request_is_refused_and_the_pairing_stands() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_CARD_STATUS.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);

    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        let bad_reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: refineid_rapp::RequestHash::from_array([0xee; 32]),
        };
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                bad_reference,
                &CardOperationResult::Inspection(CardInspection {
                    answer_to_reset: Vec::new(),
                    pin1_factory: false,
                    pin2_factory: false,
                    pin1_attempts: Some(5),
                    pin2_attempts: Some(5),
                    puk_attempts: None,
                }),
            ),
        ));
        let TypedMessage::SessionClose(close) = session.receive() else {
            panic!("expected the requester's close");
        };
        assert_eq!(close.reason, CloseReason::ProtocolViolation);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &CardOperation::InspectCard, 30_000)
        .unwrap();
    proxy.join().unwrap();
    assert_eq!(outcome, OperationOutcome::Refused);
    assert_eq!(
        TestRequester::session_end(&session),
        Some(SessionEnd::Violation)
    );
    // Section 10.1: a message the protocol did not call for closes the
    // session; only class 4 revokes the pairing.
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.disposition, PairingDisposition::Paired);
    assert!(!record.local_private.is_empty());
    assert!(!record.peer_public.is_empty());
}

#[test]
fn a_refused_result_of_a_consequential_operation_is_ambiguous() {
    let mut requester = test_requester();
    let granted = vec![PROFILE_AUTHENTICATION.to_owned()];
    let (pair_id, proxy_pairing) = paired(&mut requester, &granted);
    let (requester_transport, proxy_transport) = MemoryTransport::pair(CANDIDATE, DEADLINE);
    let proxy = std::thread::spawn(move || {
        let mut session = proxy_accept_session(&proxy_pairing, proxy_transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        let bad_reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: refineid_rapp::RequestHash::from_array([0xee; 32]),
        };
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                bad_reference,
                &CardOperationResult::Signature(vec![0xAB; 96]),
            ),
        ));
        let TypedMessage::SessionClose(close) = session.receive() else {
            panic!("expected the requester's close");
        };
        assert_eq!(close.reason, CloseReason::ProtocolViolation);
    });
    let mut session = requester.connect(pair_id, requester_transport).unwrap();
    let outcome = requester
        .execute(&mut session, &authentication_operation(), 60_000)
        .unwrap();
    proxy.join().unwrap();
    // A result means the card acted, so the signature is ambiguous and
    // never retried on its own; the pairing stands.
    assert_eq!(outcome, OperationOutcome::Ambiguous);
    let record = requester.store().get(pair_id).unwrap();
    assert_eq!(record.disposition, PairingDisposition::Paired);
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
        let mut session = proxy_accept_session(&record, transport);
        let TypedMessage::OperationRequest(request) = session.receive() else {
            panic!("expected an operation request");
        };
        let reference = OperationReference {
            operation_id: request.operation_id,
            request_hash: request.request_hash().unwrap(),
        };
        session.send(&TypedMessage::OperationResult(
            OperationResultMessage::completed(
                reference,
                &CardOperationResult::Certificate(vec![0x30, 0x03, 0x02, 0x01, 0x01]),
            ),
        ));
        let TypedMessage::OperationResultAck(acknowledged) = session.receive() else {
            panic!("expected the result to be acknowledged");
        };
        assert_eq!(acknowledged, reference);
    });

    let mut requester = test_requester();
    let pairing = dial(
        &endpoints,
        STREAM_CANDIDATE_ID,
        DEADLINE,
        &RoutingPreamble::Pairing,
    )
    .unwrap();
    let pair_id = requester
        .pair_with_code(SHOWN_CODE, pairing, |_, requested| Some(requested.to_vec()))
        .unwrap();
    let core = requester
        .store()
        .get(pair_id)
        .unwrap()
        .to_core_pair_record()
        .unwrap();
    let routing = RoutingKey::derive(&core)
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
    let outcome = requester
        .execute(
            &mut session,
            &CardOperation::ReadCertificate {
                kind: refineid_rapp::CertificateKind::Authentication,
            },
            30_000,
        )
        .unwrap();
    custodian.join().unwrap();
    assert_eq!(
        outcome,
        OperationOutcome::Completed(CardOperationResult::Certificate(vec![
            0x30, 0x03, 0x02, 0x01, 0x01
        ]))
    );
}
