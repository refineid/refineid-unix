//! Durable pairing records.
//!
//! A pairing record is the engine's [`PairRecord`] -- the pair keys,
//! `pair_id`, the granted profiles and their `grants_hash`, whether the
//! peer confirmed its storage (RAPP v26.10.21 section 4.3 item 4), and when
//! this computer's user forgot it (section 4.6 item 2) -- with what this
//! computer keeps beside it: the phone's labels, the re-pairing hint, and
//! the cached authentication certificate. Operations leave nothing here:
//! an operation lives and ends inside its session (section 8.1).
//!
//! A record exists while its key does. A pairing that is revoked loses its
//! key and its record together.
//!
//! The store is a trait so the workstation keeps records in owner-only
//! files while tests use the in-memory form shipped here. It never
//! contains a credential value, a card identifier, or message plaintext.

pub use refineid_rapp::PairingState;
use refineid_rapp::{ActivePairing, EndpointRole, PairRecord};

use crate::ids::PairId;

/// The re-pairing hint of a record no candidate has failed.
const NO_CANDIDATE_FAILURES: u32 = 0;
/// What one failed session candidate adds to the hint.
const ONE_CANDIDATE_FAILURE: u32 = 1;

/// What a phone introduced itself as in `pairing.hello` (section 7.1):
/// labels for display, not identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIntroduction {
    /// The phone's display label.
    pub display_name: String,
    /// The phone's platform label.
    pub platform: String,
}

/// Why a record was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The engine's record belongs to the custodian role; this store holds
    /// the requester's half of each pairing.
    NotRequester,
    /// The record names another pairing than the confirmation does.
    PairMismatch,
}

/// One stored pairing.
pub struct PairingRecord {
    pairing: PairRecord,
    peer: PeerIntroduction,
    candidate_failures: u32,
    auth_cert: Option<Vec<u8>>,
}

impl core::fmt::Debug for PairingRecord {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PairingRecord")
            .field("pair_id", &self.pairing.pair_id())
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl PairingRecord {
    /// The record of the requester's half of `pairing`, introduced by
    /// `peer`, with no re-pairing hint and no cached certificate.
    ///
    /// # Errors
    /// [`RecordError::NotRequester`] for a custodian's record.
    pub fn new(pairing: PairRecord, peer: PeerIntroduction) -> Result<Self, RecordError> {
        if pairing.role() != EndpointRole::Requester {
            return Err(RecordError::NotRequester);
        }
        Ok(Self {
            pairing,
            peer,
            candidate_failures: NO_CANDIDATE_FAILURES,
            auth_cert: None,
        })
    }

    /// The pairing's identifier.
    #[must_use]
    pub const fn pair_id(&self) -> PairId {
        self.pairing.pair_id()
    }

    /// The engine's record of the pairing.
    #[must_use]
    pub const fn pairing(&self) -> &PairRecord {
        &self.pairing
    }

    /// Where the stored pairing stands in the pairing machine of RAPP
    /// v26.10.21: awaiting the peer's storage confirmation
    /// ([`PairingState::StorageConfirming`]), usable
    /// ([`PairingState::PairedDisconnected`]), or forgotten and keeping
    /// its key for the close ([`PairingState::Revoking`]).
    #[must_use]
    pub const fn state(&self) -> PairingState {
        if self.pairing.forgotten_at_ms().is_some() {
            PairingState::Revoking
        } else if self.pairing.is_storage_confirmed() {
            PairingState::PairedDisconnected
        } else {
            PairingState::StorageConfirming
        }
    }

    /// What the phone introduced itself as.
    #[must_use]
    pub const fn peer(&self) -> &PeerIntroduction {
        &self.peer
    }

    /// Consecutive failed session-candidate authentications.
    #[must_use]
    pub const fn candidate_failures(&self) -> u32 {
        self.candidate_failures
    }

    /// The cached DER authentication certificate, if read.
    #[must_use]
    pub fn auth_cert(&self) -> Option<&[u8]> {
        self.auth_cert.as_deref()
    }

    /// The record once the peer confirmed its storage (section 4.3 item
    /// 4); `active` is the engine's proof of both confirmations.
    ///
    /// # Errors
    /// [`RecordError::PairMismatch`] when `active` proves another pairing;
    /// the record and its key are gone.
    pub fn confirmed(self, active: ActivePairing) -> Result<Self, RecordError> {
        let Self {
            pairing,
            peer,
            candidate_failures,
            auth_cert,
        } = self;
        let pairing = active
            .confirm(pairing)
            .map_err(|_| RecordError::PairMismatch)?;
        Ok(Self {
            pairing,
            peer,
            candidate_failures,
            auth_cert,
        })
    }

    /// The record its user forgot at `at_ms`, milliseconds since the Unix
    /// epoch (section 4.6 item 2): it serves nothing from then on.
    #[must_use]
    pub fn forgotten(self, at_ms: u64) -> Self {
        Self {
            pairing: self.pairing.forgotten(at_ms),
            ..self
        }
    }

    /// The record with the phone introduced as `peer`.
    #[must_use]
    pub fn with_peer(self, peer: PeerIntroduction) -> Self {
        Self { peer, ..self }
    }

    /// The record after one more consecutive failed session candidate.
    #[must_use]
    pub fn with_failed_candidate(self) -> Self {
        let failures = self
            .candidate_failures
            .saturating_add(ONE_CANDIDATE_FAILURE);
        self.with_candidate_failures(failures)
    }

    /// The record once a session candidate authenticated.
    #[must_use]
    pub fn with_authenticated_candidate(self) -> Self {
        self.with_candidate_failures(NO_CANDIDATE_FAILURES)
    }

    /// The record counting `failures` consecutive failed candidates, as
    /// storage kept it.
    #[must_use]
    pub(crate) fn with_candidate_failures(self, failures: u32) -> Self {
        Self {
            candidate_failures: failures,
            ..self
        }
    }

    /// The record caching `auth_cert`, or none.
    #[must_use]
    pub fn with_auth_cert(self, auth_cert: Option<Vec<u8>>) -> Self {
        Self { auth_cert, ..self }
    }
}

/// Why a store operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// No record exists for the identifier.
    Unknown,
    /// The backing store refused the write.
    WriteRefused,
}

/// Durable storage for pairing records.
pub trait PairingStore {
    /// Stores a record atomically, in place of any record of its pairing.
    ///
    /// # Errors
    ///
    /// Fails when the backing store refuses the write.
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError>;

    /// Reads one record.
    ///
    /// # Errors
    ///
    /// Fails when no record exists.
    fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError>;

    /// Replaces one record by what `change` makes of it, atomically: its
    /// successor, or nothing, which removes the record and its key.
    /// `change` is given the record as the store durably holds it now,
    /// which another program sharing the store may have rewritten since
    /// this one read it.
    ///
    /// # Errors
    ///
    /// Fails when no record exists or the write is refused; a refused
    /// write leaves the record as the store last held it durably.
    fn update(
        &mut self,
        pair_id: PairId,
        change: &mut dyn FnMut(PairingRecord) -> Option<PairingRecord>,
    ) -> Result<(), StoreError>;

    /// Removes one record entirely, its key with it.
    ///
    /// # Errors
    ///
    /// As [`Self::update`].
    fn remove(&mut self, pair_id: PairId) -> Result<(), StoreError> {
        self.update(pair_id, &mut |_| None)
    }

    /// Every stored pairing, newest first.
    fn pair_ids(&self) -> Vec<PairId>;
}

/// An in-memory pairing store for tests and composition.
#[derive(Debug, Default)]
pub struct MemoryPairingStore {
    records: Vec<PairingRecord>,
}

impl MemoryPairingStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl PairingStore for MemoryPairingStore {
    fn insert(&mut self, record: PairingRecord) -> Result<(), StoreError> {
        self.records
            .retain(|entry| entry.pair_id() != record.pair_id());
        self.records.push(record);
        Ok(())
    }

    fn get(&self, pair_id: PairId) -> Result<&PairingRecord, StoreError> {
        self.records
            .iter()
            .find(|entry| entry.pair_id() == pair_id)
            .ok_or(StoreError::Unknown)
    }

    fn update(
        &mut self,
        pair_id: PairId,
        change: &mut dyn FnMut(PairingRecord) -> Option<PairingRecord>,
    ) -> Result<(), StoreError> {
        let mut outcome = Err(StoreError::Unknown);
        self.records = core::mem::take(&mut self.records)
            .into_iter()
            .filter_map(|record| {
                if record.pair_id() != pair_id {
                    return Some(record);
                }
                outcome = Ok(());
                change(record)
            })
            .collect();
        outcome
    }

    fn pair_ids(&self) -> Vec<PairId> {
        self.records
            .iter()
            .rev()
            .map(PairingRecord::pair_id)
            .collect()
    }
}

/// Synthetic engine records for this crate's tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use refineid_rapp::{
        EndpointRole, PairRecord, ProfileName, compute_grants_hash, generate_pair_key_material,
    };

    use super::{PairingRecord, PeerIntroduction};
    use crate::ids::PairId;

    /// When the fixtures' pairings were made.
    pub(crate) const CREATED_AT_MS: u64 = 1_700_000_000_000;

    /// The phone every fixture is paired with.
    pub(crate) fn phone() -> PeerIntroduction {
        PeerIntroduction {
            display_name: "Alpha Phone".into(),
            platform: "iOS".into(),
        }
    }

    /// A confirmed requester record of `pair_id` granting `profiles`, with
    /// fresh keys.
    pub(crate) fn pair_record(pair_id: PairId, profiles: Vec<ProfileName>) -> PairRecord {
        let local = generate_pair_key_material().expect("local keys");
        let peer = generate_pair_key_material().expect("peer keys");
        let grants_hash = compute_grants_hash(&profiles).expect("grants hash");
        local
            .with_private_key(|private| {
                PairRecord::new(
                    pair_id,
                    EndpointRole::Requester,
                    *private,
                    *local.public_key(),
                    *peer.public_key(),
                    grants_hash,
                    profiles,
                    CREATED_AT_MS,
                )
            })
            .expect("a valid record")
    }

    /// A usable record of `pair_id` granting card status.
    pub(crate) fn record(pair_id: PairId) -> PairingRecord {
        PairingRecord::new(pair_record(pair_id, vec![ProfileName::CardStatus]), phone())
            .expect("a requester record")
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use refineid_rapp::{EndpointRole, PairRecord, PairingState, ProfileName};

    use super::fixtures::{CREATED_AT_MS, phone, record};
    use super::{MemoryPairingStore, PairingRecord, PairingStore, RecordError, StoreError};
    use crate::ids::PairId;

    /// A synthetic pair identifier.
    const PAIR_ID: [u8; refineid_rapp::PAIR_ID_SIZE] = *b"synthetic-pair-1";
    /// When the fixture's user forgot it.
    const FORGOTTEN_AT_MS: u64 = 1_800_000_000_000;
    /// The re-pairing hint the update test records.
    const FAILURES: u32 = 1;

    #[test]
    fn records_update_into_their_successor_and_go_with_their_key() {
        let mut store = MemoryPairingStore::new();
        let pair_id = PairId::from_array(PAIR_ID);
        store.insert(record(pair_id)).unwrap();
        store
            .update(pair_id, &mut |entry| {
                Some(entry.with_candidate_failures(FAILURES))
            })
            .unwrap();
        assert_eq!(store.get(pair_id).unwrap().candidate_failures(), FAILURES);
        store.remove(pair_id).unwrap();
        assert!(matches!(store.get(pair_id), Err(StoreError::Unknown)));
        assert_eq!(store.remove(pair_id), Err(StoreError::Unknown));
    }

    #[test]
    fn a_forgotten_record_is_revoking_and_serves_nothing() {
        let usable = record(PairId::from_array(PAIR_ID));
        assert_eq!(usable.state(), PairingState::PairedDisconnected);
        assert!(!usable.pairing().serving_profiles().is_empty());
        let forgotten = usable.forgotten(FORGOTTEN_AT_MS);
        assert_eq!(forgotten.state(), PairingState::Revoking);
        assert_eq!(forgotten.pairing().forgotten_at_ms(), Some(FORGOTTEN_AT_MS));
        assert!(forgotten.pairing().serving_profiles().is_empty());
    }

    #[test]
    fn a_custodians_record_is_refused() {
        let local = refineid_rapp::generate_pair_key_material().unwrap();
        let peer = refineid_rapp::generate_pair_key_material().unwrap();
        let profiles = vec![ProfileName::CardStatus];
        let grants_hash = refineid_rapp::compute_grants_hash(&profiles).unwrap();
        let custodian = local
            .with_private_key(|private| {
                PairRecord::new(
                    PairId::from_array(PAIR_ID),
                    EndpointRole::Proxy,
                    *private,
                    *local.public_key(),
                    *peer.public_key(),
                    grants_hash,
                    profiles,
                    CREATED_AT_MS,
                )
            })
            .unwrap();
        assert_eq!(
            PairingRecord::new(custodian, phone()).err(),
            Some(RecordError::NotRequester)
        );
    }

    #[test]
    fn pairing_record_debug_names_no_key() {
        let text = format!("{:?}", record(PairId::from_array(PAIR_ID)));
        assert!(text.contains("pair_id"));
        assert!(!text.contains("private"));
    }
}
