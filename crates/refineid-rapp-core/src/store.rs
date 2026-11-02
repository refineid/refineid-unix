//! Durable pairing records.
//!
//! A pairing record is the engine's [`PairRecord`] -- the pair keys,
//! `pair_id`, the granted profiles and their `grants_hash`, whether the
//! peer confirmed its storage (RAPP v26.11.2 section 4.3 item 4), when
//! this computer's user forgot it or it expired (section 4.6 items 2 and
//! 5), its latest session time (item 5) and the phone's display name
//! (section 4.3 item 4) -- with what this computer keeps beside it: the
//! phone's platform label and the cached authentication certificate. Operations leave nothing here: an operation
//! lives and ends inside its session (section 8.1), and a session that
//! fails before authentication changes nothing stored (section 10.1 item
//! 1).
//!
//! A record exists while its key does. A pairing that is revoked loses its
//! key and its record together.
//!
//! The store is a trait so the workstation keeps records in owner-only
//! files while tests use the in-memory form shipped here. It never
//! contains a credential value, a card identifier, or message plaintext.

pub use refineid_rapp::PairingState;
use refineid_rapp::{
    ActivePairing, DisplayName, EndpointRole, PairRecord, RecordStoreError, SweepOutcome,
};

use crate::ids::PairId;
use crate::persistence::frame_pairing_record;

/// What a phone introduced itself as in `pairing.hello` (section 4.3
/// item 3): labels for display, not identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIntroduction {
    /// The phone's display name.
    pub display_name: DisplayName,
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
    platform: String,
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
    /// The record of the requester's half of `pairing`, whose phone named
    /// its platform `platform`, with no cached certificate. The phone's
    /// display name is the engine record's.
    ///
    /// # Errors
    /// [`RecordError::NotRequester`] for a custodian's record.
    pub fn new(pairing: PairRecord, platform: String) -> Result<Self, RecordError> {
        if pairing.role() != EndpointRole::Requester {
            return Err(RecordError::NotRequester);
        }
        Ok(Self {
            pairing,
            platform,
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
    /// v26.11.2: awaiting the peer's storage confirmation
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

    /// The name the phone last sent for itself (section 4.3 item 4).
    #[must_use]
    pub const fn peer_display_name(&self) -> &DisplayName {
        self.pairing.peer_display_name()
    }

    /// The platform the phone named in its `pairing.hello`.
    #[must_use]
    pub fn peer_platform(&self) -> &str {
        &self.platform
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
            platform,
            auth_cert,
        } = self;
        let pairing = active
            .confirm(pairing)
            .map_err(|_| RecordError::PairMismatch)?;
        Ok(Self {
            pairing,
            platform,
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

    /// The pairing's idle-expiry sweep at `now_ms`, milliseconds since the
    /// Unix epoch (section 4.6 item 5), with `session_established` saying
    /// whether a session to it is established now: the engine's
    /// [`PairRecord::sweep`]. A change is handed to `write` as the whole
    /// stored record and taken into this one only once `write` returned
    /// `Ok`; with nothing to change, `write` is not called.
    ///
    /// # Errors
    /// [`RecordStoreError::Store`] with `write`'s error, or with
    /// [`StoreError::WriteRefused`] for a record that does not frame, and
    /// [`RecordStoreError::Encoding`] when the engine's record does not
    /// encode; the record is unchanged.
    pub fn sweep(
        &mut self,
        now_ms: u64,
        session_established: bool,
        write: impl FnOnce(&[u8]) -> Result<(), StoreError>,
    ) -> Result<SweepOutcome, RecordStoreError<StoreError>> {
        let Self {
            pairing,
            platform,
            auth_cert,
        } = self;
        pairing.sweep(now_ms, session_established, |encoded| {
            let blob = frame_pairing_record(encoded.as_bytes(), platform, auth_cert.as_deref())
                .map_err(|_| StoreError::WriteRefused)?;
            write(&blob)
        })
    }

    /// Keeps `name`, the display name the phone sent in `session.ready`,
    /// as the record's (section 4.3 item 4): the engine's
    /// [`PairRecord::record_peer_display_name`]. A different name is
    /// handed to `write` as the whole stored record and taken into this
    /// one only once `write` returned `Ok` (`Ok(true)`); an equal one
    /// writes nothing (`Ok(false)`).
    ///
    /// # Errors
    /// As [`Self::sweep`]; the record keeps its old name.
    pub fn rename_peer(
        &mut self,
        name: &DisplayName,
        write: impl FnOnce(&[u8]) -> Result<(), StoreError>,
    ) -> Result<bool, RecordStoreError<StoreError>> {
        let Self {
            pairing,
            platform,
            auth_cert,
        } = self;
        pairing.record_peer_display_name(name, |encoded| {
            let blob = frame_pairing_record(encoded.as_bytes(), platform, auth_cert.as_deref())
                .map_err(|_| StoreError::WriteRefused)?;
            write(&blob)
        })
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
    /// No per-user configuration directory resolves: none of
    /// `SNAP_USER_COMMON`, `XDG_CONFIG_HOME` or `HOME` names an absolute
    /// path.
    NoUserDirectory,
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

    /// One record's idle-expiry sweep at `now_ms` (section 4.6 item 5), as
    /// [`PairingRecord::sweep`] on the record as the store durably holds it
    /// now: a change is written before it is taken.
    ///
    /// # Errors
    ///
    /// [`RecordStoreError::Store`] with [`StoreError::Unknown`] when no
    /// record exists, and as [`PairingRecord::sweep`]; a refused write
    /// leaves the record as the store last held it durably, and the next
    /// sweep repeats the step.
    fn sweep(
        &mut self,
        pair_id: PairId,
        now_ms: u64,
        session_established: bool,
    ) -> Result<SweepOutcome, RecordStoreError<StoreError>>;

    /// One record's new peer display name (section 4.3 item 4), as
    /// [`PairingRecord::rename_peer`] on the record as the store durably
    /// holds it now: the new name is written before it is taken.
    ///
    /// # Errors
    ///
    /// As [`Self::sweep`]; a refused write keeps the old name, and the next
    /// session tries again.
    fn rename_peer(
        &mut self,
        pair_id: PairId,
        name: &DisplayName,
    ) -> Result<bool, RecordStoreError<StoreError>>;

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

    fn sweep(
        &mut self,
        pair_id: PairId,
        now_ms: u64,
        session_established: bool,
    ) -> Result<SweepOutcome, RecordStoreError<StoreError>> {
        self.records
            .iter_mut()
            .find(|entry| entry.pair_id() == pair_id)
            .ok_or(RecordStoreError::Store(StoreError::Unknown))?
            .sweep(now_ms, session_established, |_| Ok(()))
    }

    fn rename_peer(
        &mut self,
        pair_id: PairId,
        name: &DisplayName,
    ) -> Result<bool, RecordStoreError<StoreError>> {
        self.records
            .iter_mut()
            .find(|entry| entry.pair_id() == pair_id)
            .ok_or(RecordStoreError::Store(StoreError::Unknown))?
            .rename_peer(name, |_| Ok(()))
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
        DisplayName, EndpointRole, PairRecord, ProfileName, compute_grants_hash,
        generate_pair_key_material,
    };

    use super::PairingRecord;
    use crate::ids::PairId;

    /// When the fixtures' pairings were made.
    pub(crate) const CREATED_AT_MS: u64 = 1_700_000_000_000;

    /// The name of the phone every fixture is paired with.
    pub(crate) const PHONE_NAME: &str = "Alpha Phone";
    /// The platform of the phone every fixture is paired with.
    pub(crate) const PHONE_PLATFORM: &str = "iOS";

    /// The phone's display name.
    pub(crate) fn phone_name() -> DisplayName {
        DisplayName::parse(PHONE_NAME.to_owned()).expect("a valid name")
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
                    phone_name(),
                    CREATED_AT_MS,
                )
            })
            .expect("a valid record")
    }

    /// A usable record of `pair_id` granting card status.
    pub(crate) fn record(pair_id: PairId) -> PairingRecord {
        PairingRecord::new(
            pair_record(pair_id, vec![ProfileName::CardStatus]),
            PHONE_PLATFORM.to_owned(),
        )
        .expect("a requester record")
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use refineid_rapp::{DisplayName, EndpointRole, PairRecord, PairingState, ProfileName};

    use super::fixtures::{CREATED_AT_MS, PHONE_PLATFORM, phone_name, record};
    use super::{MemoryPairingStore, PairingRecord, PairingStore, RecordError, StoreError};
    use crate::ids::PairId;

    /// A synthetic pair identifier.
    const PAIR_ID: [u8; refineid_rapp::PAIR_ID_SIZE] = *b"synthetic-pair-1";
    /// When the fixture's user forgot it.
    const FORGOTTEN_AT_MS: u64 = 1_800_000_000_000;
    /// A synthetic authentication certificate.
    const CERTIFICATE: &[u8] = b"synthetic authentication certificate";
    /// The phone's name after its user renamed it.
    const RENAMED_PHONE: &str = "Beta Phone";

    #[test]
    fn records_update_into_their_successor_and_go_with_their_key() {
        let mut store = MemoryPairingStore::new();
        let pair_id = PairId::from_array(PAIR_ID);
        store.insert(record(pair_id)).unwrap();
        store
            .update(pair_id, &mut |entry| {
                Some(entry.with_auth_cert(Some(CERTIFICATE.to_vec())))
            })
            .unwrap();
        assert_eq!(store.get(pair_id).unwrap().auth_cert(), Some(CERTIFICATE));
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
                    phone_name(),
                    CREATED_AT_MS,
                )
            })
            .unwrap();
        assert_eq!(
            PairingRecord::new(custodian, PHONE_PLATFORM.to_owned()).err(),
            Some(RecordError::NotRequester)
        );
    }

    #[test]
    fn a_new_phone_name_replaces_the_stored_one_and_an_equal_one_writes_nothing() {
        let mut store = MemoryPairingStore::new();
        let pair_id = PairId::from_array(PAIR_ID);
        store.insert(record(pair_id)).unwrap();
        assert_eq!(store.rename_peer(pair_id, &phone_name()), Ok(false));
        let renamed = DisplayName::parse(RENAMED_PHONE.to_owned()).unwrap();
        assert_eq!(store.rename_peer(pair_id, &renamed), Ok(true));
        assert_eq!(store.get(pair_id).unwrap().peer_display_name(), &renamed);
        assert_eq!(store.get(pair_id).unwrap().peer_platform(), PHONE_PLATFORM);
    }

    #[test]
    fn a_record_refuses_a_name_that_fails_to_store_and_keeps_the_old_one() {
        let mut entry = record(PairId::from_array(PAIR_ID));
        let renamed = DisplayName::parse(RENAMED_PHONE.to_owned()).unwrap();
        assert!(
            entry
                .rename_peer(&renamed, |_| Err(StoreError::WriteRefused))
                .is_err()
        );
        assert_eq!(entry.peer_display_name(), &phone_name());
    }

    #[test]
    fn pairing_record_debug_names_no_key() {
        let text = format!("{:?}", record(PairId::from_array(PAIR_ID)));
        assert!(text.contains("pair_id"));
        assert!(!text.contains("private"));
    }
}
