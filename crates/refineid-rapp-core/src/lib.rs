//! Remote Authorization Proxy Protocol (RAPP) requester core.
//!
//! This crate implements the requester role of RAPP v26.10.21 for Unix
//! workstations: the workstation asks for typed credential operations, and
//! the custodian — the holder's phone — presents consent, talks to the
//! identity card, and returns only the profile-defined result.
//!
//! Protocol primitives, Noise cryptography, and canonical framing are provided
//! by `refineid_rapp`.

pub mod addresses;
pub mod engine;
pub mod file_store;
pub mod ids;
pub mod message;
pub mod offer;
pub mod operations;
pub mod persistence;
pub mod profiles;
pub mod remote;
pub mod session_lock;
pub mod store;
pub mod stream;
pub mod transport;

/// The wire version of RAPP from canonical core.
pub const WIRE_VERSION: (u16, u16, u16) = refineid_rapp::WIRE_VERSION_V26_10_21;

/// The mandatory pairing handshake construction.
pub const PAIRING_SUITE: &str = refineid_rapp::MANDATORY_PAIRING_SUITE;

/// The mandatory session handshake construction.
pub const SESSION_SUITE: &str = refineid_rapp::MANDATORY_SESSION_SUITE;

/// Named resource limits re-exported from canonical core.
pub mod limits {
    /// Maximum bytes in one Noise frame (`NOISE_MAX_MESSAGE`).
    pub const NOISE_MAX_MESSAGE: usize = refineid_rapp::MAX_FRAME_SIZE;

    /// Maximum plaintext bytes in one envelope (`MAX_FRAME_PLAINTEXT`).
    pub const MAX_FRAME_PLAINTEXT: usize = refineid_rapp::MAX_FRAME_PLAINTEXT;

    /// Maximum encoded pairing-offer bytes (`MAX_OFFER_SIZE`).
    pub const MAX_OFFER_SIZE: usize = refineid_rapp::MAX_OFFER_SIZE;

    /// Operations one session carries at a time (section 8.1 item 1).
    pub const MAX_ACTIVE_OPERATIONS: usize = refineid_rapp::MAX_ACTIVE_OPERATIONS;

    /// Pairing-offer lifetime in milliseconds (`OFFER_TTL_MS`).
    pub const OFFER_TTL_MS: u64 = refineid_rapp::OFFER_TTL_MS;
}
