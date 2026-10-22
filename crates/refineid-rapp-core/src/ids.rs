//! Protocol identifiers re-exported and extended from `refineid_rapp`.

use getrandom::fill;

pub use refineid_rapp::{
    CertificateFingerprint, GrantsHash, OfferId, OperationId, PairId, PairingSecret, PingChallenge,
    SessionId, derive_pair_id, derive_session_id,
};

/// The random-generator failure surfaced by identifier creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomUnavailable;

fn secure_random<const N: usize>() -> Result<[u8; N], RandomUnavailable> {
    let mut buf = [0u8; N];
    fill(&mut buf).map_err(|_| RandomUnavailable)?;
    Ok(buf)
}

/// Extension trait for generating random identifiers.
pub trait RandomIdExt: Sized {
    /// Generates a new identifier using a cryptographically secure random source.
    ///
    /// # Errors
    /// Returns [`RandomUnavailable`] when the platform entropy source fails.
    fn random() -> Result<Self, RandomUnavailable>;
}

impl RandomIdExt for OfferId {
    fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self::from_array(secure_random()?))
    }
}

impl RandomIdExt for OperationId {
    fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self::from_array(secure_random()?))
    }
}

impl RandomIdExt for PingChallenge {
    fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self::reconstruct(secure_random()?))
    }
}

impl RandomIdExt for PairingSecret {
    fn random() -> Result<Self, RandomUnavailable> {
        Ok(Self::from_random_bytes(secure_random()?))
    }
}
