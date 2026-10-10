//! The pairing code and the offer bootstrap.
//!
//! In RAPP v26.10.9 the custodian (the phone) shows a six-character code and
//! the requester types it (section 3). The custodian creates a random offer
//! and serves it as its first transport frame after the requester's pairing
//! preamble (section 4.2); the requester binds that offer's entry for the
//! connection's transport profile.

pub use refineid_rapp::cpace::CpaceError;
pub use refineid_rapp::{PairingOffer, PairingOfferError, TransportCandidate, TransportProfile};

/// Alias kept for the engine's error type.
pub type OfferError = PairingOfferError;

/// Characters in one pairing code (section 3.1).
pub const PAIRING_CODE_LENGTH: usize = 6;

/// Characters per display cluster (section 3.2: `XX XX XX`).
pub const PAIRING_CODE_GROUP_SIZE: usize = 2;

/// Offer lifetime the custodian binds into the offer (section 3.3).
pub const PAIRING_OFFER_LIFETIME_MS: u64 = refineid_rapp::OFFER_TTL_MS;

/// Crockford Base32 alphabet (section 3.1).
const CODE_ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Applies the section 3.1 canonicalization pipeline.
///
/// Uppercases ASCII letters, strips ASCII whitespace and hyphens, maps the
/// Crockford aliases `I`/`L` to `1` and `O` to `0`, and accepts the result
/// only when it is exactly six alphabet characters. Input outside ASCII is
/// refused rather than NFKC-normalized; every valid code is ASCII.
///
/// Returns `None` for input that is not a pairing code.
#[must_use]
pub fn normalize_pairing_code(input: &str) -> Option<String> {
    let mut code = String::with_capacity(PAIRING_CODE_LENGTH);
    for character in input.chars() {
        if !character.is_ascii() {
            return None;
        }
        let upper = character.to_ascii_uppercase();
        let mapped = match upper {
            ' ' | '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | '-' => continue,
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        if !CODE_ALPHABET.contains(mapped) {
            return None;
        }
        code.push(mapped);
    }
    (code.len() == PAIRING_CODE_LENGTH).then_some(code)
}

/// Formats a normalized code in two-character clusters (`7K X4 M9`).
#[must_use]
pub fn format_pairing_code(code: &str) -> String {
    let characters: Vec<char> = code.chars().collect();
    characters
        .chunks(PAIRING_CODE_GROUP_SIZE)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decodes the custodian's bootstrap frame into the offer this connection
/// binds (section 4.2 step 3).
///
/// # Errors
/// [`PairingOfferError`] when the bytes are not a valid offer of this
/// protocol version, or the offer does not list `profile`.
pub fn offer_from_bootstrap(
    bytes: &[u8],
    profile: TransportProfile,
) -> Result<PairingOffer, PairingOfferError> {
    PairingOffer::from_bootstrap(bytes, profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_follows_section_3_1() {
        assert_eq!(normalize_pairing_code("7kx4m9").as_deref(), Some("7KX4M9"));
        assert_eq!(
            normalize_pairing_code("7K X4-M9").as_deref(),
            Some("7KX4M9")
        );
        assert_eq!(normalize_pairing_code("ilo123").as_deref(), Some("110123"));
        assert_eq!(normalize_pairing_code("7KX4MU"), None);
        assert_eq!(normalize_pairing_code("7KX4M"), None);
        assert_eq!(normalize_pairing_code("7KX4M99"), None);
        assert_eq!(normalize_pairing_code("7KX4M\u{FF19}"), None);
    }

    #[test]
    fn display_uses_two_character_clusters() {
        assert_eq!(format_pairing_code("7KX4M9"), "7K X4 M9");
    }

    #[test]
    fn a_bootstrap_must_list_the_connection_transport() {
        let mut offer_id = [0_u8; refineid_rapp::OFFER_ID_SIZE];
        getrandom::fill(&mut offer_id).expect("random offer id");
        let offer = PairingOffer::create(
            refineid_rapp::OfferId::from_array(offer_id),
            vec![crate::profiles::PROFILE_AUTHENTICATION.to_owned()],
            &[TransportProfile::Stream],
        )
        .expect("offer");
        let bytes = offer.to_cbor().expect("encoded");
        let decoded = offer_from_bootstrap(&bytes, TransportProfile::Stream).expect("decoded");
        assert_eq!(decoded.offer_hash().ok(), offer.offer_hash().ok());
        assert_eq!(decoded.offer_ttl_ms, PAIRING_OFFER_LIFETIME_MS);
        assert_eq!(
            offer_from_bootstrap(&bytes, TransportProfile::Ble),
            Err(PairingOfferError::TransportNotOffered)
        );
    }
}
