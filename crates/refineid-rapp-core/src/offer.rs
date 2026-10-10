//! The pairing code and the offer both peers derive from it.
//!
//! In RAPP v26.10.1 the custodian (the phone) shows a six-character code and
//! the requester types it (section 3). Over the stream transport neither peer
//! publishes an offer: both derive the same offer from the code, so the
//! `offer_hash` that CPace and the Noise prologue bind is identical on both
//! sides without anything code-derived ever leaving the device.

use std::collections::BTreeMap;

pub use refineid_rapp::cpace::{CpaceError, derive_manual_offer_id};
pub use refineid_rapp::{PairingOffer, PairingOfferError, TransportCandidate};

use crate::profiles::{PROFILE_AUTHENTICATION, PROFILE_CARD_STATUS, PROFILE_DOCUMENT_SIGNING};

/// Alias kept for the engine's error type.
pub type OfferError = PairingOfferError;

/// Characters in one pairing code (section 3.1).
pub const PAIRING_CODE_LENGTH: usize = 6;

/// Characters per display cluster (section 3.2: `XX XX XX`).
pub const PAIRING_CODE_GROUP_SIZE: usize = 2;

/// Offer lifetime both peers bind into the offer (section 3.3).
pub const PAIRING_OFFER_LIFETIME_MS: u64 = 60_000;

/// Crockford Base32 alphabet (section 3.1).
const CODE_ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Profiles a code-derived offer names, in the custodian's order.
pub const OFFERED_PROFILES: [&str; 3] = [
    PROFILE_CARD_STATUS,
    PROFILE_AUTHENTICATION,
    PROFILE_DOCUMENT_SIGNING,
];

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

/// The offer both peers derive from a normalized code for one transport
/// candidate.
///
/// The candidate carries no parameters: the requester finds the custodian
/// by its published discovery attributes, not by an endpoint in the offer.
///
/// # Errors
/// [`CpaceError`] for a code the derivation refuses, and
/// [`CpaceError::MalformedFrame`] when the offer fails its structural rules.
pub fn code_offer(
    normalized_code: &str,
    transport_profile: &str,
    candidate_id: &str,
) -> Result<PairingOffer, CpaceError> {
    let offer_id = derive_manual_offer_id(normalized_code)?;
    PairingOffer::reconstruct(
        offer_id,
        vec![refineid_rapp::CPACE_KC2_SUITE.to_owned()],
        OFFERED_PROFILES
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        vec![TransportCandidate {
            profile: transport_profile.to_owned(),
            candidate_id: candidate_id.to_owned(),
            parameters: BTreeMap::new(),
        }],
        PAIRING_OFFER_LIFETIME_MS,
    )
    .map_err(|_| CpaceError::MalformedFrame)
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
    fn both_spellings_of_a_code_derive_one_offer() {
        let first = code_offer(
            &normalize_pairing_code("7kx4m9").expect("valid"),
            refineid_rapp::STREAM_PROFILE,
            "stream-1",
        )
        .expect("offer");
        let second = code_offer(
            &normalize_pairing_code("7K X4 M9").expect("valid"),
            refineid_rapp::STREAM_PROFILE,
            "stream-1",
        )
        .expect("offer");
        assert_eq!(
            first.offer_hash().expect("hash"),
            second.offer_hash().expect("hash")
        );
        assert_eq!(first.offer_ttl_ms, PAIRING_OFFER_LIFETIME_MS);
        assert_eq!(first.suites, [refineid_rapp::CPACE_KC2_SUITE]);
    }
}
