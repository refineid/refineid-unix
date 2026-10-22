//! The credential-profile registry (RAPP v26.10.21 section 9).
//!
//! The names come from the engine's registry, so the strings this crate
//! stores and compares are exactly the ones the wire carries.

pub use refineid_rapp::ProfileName;

/// Inspect the card and read its identity. No consequential command.
pub const PROFILE_CARD_STATUS: &str = ProfileName::CardStatus.as_str();
/// Browser or application authentication: PIN 1 verify and key operation.
pub const PROFILE_AUTHENTICATION: &str = ProfileName::Authentication.as_str();
/// Sign a document digest: PIN 2 verify and key operation.
pub const PROFILE_DOCUMENT_SIGNING: &str = ProfileName::DocumentSigning.as_str();
