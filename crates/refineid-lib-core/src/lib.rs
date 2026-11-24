// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! FINEID smart-card protocol -- language-agnostic, transport-
//! agnostic.
//!
//! Layered from the card edge upwards. The foundation modules
//! ([`backend`], [`error`], [`transport`]) define the ports and
//! types every higher layer depends on. The crypto, protocol, and
//! use-case layers (PACE, secure messaging, eMRTD, PKCS#15, PIN,
//! and signing operations) sit on top.
//!
//! ## Typing-discipline backbone
//!
//! Three modules carry the type-level safety this codebase
//! leans on (see [`doc/typing-discipline.md`][typing] for the
//! full position):
//!
//! - [`oid`] -- typed [`Oid<'a>`] wrapper over OBJECT
//!   IDENTIFIER content bytes, plus a `known` submodule of
//!   spec-cited static `Oid<'static>` constants.
//! - [`fineid_card`] -- card-identity newtypes ([`Atr`],
//!   [`Ats`], [`CardType`], [`CardVendor`], [`FineidCardModel`])
//!   that project DVV's ATR/ATS technote and the wider FINEID
//!   card-model taxonomy onto the type system. The classifier
//!   refuses out-of-scope cards before any modify APDU.
//! - [`cert_state`] -- owned certificate provenance wrapper
//!   ([`CertDer`]) separating raw card-slot DER reads from
//!   parsed and verified X.509 certificate views in [`x509`].
//!
//! [`Oid<'a>`]: oid::Oid
//! [`Atr`]: fineid_card::Atr
//! [`Ats`]: fineid_card::Ats
//! [`CardType`]: fineid_card::CardType
//! [`CardVendor`]: fineid_card::CardVendor
//! [`FineidCardModel`]: fineid_card::FineidCardModel
//! [`CertDer`]: cert_state::CertDer
//! [typing]: ../../../../doc/typing-discipline.md

// `clippy::pub_use` fires on every `pub use submodule::Item;` at
// the crate root.  Those re-exports are the library-facade
// pattern: external consumers reach `refineid_lib_core::Item`
// without depending on which submodule defines it.  Per-item
// `#[expect(clippy::pub_use)]` is rejected by rustc as a useless
// lint attribute (the lint fires at crate scope, not on the
// use-item), so the suppression lives here as a crate-level
// inner attribute carrying the rationale for the whole cluster.
#![expect(
    clippy::pub_use,
    reason = "library-facade pattern: crate root re-exports the public API surface of submodules so external consumers don't depend on the internal module layout"
)]

pub mod aa;
pub mod apdu;
pub use refineid_atr as atr;
pub mod auth;
pub mod backend;
pub mod base64;
pub(crate) use refineid_ber as ber;
pub mod ca;
pub mod can;
pub mod card_access;
pub mod cert_state;
pub mod cms;
pub mod country;
pub mod crl;
pub mod crypto;
pub mod emrtd;
pub mod error;
pub mod events;

/// FINEID card identity and ATR/ATS classification, re-exported from
/// [`refineid_atr::fineid`] alongside the core ATR types.
pub mod fineid_card {
    #![expect(
        clippy::pub_use,
        reason = "library-facade pattern: collects FINEID model classification and core ATR types under fineid_card::*"
    )]
    pub use refineid_atr::fineid::*;
    pub use refineid_atr::{ATR_MAX_LEN, ATR_MIN_LEN, Atr, AtrError};
}
pub mod hex;
pub mod identity;
pub mod iso8601;
pub mod ocsp;
pub mod oid;
pub mod pace;
pub mod pin;
pub mod pkcs15;
pub mod revocation;
pub mod rng;
pub mod secure_messaging;
pub mod sign;
pub mod text;
pub mod transport;
pub mod x509;

// Library-facade re-exports of the crate's public surface.
// Module-level `#![expect]` at the crate root carries the
// rationale for the cluster; per-item `#[expect(clippy::pub_use)]`
// is rejected by rustc as a useless lint attribute (the lint
// fires at module scope, not on the use-item).
pub use backend::ReaderBackend;
pub use error::IoError;

/// Project version `YY.M.D.B`, or `YY.M.D~MB` with a build mark `M`:
/// the workspace version `YY.M.D`, the UTC day the code last changed,
/// and the build number `B`, the UTC time of day of the build as
/// hour * 100 + minute, as build.rs assembles them.
pub const VERSION: &str = env!("REFINEID_VERSION");
