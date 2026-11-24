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

//! The single OS-CSPRNG seam for this crate.
//!
//! Re-exports [`Failure`] and [`fill`] from [`refineid_pace::rng`] and adds
//! [`array()`] for fixed-width random draws.

pub use refineid_pace::rng::{Failure, fill};

/// Draw a fresh `N`-byte array from the OS CSPRNG, or fail.
///
/// # Errors
/// Returns [`Failure`] if the OS RNG is unavailable.
#[inline]
pub fn array<const N: usize>() -> Result<[u8; N], Failure> {
    let mut bytes = [0_u8; N];
    fill(&mut bytes)?;
    Ok(bytes)
}
