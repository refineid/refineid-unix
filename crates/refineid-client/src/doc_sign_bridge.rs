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

//! The secrets this crate reads at its input boundary, in the types
//! `refineid_doc_sign` takes them as.
//!
//! The prompts and argument parsers produce `refineid_lib_core` types,
//! which the card commands outside document signing still use; core's
//! signing service takes its own. Each conversion copies the digits
//! once into the core type, which zeroizes them on drop.

use refineid_doc_sign::identity::{TokenSerial, render_token_serial};
use refineid_doc_sign::pin::{PinBytes, PinRoleError};
use refineid_pace::{Can, UnvalidatedCan};

/// The same Card Access Number as core's type, for one signing
/// session: core consumes a CAN per session and never copies it.
/// `None` only if core would refuse digits this crate accepted.
#[must_use]
pub fn can(can: &refineid_lib_core::can::Can) -> Option<Can> {
    Can::reconstruct(UnvalidatedCan::from_owned_text(can.as_str().to_owned())).ok()
}

/// The same card serial as core's type, rendered as core renders a
/// serial read off the card, so it compares equal to the live one.
#[must_use]
pub fn token_serial(serial: &refineid_lib_core::identity::TokenSerial) -> TokenSerial {
    render_token_serial(TokenSerial::new(serial.as_str().to_owned()))
}

/// The same PIN as core's type.
///
/// # Errors
/// [`PinRoleError`] when core refuses digits this crate accepted.
pub fn pin(pin: &refineid_lib_core::pin::PinBytes) -> Result<PinBytes, PinRoleError> {
    PinBytes::new(pin.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check, check_true};

    /// A synthetic CAN.
    const SYNTHETIC_CAN: &str = "123456";
    /// A synthetic PIN.
    const SYNTHETIC_PIN: &[u8] = b"123456";

    #[test]
    fn a_can_crosses_over() -> TestResult {
        let ours = refineid_lib_core::can::Can::new(SYNTHETIC_CAN)?;
        check_true(can(&ours).is_some(), "core accepts the same CAN")
    }

    #[test]
    fn a_pin_crosses_over_digit_for_digit() -> TestResult {
        let ours = refineid_lib_core::pin::PinBytes::new(SYNTHETIC_PIN.to_vec())?;
        let theirs = pin(&ours)?;
        check(&theirs.as_bytes(), &SYNTHETIC_PIN, "same digits")
    }
}
