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

//! Card Access Number -- typed wrapper around the 4-12 digit code
//! printed on the front of a FINEID personal card or used for an
//! organisational card.
//!
//! See [`doc/typing-discipline.md`][doc] for why we newtype
//! values that cross trust boundaries. The CAN crosses a real
//! one: it's operator input (typed at a CLI prompt or piped
//! from an LDIF / config) and reaches the card via the PACE
//! key-derivation path. A wrong CAN does not consume a retry
//! counter, but the card can suspend it until a power reset.
//!
//! The CAN is a secret, handled like PIN 1, PIN 2, the PUK and the
//! Activation PIN: never displayed back, never logged (neither its
//! digits nor its length), never sent over any network, RAPP,
//! diagnostics or export path. `Debug` redacts it and there is no
//! `Display`; the bytes leave the type only through
//! [`Can::as_bytes`] for the PACE key derivation. Constructor-only
//! construction means downstream code taking `&Can` can assume
//! well-formed bytes without re-validating; CLI parse-don't-validate
//! replaces the previous `validate_can(&str) -> Result<(), _>` shape
//! where the raw `&str` survived the check.
//!
//! [doc]: ../../../../doc/typing-discipline.md

use core::fmt;

/// Minimum number of ASCII digits in a Card Access Number.
pub const CAN_MIN_DIGITS: usize = 4;

/// Maximum number of ASCII digits in a Card Access Number.
pub const CAN_MAX_DIGITS: usize = 12;

/// Default number of ASCII digits in a personal card's CAN.
/// FINEID and ICAO 9303 §6.2 fix personal cards at 6.
pub const CAN_DIGITS: usize = 6;

/// A FINEID Card Access Number, validated at construction.
///
/// 4 to 12 ASCII digits. The internal byte array is the only
/// representation. `Debug` prints a fixed placeholder; the type has
/// no `Display`.
#[derive(Clone, Copy)]
pub struct Can {
    bytes: [u8; CAN_MAX_DIGITS],
    len: u8,
}

impl PartialEq for Can {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Can {}

impl fmt::Debug for Can {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Can(<redacted>)")
    }
}

/// Error returned by [`Can::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanError {
    /// Input was empty.
    Empty,
    /// Input was the wrong length. CAN must be between 4 and 12 digits.
    WrongLength,
    /// A non-digit byte appeared.
    NonDigit,
    /// The CAN was all zeros. Syntactically numeric digits, but
    /// never a real issued value on a production card -- an all-zero
    /// CAN means the input was lost / uninitialised / zeroed
    /// somewhere upstream, not entered. Rejected as a
    /// data-integrity sentinel. (This is the *only* "value" CAN
    /// rejects beyond shape; we do not police other unlikely-but-
    /// possible CANs -- the card is the authority on correctness.)
    AllZeros,
}

impl fmt::Display for CanError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "CAN cannot be empty"),
            Self::WrongLength => {
                write!(
                    f,
                    "CAN must be between {CAN_MIN_DIGITS} and {CAN_MAX_DIGITS} digits"
                )
            }
            Self::NonDigit => write!(f, "CAN must be ASCII digits only"),
            Self::AllZeros => write!(f, "CAN is not an issued card access number"),
        }
    }
}

impl core::error::Error for CanError {}

impl Can {
    /// Parse `s` as a CAN. Accepts between 4 and 12 ASCII-digit bytes;
    /// rejects anything else with a specific [`CanError`].
    ///
    /// # Errors
    /// Empty input, wrong length (not 4..=12), or any non-digit byte.
    #[inline]
    pub fn new<S: AsRef<str>>(s: S) -> Result<Self, CanError> {
        let bytes = s.as_ref().as_bytes();
        if bytes.is_empty() {
            return Err(CanError::Empty);
        }
        if bytes.len() < CAN_MIN_DIGITS || bytes.len() > CAN_MAX_DIGITS {
            return Err(CanError::WrongLength);
        }
        if bytes.iter().any(|b| !b.is_ascii_digit()) {
            return Err(CanError::NonDigit);
        }
        // All-zero CAN: well-formed shape, but never a real issued
        // value -- treat it as a lost-data sentinel, not a CAN.
        if bytes.iter().all(|&b| b == b'0') {
            return Err(CanError::AllZeros);
        }
        let mut buf = [0_u8; CAN_MAX_DIGITS];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: buf,
            len: bytes.len() as u8,
        })
    }

    /// The ASCII digit bytes that make up the CAN.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Number of digits in the CAN.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the CAN is empty (always false for a valid [`Can`]).
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {

    use super::{CAN_MAX_DIGITS, CAN_MIN_DIGITS, Can, CanError};

    #[test]
    fn happy_path() {
        let c = Can::new("123456").expect("six digits is a valid CAN");
        assert_eq!(c.as_bytes(), b"123456");
        assert_eq!(c.len(), 6);
        assert!(!c.is_empty());
    }

    #[test]
    fn variable_lengths() {
        for valid in ["1234", "12345", "123456", "12345678", "123456789012"] {
            let c = Can::new(valid).unwrap_or_else(|_| panic!("{valid} should be valid"));
            assert_eq!(c.as_bytes(), valid.as_bytes());
            assert_eq!(c.len(), valid.len());
        }
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(Can::new(""), Err(CanError::Empty));
    }

    #[test]
    fn rejects_too_short() {
        assert_eq!(Can::new("123"), Err(CanError::WrongLength));
    }

    #[test]
    fn rejects_too_long() {
        assert_eq!(Can::new("1234567890123"), Err(CanError::WrongLength));
    }

    #[test]
    fn rejects_letter() {
        assert_eq!(Can::new("12a456"), Err(CanError::NonDigit));
        assert_eq!(Can::new("12a4"), Err(CanError::NonDigit));
    }

    #[test]
    fn rejects_dash() {
        assert_eq!(Can::new("12-456"), Err(CanError::NonDigit));
    }

    #[test]
    fn display_omits_candidate_metadata() {
        assert_eq!(
            CanError::WrongLength.to_string(),
            format!("CAN must be between {CAN_MIN_DIGITS} and {CAN_MAX_DIGITS} digits")
        );
        assert_eq!(
            CanError::NonDigit.to_string(),
            "CAN must be ASCII digits only"
        );
        assert_eq!(CanError::Empty.to_string(), "CAN cannot be empty");
    }

    #[test]
    fn debug_redacts_digits() {
        let c = Can::new("987654").expect("six digits is a valid CAN");
        let rendered = format!("{c:?}");
        assert_eq!(rendered, "Can(<redacted>)");
        assert!(!rendered.contains("987654"));
        assert!(!rendered.chars().any(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn error_texts_carry_no_input() {
        for (input, error) in [
            ("12a456", CanError::NonDigit),
            ("000000", CanError::AllZeros),
            ("0000", CanError::AllZeros),
            ("123", CanError::WrongLength),
        ] {
            let text = Can::new(input).expect_err("rejected").to_string();
            assert_eq!(Can::new(input), Err(error));
            assert!(!text.contains(input));
        }
    }

    /// All-zero values are shape-valid (ASCII digits in range) but
    /// never a real issued CAN -- an all-zero value means the input
    /// was lost or zeroed upstream. Rejected as a data-integrity
    /// sentinel.
    #[test]
    fn rejects_all_zeros() {
        for zeros in ["0000", "000000", "000000000000"] {
            assert_eq!(Can::new(zeros), Err(CanError::AllZeros));
        }
    }

    /// The all-zero reject is the *only* value-level rule: a CAN
    /// that merely contains zeros (leading, trailing, or interior)
    /// is accepted. We don't police "unlikely" CANs -- the card is
    /// the authority on correctness.
    #[test]
    fn accepts_cans_with_some_zeros() {
        for can in [
            "0001",
            "000001",
            "100000",
            "012300",
            "010101",
            "000000000001",
        ] {
            assert!(Can::new(can).is_ok(), "{can} should be accepted");
        }
    }
}
