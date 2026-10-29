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

// The build number `B` of the project version `YY.M.D.B`: the UTC time
// of day as the one integer hour * 100 + minute, with no leading zeros
// (7 at 00:07, 2105 at 21:05).
//
// build.rs compiles this file through `include!`, and the crate
// compiles it as a test-only module, so it holds plain comments and
// items only.

const SECONDS_PER_MINUTE: u64 = 60;
const MINUTES_PER_HOUR: u64 = 60;
const HOURS_PER_DAY: u64 = 24;
const SECONDS_PER_HOUR: u64 = SECONDS_PER_MINUTE * MINUTES_PER_HOUR;
const SECONDS_PER_DAY: u64 = SECONDS_PER_HOUR * HOURS_PER_DAY;
/// The build number is hour * 100 + minute.
const HOUR_WEIGHT: u64 = 100;
/// The largest build number, at 23:59.
const MAX_BUILD_NUMBER: u64 = (HOURS_PER_DAY - 1) * HOUR_WEIGHT + MINUTES_PER_HOUR - 1;

/// The build number at `epoch_seconds` after 1970-01-01T00:00:00Z.
fn build_number(epoch_seconds: u64) -> u64 {
    let second_of_day = epoch_seconds % SECONDS_PER_DAY;
    let hour = second_of_day / SECONDS_PER_HOUR;
    let minute = second_of_day % SECONDS_PER_HOUR / SECONDS_PER_MINUTE;
    hour * HOUR_WEIGHT + minute
}

/// Whether `text` is a build number: a decimal number from 0 to 2359
/// with no sign and no leading zero, whose last two digits are a
/// minute.
fn is_build_number(text: &str) -> bool {
    let canonical = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    canonical
        && text
            .parse::<u64>()
            .is_ok_and(|value| value <= MAX_BUILD_NUMBER && value % HOUR_WEIGHT < MINUTES_PER_HOUR)
}

#[cfg(test)]
mod tests {
    use super::{SECONDS_PER_HOUR, SECONDS_PER_MINUTE, build_number, is_build_number};

    /// A synthetic day start: 2001-01-01T00:00:00Z.
    const DAY_START: u64 = 978_307_200;

    fn at(hour: u64, minute: u64, second: u64) -> u64 {
        DAY_START + hour * SECONDS_PER_HOUR + minute * SECONDS_PER_MINUTE + second
    }

    #[test]
    fn midnight_is_zero() {
        assert_eq!(build_number(0), 0);
        assert_eq!(build_number(DAY_START), 0);
    }

    #[test]
    fn early_minutes_carry_no_leading_zeros() {
        const MINUTE: u64 = 7;
        assert_eq!(build_number(at(0, MINUTE, 0)).to_string(), "7");
    }

    #[test]
    fn hour_times_hundred_plus_minute() {
        const HOUR: u64 = 21;
        const MINUTE: u64 = 5;
        const SECOND: u64 = 59;
        assert_eq!(build_number(at(HOUR, MINUTE, SECOND)).to_string(), "2105");
    }

    #[test]
    fn last_minute_of_the_day_then_midnight() {
        const HOUR: u64 = 23;
        const MINUTE: u64 = 59;
        const SECOND: u64 = 59;
        let last = at(HOUR, MINUTE, SECOND);
        assert_eq!(build_number(last).to_string(), "2359");
        assert_eq!(build_number(last + 1), 0);
    }

    #[test]
    fn build_number_shape() {
        assert!(is_build_number("0"));
        assert!(is_build_number("7"));
        assert!(is_build_number("2359"));
        assert!(!is_build_number("007"));
        assert!(!is_build_number("2400"));
        assert!(!is_build_number("1260"));
        assert!(!is_build_number("-1"));
        assert!(!is_build_number("1.5"));
        assert!(!is_build_number(""));
    }
}
