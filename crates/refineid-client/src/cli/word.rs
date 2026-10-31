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

//! Command words shortened to a prefix.
//!
//! A word that equals a candidate names it. Otherwise a word that
//! starts exactly one candidate names that one, so `doc s` is
//! `document sign`. A word that starts several is ambiguous and is
//! never guessed at; the caller reports the candidates.

/// What a word names among a set of candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match<'a> {
    /// Exactly one candidate: the word itself, or the only one it
    /// starts.
    One(&'a str),
    /// No candidate equals or starts with the word.
    None,
    /// Several candidates start with the word, in candidate order.
    Several(Vec<&'a str>),
}

/// The candidate `word` names: itself when it is one, else the one
/// candidate it is a prefix of. An empty word names nothing.
pub fn resolve<'a>(word: &str, candidates: impl IntoIterator<Item = &'a str>) -> Match<'a> {
    if word.is_empty() {
        return Match::None;
    }
    let mut started = Vec::new();
    for candidate in candidates {
        if candidate == word {
            return Match::One(candidate);
        }
        if candidate.starts_with(word) {
            started.push(candidate);
        }
    }
    match started.as_slice() {
        [] => Match::None,
        [only] => Match::One(only),
        _ => Match::Several(started),
    }
}

#[cfg(test)]
mod tests {
    use super::{Match, resolve};
    use crate::test_util::{TestResult, check};

    const WORDS: &[&str] = &["card", "cert", "pin", "phone", "document", "verify"];

    #[test]
    fn a_whole_word_names_itself_even_when_it_starts_another() -> TestResult {
        check(
            &resolve("pin", ["pin", "pinhole"]),
            &Match::One("pin"),
            "exact wins",
        )
    }

    #[test]
    fn a_prefix_of_one_candidate_names_it() -> TestResult {
        check(
            &resolve("doc", WORDS.iter().copied()),
            &Match::One("document"),
            "doc",
        )?;
        check(
            &resolve("v", WORDS.iter().copied()),
            &Match::One("verify"),
            "v",
        )
    }

    #[test]
    fn a_prefix_of_several_lists_them_in_order() -> TestResult {
        check(
            &resolve("c", WORDS.iter().copied()),
            &Match::Several(vec!["card", "cert"]),
            "c",
        )?;
        check(
            &resolve("p", WORDS.iter().copied()),
            &Match::Several(vec!["pin", "phone"]),
            "p",
        )
    }

    #[test]
    fn no_candidate_and_the_empty_word_name_nothing() -> TestResult {
        check(&resolve("x", WORDS.iter().copied()), &Match::None, "x")?;
        check(&resolve("", WORDS.iter().copied()), &Match::None, "empty")
    }
}
