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

//! The PIN a card flow presents, obtained when the flow reaches the
//! command that needs it.
//!
//! A flow picks the reader, finds the card and runs its checks first;
//! only then does it call [`PinSource::obtain`]. A missing reader, a
//! missing or wrong card, or a counter at the retry floor therefore
//! ends the flow before anyone is asked for a PIN.

use alloc::boxed::Box;
use core::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use refineid_lib_core::pin::PinBytes;

use crate::exit_status::ExitStatus;

/// PIN entry ended without a PIN. The entry has already told the
/// operator why; `status` is the exit status that outcome maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinEntryError {
    /// Exit status for the failed entry.
    pub status: ExitStatus,
}

impl fmt::Display for PinEntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PIN entry ended without a PIN")
    }
}

impl core::error::Error for PinEntryError {}

/// Reads a PIN from the operator.
pub type PinPrompt = Box<dyn FnMut() -> Result<PinBytes, PinEntryError> + Send>;

/// Where a flow gets its PIN.
pub enum PinSource {
    /// A PIN the caller already holds.
    Given(PinBytes),
    /// A prompt the flow runs at the point of use.
    Ask(PinPrompt),
}

impl PinSource {
    /// The PIN to present. [`PinSource::Ask`] runs its prompt now.
    ///
    /// # Errors
    /// The prompt's [`PinEntryError`].
    pub fn obtain(&mut self) -> Result<PinBytes, PinEntryError> {
        match self {
            Self::Given(pin) => Ok(pin.clone()),
            Self::Ask(prompt) => prompt(),
        }
    }
}

/// One prompt shared by several sources: the first source to be
/// obtained runs it, every later one answers with the same PIN. For a
/// run that signs several documents with one PIN, asked once.
pub struct SharedPin {
    prompt: Arc<Mutex<PinPrompt>>,
    answer: Arc<Mutex<Option<PinBytes>>>,
}

impl SharedPin {
    /// Wrap `prompt` so that it runs at most once.
    #[must_use]
    pub fn new(prompt: PinPrompt) -> Self {
        Self {
            prompt: Arc::new(Mutex::new(prompt)),
            answer: Arc::new(Mutex::new(None)),
        }
    }

    /// A source that asks the shared prompt, or repeats its answer.
    #[must_use]
    pub fn source(&self) -> PinSource {
        let prompt = Arc::clone(&self.prompt);
        let answer = Arc::clone(&self.answer);
        PinSource::Ask(Box::new(move || {
            let mut answer = answer.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(pin) = answer.as_ref() {
                return Ok(pin.clone());
            }
            let pin = (prompt.lock().unwrap_or_else(PoisonError::into_inner))()?;
            *answer = Some(pin.clone());
            Ok(pin)
        }))
    }
}

impl fmt::Debug for SharedPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedPin")
    }
}

impl fmt::Debug for PinSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Given(_) => "PinSource::Given",
            Self::Ask(_) => "PinSource::Ask",
        })
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! PIN sources that record whether a flow asked.

    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::{PinBytes, PinEntryError, PinSource};

    /// A synthetic PIN, in the shape every PIN slot accepts.
    pub(crate) const SYNTHETIC_PIN: &str = "123456";

    /// A source that counts its prompts and answers with
    /// [`SYNTHETIC_PIN`].
    pub(crate) fn counting_source() -> (PinSource, Arc<AtomicUsize>) {
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&asked);
        let source = PinSource::Ask(Box::new(move || {
            let _previous: usize = counter.fetch_add(1, Ordering::SeqCst);
            PinBytes::new(SYNTHETIC_PIN.as_bytes().to_vec()).map_err(|_policy| PinEntryError {
                status: crate::exit_status::ExitStatus::RuntimeFailure,
            })
        }));
        (source, asked)
    }

    /// How many times the source behind `asked` prompted.
    pub(crate) fn prompts(asked: &Arc<AtomicUsize>) -> usize {
        asked.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{counting_source, prompts};
    use super::*;
    use crate::test_util::{TestResult, check};

    #[test]
    fn ask_prompts_only_when_obtained() -> TestResult {
        let (mut source, asked) = counting_source();
        check(&prompts(&asked), &0, "before obtain")?;
        let _pin: PinBytes = source.obtain()?;
        check(&prompts(&asked), &1, "after obtain")
    }

    #[test]
    fn a_shared_prompt_runs_once_for_every_source() -> TestResult {
        let (source, asked) = counting_source();
        let PinSource::Ask(prompt) = source else {
            return Err("counting source asks".into());
        };
        let shared = SharedPin::new(prompt);
        let mut first = shared.source();
        let mut second = shared.source();
        let a: PinBytes = first.obtain()?;
        let b: PinBytes = second.obtain()?;
        check(&prompts(&asked), &1, "asked once")?;
        check(&(a.as_bytes() == b.as_bytes()), &true, "the same PIN")
    }

    #[test]
    fn debug_names_the_variant_only() -> TestResult {
        let (source, _asked) = counting_source();
        check(
            &format!("{source:?}"),
            &"PinSource::Ask".to_owned(),
            "debug",
        )
    }
}
