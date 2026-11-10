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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `scs` typed arguments.

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};

/// What `refineid scs help`
/// prints. The man page refineid(1) carries the same facts.
pub const HELP: &str = "\
usage: refineid scs

Serve the Signature Creation Service on https://127.0.0.1:53952
until interrupted: web pages sign through the local card. The
first run generates the server identity and prints its
certificate fingerprint; later runs reuse it. Every signature
prompts for its PIN, naming the site and the digest.
";

/// Parsed `scs` arguments: none; the port is fixed by the
/// specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScsArgs;

impl ScsArgs {
    /// Execute the `scs` verb.
    #[must_use]
    pub fn run(self, verbose: bool) -> std::process::ExitCode {
        crate::scs_server::serve(verbose)
    }

    /// Parse the post-subcommand argv slice. Accepts no arguments.
    ///
    /// # Errors
    /// [`ArgParseError`] when any argument is given.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let tokens = argv.into_vec();
        match tokens.as_slice() {
            [] => Ok(Self),
            [first, ..] => Err(ArgParseError::Unexpected {
                cmd: VerbTag::Scs,
                got: first.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check_true};

    #[test]
    fn parses_empty() -> TestResult {
        let _args = ScsArgs::parse(argv(&[]))?;
        Ok(())
    }

    #[test]
    fn extra_argument_rejected() -> TestResult {
        let result = ScsArgs::parse(argv(&["--port"]));
        check_true(
            matches!(result, Err(ArgParseError::Unexpected { .. })),
            "Unexpected",
        )
    }
}
