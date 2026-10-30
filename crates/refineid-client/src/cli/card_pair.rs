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

//! `refineid pair`, `refineid pairs`, and `refineid unpair` CLI commands.

use alloc::string::{String, ToString};
use std::io::{BufRead as _, Write as _};
use std::process::ExitCode;
use std::time::Duration;

use refineid_rapp_core::offer::{format_pairing_code, normalize_pairing_code};
use refineid_rapp_core::profiles::ProfileName;
use refineid_rapp_core::remote::{RemoteError, RemoteReader};

use super::ArgParseError;
use super::argv::RemainingArgv;
use super::verb::VerbTag;
use crate::exit_status::ExitStatus;

/// The first HTTP status code that means the site refused the request:
/// the client and server error classes, as `curl --fail` counts them.
/// A redirect after a certificate login is the site moving on.
const HTTP_FIRST_ERROR_STATUS: u16 = 400;
/// The position of the status code in an HTTP status line.
const HTTP_STATUS_CODE_FIELD: usize = 1;

/// The status code of an HTTP status line, `None` when the line has none.
fn http_status_code(status_line: &str) -> Option<u16> {
    status_line
        .split_whitespace()
        .nth(HTTP_STATUS_CODE_FIELD)
        .and_then(|code| code.parse().ok())
}

/// What `refineid pair help`
/// prints. The man page refineid(1) carries the same facts.
pub const PAIR_HELP: &str = "\
usage: refineid pair

Pair with a phone running RefineID. Start pairing on the phone and
type the six-character code it shows. The code is read from the
prompt only, never from the command line.
Prints nothing on success; -v shows each step.
";

/// What `refineid pairs help`
/// prints. The man page refineid(1) carries the same facts.
pub const PAIRS_HELP: &str = "\
usage: refineid pairs

List the paired phone.
";

/// What `refineid unpair help`
/// prints. The man page refineid(1) carries the same facts.
pub const UNPAIR_HELP: &str = "\
usage: refineid unpair

Forget the paired phone. Prints nothing on success; -v shows each step.
";

/// What `refineid auth help`
/// prints. The man page refineid(1) carries the same facts.
pub const AUTH_HELP: &str = "\
usage: refineid auth [URL]

Log in to a TLS site with the card in the paired phone and print the
response's status line; a 4xx or 5xx status exits 1. URL defaults to
https://card.refineid.fi.
-v shows each step.
";

/// How long pairing and operations browse for the phone.
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Arguments for `refineid pair`. The code is read from the prompt only,
/// never from the command line, where other local accounts could read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairArgs;

impl PairArgs {
    /// Parse arguments for `refineid pair`, which takes none.
    ///
    /// # Errors
    /// Returns [`ArgParseError`] on any argument.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        match argv.into_vec().first() {
            None => Ok(Self),
            Some(got) => Err(ArgParseError::Unexpected {
                cmd: VerbTag::CardPair,
                got: got.clone(),
            }),
        }
    }

    /// Pair with the phone that shows the code. Silent on success;
    /// `verbose` prints the steps.
    #[must_use]
    pub fn run(self, verbose: bool) -> ExitCode {
        let Some(code) = prompt_code() else {
            eprintln!("pair: that is not a pairing code");
            return ExitStatus::BadInvocation.into();
        };
        let Some(normalized) = normalize_pairing_code(&code) else {
            eprintln!("pair: that is not a pairing code");
            return ExitStatus::BadInvocation.into();
        };

        let mut reader = match RemoteReader::open_local() {
            Ok(reader) => reader,
            Err(e) => {
                eprintln!("pair: cannot open the paired-phone store: {e}");
                return ExitStatus::RuntimeFailure.into();
            }
        };
        if verbose {
            println!(
                "Looking for the phone showing {} on the local network",
                format_pairing_code(&normalized)
            );
        }
        let pair = match reader.pair_with_code(&normalized, DISCOVERY_TIMEOUT) {
            Ok(pair) => pair,
            Err(RemoteError::Pairing(error)) => {
                eprintln!("pair: {error}");
                return ExitStatus::RuntimeFailure.into();
            }
            Err(e) => {
                eprintln!("pair: {e}");
                return ExitStatus::RuntimeFailure.into();
            }
        };
        if verbose {
            println!(
                "Paired with {} ({})",
                pair.peer_display_name, pair.peer_platform
            );
            println!("Retrieving the authentication certificate for offline caching");
        }
        match reader.refresh_auth_cert(pair.pair_id, DISCOVERY_TIMEOUT) {
            Ok(_) => {
                if verbose {
                    println!("Cached the authentication certificate");
                }
            }
            Err(e) => eprintln!("pair: authentication certificate not cached: {e}"),
        }
        if verbose {
            println!("Pair ID: {}", pair.pair_id_hex());
            println!(
                "Granted profiles: {}",
                profile_names(&pair.granted_profiles)
            );
        }
        ExitStatus::Ok.into()
    }
}

/// The registered names of `profiles`, for display.
fn profile_names(profiles: &[ProfileName]) -> String {
    profiles
        .iter()
        .map(|profile| profile.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Prompt on stderr and read one line from standard input as the
/// pairing code.
fn prompt_code() -> Option<String> {
    eprint!("Pairing code: ");
    std::io::stderr().flush().ok()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).ok()?;
    normalize_pairing_code(line.trim()).map(|_| line.trim().to_owned())
}

/// Arguments for `refineid pairs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairsArgs;

impl PairsArgs {
    /// Parse arguments for `refineid pairs`.
    ///
    /// # Errors
    /// Returns [`ArgParseError`] on unexpected arguments.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let tokens = argv.into_vec();
        if let Some(arg) = tokens.into_iter().next() {
            return Err(ArgParseError::Unexpected {
                cmd: VerbTag::CardPairs,
                got: arg,
            });
        }
        Ok(Self)
    }

    /// List all paired devices.
    #[must_use]
    pub fn run(self) -> ExitCode {
        let reader = match RemoteReader::open_local() {
            Ok(reader) => reader,
            Err(e) => {
                eprintln!("pairs: cannot read the paired-phone store: {e}");
                return ExitStatus::RuntimeFailure.into();
            }
        };
        let Some(pair) = reader.phone() else {
            println!("No phone paired.");
            return ExitStatus::Ok.into();
        };
        println!("Phone: {} - {}", pair.peer_display_name, pair.peer_platform);
        println!("  Pair ID:    {}", pair.pair_id_hex());
        println!("  Profiles:   {}", profile_names(&pair.granted_profiles));
        println!(
            "  Cert cache: {}",
            if pair.auth_cert.is_some() {
                "Cached"
            } else {
                "None"
            }
        );
        ExitStatus::Ok.into()
    }
}

/// Arguments for `refineid unpair`, which takes none: it forgets the
/// paired phone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnpairArgs;

impl UnpairArgs {
    /// Parse arguments for `refineid unpair`, which takes none.
    ///
    /// # Errors
    /// Returns [`ArgParseError`] on any argument.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        match argv.into_vec().first() {
            None => Ok(Self),
            Some(got) => Err(ArgParseError::Unexpected {
                cmd: VerbTag::CardUnpair,
                got: got.clone(),
            }),
        }
    }

    /// Forget the paired phone. Silent on success; `verbose` says
    /// whether the phone was told.
    #[must_use]
    pub fn run(self, verbose: bool) -> ExitCode {
        let mut reader = match RemoteReader::open_local() {
            Ok(reader) => reader,
            Err(e) => {
                eprintln!("unpair: cannot read the paired-phone store: {e}");
                return ExitStatus::RuntimeFailure.into();
            }
        };
        let Some(phone) = reader.phone() else {
            eprintln!("unpair: no phone paired");
            return ExitStatus::RuntimeFailure.into();
        };
        if let Err(e) = reader.forget() {
            eprintln!("unpair: cannot forget {}: {e}", phone.peer_display_name);
            return ExitStatus::RuntimeFailure.into();
        }
        let told = reader.deliver_revocation_notices() > 0;
        if verbose {
            if told {
                println!("Forgot {}; the phone was told.", phone.peer_display_name);
            } else {
                println!(
                    "Forgot {}; the phone is told when this computer next reaches it.",
                    phone.peer_display_name
                );
            }
        }
        ExitStatus::Ok.into()
    }
}

/// Arguments for `refineid auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthArgs {
    /// URL to authenticate to (default: <https://card.refineid.fi>).
    pub url: Option<String>,
}

impl AuthArgs {
    /// Parse arguments for `refineid auth`.
    ///
    /// # Errors
    /// Returns [`ArgParseError`] on syntax error.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let tokens = argv.into_vec();
        let mut url = None;
        for token in tokens {
            if !token.starts_with('-') && url.is_none() {
                url = Some(token);
            }
        }
        Ok(Self { url })
    }

    /// Run the `refineid auth` command: print the response's status
    /// line. `verbose` adds the steps and the page's title lines.
    #[must_use]
    pub fn run(self, verbose: bool) -> ExitCode {
        let target = self.url.as_deref().unwrap_or("https://card.refineid.fi");
        let reader = match RemoteReader::open_local() {
            Ok(reader) => reader,
            Err(e) => {
                eprintln!("auth: cannot open the paired-phone store: {e}");
                return ExitStatus::RuntimeFailure.into();
            }
        };
        let Some(pair) = reader.phone() else {
            eprintln!("auth: no phone paired; run `refineid pair` first");
            return ExitStatus::RuntimeFailure.into();
        };
        let uri = match refineid_lib_core::text::Uri::parse(target.to_string()) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("auth: invalid URL {target}: {e:?}");
                return ExitStatus::BadInvocation.into();
            }
        };
        if verbose {
            println!("Target URL: {target}");
            println!(
                "Using paired reader: {} ({})",
                pair.peer_display_name,
                pair.pair_id_hex()
            );
            println!("Initiating TLS client certificate authentication");
        }
        #[cfg(feature = "tls-rustls")]
        {
            match refineid_lib_tls::client_auth::get_with_rapp_client_auth(&uri, pair.pair_id) {
                Ok(response) => {
                    let status_line = response.lines().next().unwrap_or_default();
                    let Some(code) = http_status_code(status_line) else {
                        eprintln!("auth: the response carries no HTTP status line");
                        return ExitStatus::RuntimeFailure.into();
                    };
                    println!("{status_line}");
                    let accepted = code < HTTP_FIRST_ERROR_STATUS;
                    if verbose {
                        for line in response.lines() {
                            if line.contains("<title>")
                                || line.contains("<h1>")
                                || line.contains("Publish as")
                            {
                                println!("{}", line.trim());
                            }
                        }
                    }
                    if accepted {
                        ExitStatus::Ok.into()
                    } else {
                        ExitStatus::VerifyFailed.into()
                    }
                }
                Err(e) => {
                    eprintln!("auth: {e:?}");
                    ExitStatus::RuntimeFailure.into()
                }
            }
        }
        #[cfg(not(feature = "tls-rustls"))]
        {
            let _ = (uri, pair);
            eprintln!("auth: refineid built without the tls-rustls feature");
            ExitStatus::RuntimeFailure.into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HTTP_FIRST_ERROR_STATUS, http_status_code};
    use crate::test_util::{TestResult, check, check_true};

    const REDIRECT_STATUS_LINE: &str = "HTTP/1.1 302 Found";
    const DENIED_STATUS_LINE: &str = "HTTP/1.1 403 Forbidden";
    const NOT_A_STATUS_LINE: &str = "<html>";

    #[test]
    fn a_redirect_is_accepted_and_a_refusal_is_not() -> TestResult {
        let redirect = http_status_code(REDIRECT_STATUS_LINE).ok_or("redirect code")?;
        check_true(
            redirect < HTTP_FIRST_ERROR_STATUS,
            "a redirect after login is success",
        )?;
        let denied = http_status_code(DENIED_STATUS_LINE).ok_or("denied code")?;
        check_true(
            denied >= HTTP_FIRST_ERROR_STATUS,
            "a refusal is a negative answer",
        )?;
        check(
            &http_status_code(NOT_A_STATUS_LINE),
            &None,
            "no status line",
        )
    }
}
