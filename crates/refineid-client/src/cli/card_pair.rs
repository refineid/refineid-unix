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

/// What `refineid pair help`
/// prints. The man page refineid(1) carries the same facts.
pub const PAIR_HELP: &str = "\
usage: refineid pair

Pair with a phone running RefineID. Start pairing on the phone and
type the six-character code it shows. The code is read from the
prompt only, never from the command line.
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

Forget the paired phone.
";

/// What `refineid auth help`
/// prints. The man page refineid(1) carries the same facts.
pub const AUTH_HELP: &str = "\
usage: refineid auth [URL]

Log in to a TLS site with the card in the paired phone and print the
response's status line. URL defaults to https://card.refineid.fi.
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

    /// Pair with the phone that shows the code.
    #[must_use]
    pub fn run(self) -> ExitCode {
        println!("======================================================");
        println!("              RefineID Device Pairing                 ");
        println!("======================================================");
        println!();
        println!("  1. Open RefineID on your phone (iPhone / Android)");
        println!("  2. Start pairing; the phone shows a six-character code");
        println!("  3. Type that code here");
        println!();
        let Some(code) = prompt_code() else {
            eprintln!("Error: that is not a pairing code.");
            return ExitCode::FAILURE;
        };
        let Some(normalized) = normalize_pairing_code(&code) else {
            eprintln!("Error: that is not a pairing code.");
            return ExitCode::FAILURE;
        };

        let mut reader = match RemoteReader::open_local() {
            Ok(reader) => reader,
            Err(e) => {
                eprintln!("Error opening the paired-phone store: {e}");
                return ExitCode::FAILURE;
            }
        };
        println!(
            "Looking for the phone showing {} on the local network...",
            format_pairing_code(&normalized)
        );
        let pair = match reader.pair_with_code(&normalized, DISCOVERY_TIMEOUT) {
            Ok(pair) => pair,
            Err(RemoteError::Pairing(error)) => {
                eprintln!("Pairing failed: {error}.");
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("Pairing failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        println!(
            "Pairing established with {} ({})!",
            pair.peer_display_name, pair.peer_platform
        );

        println!("Retrieving authentication certificate for offline caching...");
        match reader.refresh_auth_cert(pair.pair_id, DISCOVERY_TIMEOUT) {
            Ok(_) => println!("Cached authentication certificate."),
            Err(e) => eprintln!("Warning: Failed to retrieve initial certificate: {e}"),
        }

        println!();
        println!("Successfully paired!");
        println!("Pair ID: {}", pair.pair_id_hex());
        println!(
            "Granted profiles: {}",
            profile_names(&pair.granted_profiles)
        );
        println!("Remote reader is now active for PKCS#11 (Firefox / suomi.fi) and CLI!");
        ExitCode::SUCCESS
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

/// Reads one line from standard input as the pairing code.
fn prompt_code() -> Option<String> {
    print!("Pairing code: ");
    std::io::stdout().flush().ok()?;
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
                eprintln!("Error reading the paired-phone store: {e}");
                return ExitCode::FAILURE;
            }
        };
        let Some(pair) = reader.phone() else {
            println!("No phone paired.");
            return ExitCode::SUCCESS;
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
        ExitCode::SUCCESS
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

    /// Forget the paired phone.
    #[must_use]
    pub fn run(self) -> ExitCode {
        let mut reader = match RemoteReader::open_local() {
            Ok(reader) => reader,
            Err(e) => {
                eprintln!("Error reading the paired-phone store: {e}");
                return ExitCode::FAILURE;
            }
        };
        let Some(phone) = reader.phone() else {
            eprintln!("No phone paired.");
            return ExitCode::FAILURE;
        };
        if let Err(e) = reader.forget() {
            eprintln!("Error forgetting {}: {e}", phone.peer_display_name);
            return ExitCode::FAILURE;
        }
        if reader.deliver_revocation_notices() > 0 {
            println!("Forgot {}; the phone was told.", phone.peer_display_name);
        } else {
            println!(
                "Forgot {}; the phone is told when this computer next reaches it.",
                phone.peer_display_name
            );
        }
        ExitCode::SUCCESS
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

    /// Run the `refineid auth` command.
    #[must_use]
    pub fn run(self) -> ExitCode {
        let target = self.url.as_deref().unwrap_or("https://card.refineid.fi");
        println!("======================================================");
        println!("         RefineID Remote Card Authentication          ");
        println!("======================================================");
        println!("Target URL: {target}");

        let reader = match RemoteReader::open_local() {
            Ok(reader) => reader,
            Err(e) => {
                eprintln!("Error opening the paired-phone store: {e}");
                return ExitCode::FAILURE;
            }
        };
        let Some(pair) = reader.phone() else {
            eprintln!("No phone paired. Run `refineid pair` first.");
            return ExitCode::FAILURE;
        };
        println!(
            "Using paired reader: {} ({})",
            pair.peer_display_name,
            pair.pair_id_hex()
        );

        let uri = match refineid_lib_core::text::Uri::parse(target.to_string()) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("Invalid URL {target}: {e:?}");
                return ExitCode::FAILURE;
            }
        };

        println!("Initiating TLS client certificate authentication...");
        #[cfg(feature = "tls-rustls")]
        {
            match refineid_lib_tls::client_auth::get_with_rapp_client_auth(&uri, pair.pair_id) {
                Ok(response) => {
                    println!("\nAuthentication successful!");
                    if let Some(status_line) = response.lines().next() {
                        println!("Status: {status_line}");
                    }
                    for line in response.lines() {
                        if line.contains("<title>")
                            || line.contains("<h1>")
                            || line.contains("Publish as")
                        {
                            let clean = line.trim();
                            println!("{clean}");
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Authentication failed: {e:?}");
                    ExitCode::FAILURE
                }
            }
        }
        #[cfg(not(feature = "tls-rustls"))]
        {
            eprintln!("refineid built without tls-rustls feature");
            ExitCode::FAILURE
        }
    }
}
