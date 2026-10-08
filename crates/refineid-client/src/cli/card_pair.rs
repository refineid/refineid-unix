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
use alloc::vec::Vec;
use std::io::{BufRead as _, Write as _};
use std::process::ExitCode;
use std::time::Duration;

use refineid_rapp_core::offer::{format_pairing_code, normalize_pairing_code};
use refineid_rapp_core::remote::{RemoteError, RemoteReader};

use super::ArgParseError;
use super::argv::RemainingArgv;
use super::verb::VerbTag;

/// How long pairing and operations browse for the phone.
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Arguments for `refineid pair`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairArgs {
    /// The code the phone shows; asked for on standard input when absent.
    pub code: Option<String>,
}

impl PairArgs {
    /// Parse arguments for `refineid pair [CODE]` or `refineid pair --code CODE`.
    ///
    /// # Errors
    /// Returns [`ArgParseError`] on a malformed code or unexpected arguments.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut code = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            let value = match arg.as_str() {
                "--code" | "-c" => iter.next().ok_or(ArgParseError::MissingValue {
                    cmd: VerbTag::CardPair,
                    flag: "--code",
                })?,
                other if !other.starts_with('-') && code.is_none() => arg,
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::CardPair,
                        got: other.to_owned(),
                    });
                }
            };
            if normalize_pairing_code(value).is_none() {
                return Err(ArgParseError::BadValue {
                    cmd: VerbTag::CardPair,
                    flag: "--code",
                    value: value.clone(),
                    reason: "must be the six characters your phone shows".into(),
                });
            }
            code = Some(value.clone());
        }
        Ok(Self { code })
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
        let code = match self.code {
            Some(code) => code,
            None => match prompt_code() {
                Some(code) => code,
                None => {
                    eprintln!("Error: that is not a pairing code.");
                    return ExitCode::FAILURE;
                }
            },
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
            Err(RemoteError::Pairing(refineid_rapp_core::engine::PairingError::CodeMismatch)) => {
                eprintln!("Pairing failed: the code does not match the one on the phone.");
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
        println!("Granted profiles: {}", pair.granted_profiles.join(", "));
        println!("Remote reader is now active for PKCS#11 (Firefox / suomi.fi) and CLI!");
        ExitCode::SUCCESS
    }
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
        let pairs = reader.pairs();
        if pairs.is_empty() {
            println!("No paired remote devices found.");
            println!("Run `refineid pair` to pair an iPhone or Android phone.");
            return ExitCode::SUCCESS;
        }

        println!("Paired Remote Card Readers ({}):", pairs.len());
        for (idx, pair) in pairs.iter().enumerate() {
            println!(
                "\n  [{}] {} ({}){}",
                idx + 1,
                pair.peer_display_name,
                pair.peer_platform,
                if pair.revoked { " -- revoked" } else { "" }
            );
            println!("      Pair ID:    {}", pair.pair_id_hex());
            println!("      Profiles:   {}", pair.granted_profiles.join(", "));
            println!(
                "      Cert cache: {}",
                if pair.auth_cert.is_some() {
                    "Cached"
                } else {
                    "None"
                }
            );
        }
        ExitCode::SUCCESS
    }
}

/// Arguments for `refineid unpair`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpairArgs {
    /// Hex pair ID or prefix to remove.
    pub pair_id: String,
}

impl UnpairArgs {
    /// Parse arguments for `refineid unpair`.
    ///
    /// # Errors
    /// Returns [`ArgParseError`] on missing required argument or unexpected flags.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let tokens = argv.into_vec();
        let mut iter = tokens.into_iter();
        let pair_id = iter.next().ok_or(ArgParseError::Required {
            cmd: VerbTag::CardUnpair,
            name: "PAIR_ID",
        })?;
        if let Some(extra) = iter.next() {
            return Err(ArgParseError::Unexpected {
                cmd: VerbTag::CardUnpair,
                got: extra,
            });
        }
        Ok(Self { pair_id })
    }

    /// Delete the pair record from disk.
    #[must_use]
    pub fn run(self) -> ExitCode {
        let mut reader = match RemoteReader::open_local() {
            Ok(reader) => reader,
            Err(e) => {
                eprintln!("Error reading the paired-phone store: {e}");
                return ExitCode::FAILURE;
            }
        };
        let matching: Vec<_> = reader
            .pairs()
            .into_iter()
            .filter(|pair| pair.pair_id_hex().starts_with(&self.pair_id))
            .collect();

        if matching.is_empty() {
            eprintln!("No paired device matches ID '{}'.", self.pair_id);
            return ExitCode::FAILURE;
        }
        if matching.len() > 1 {
            eprintln!("Ambiguous ID '{}' matches multiple pairs.", self.pair_id);
            return ExitCode::FAILURE;
        }

        let target = &matching[0];
        let id_hex = target.pair_id_hex();
        if let Err(e) = reader.remove(target.pair_id) {
            eprintln!("Error deleting pair {id_hex}: {e}");
            return ExitCode::FAILURE;
        }
        println!("Unpaired {id_hex}. Remove this computer on the phone as well.");
        ExitCode::SUCCESS
    }
}

/// Arguments for `refineid auth` / `refineid card auth`.
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

        let mut reader = match RemoteReader::open_local() {
            Ok(reader) => reader,
            Err(e) => {
                eprintln!("Error opening the paired-phone store: {e}");
                return ExitCode::FAILURE;
            }
        };
        let Some(pair) = reader.selected() else {
            eprintln!("No paired mobile card reader found. Run `refineid pair` first.");
            return ExitCode::FAILURE;
        };
        println!(
            "Using paired reader: {} ({})",
            pair.peer_display_name,
            pair.pair_id_hex()
        );

        let cert_der = match &pair.auth_cert {
            Some(cert) => cert.clone(),
            None => {
                println!("Retrieving authentication certificate from paired reader...");
                match reader.refresh_auth_cert(pair.pair_id, DISCOVERY_TIMEOUT) {
                    Ok(der) => der,
                    Err(e) => {
                        eprintln!("Failed to retrieve authentication certificate: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        };

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
            match refineid_lib_tls::client_auth::get_with_rapp_client_auth(
                &uri,
                pair.pair_id,
                &cert_der,
            ) {
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
