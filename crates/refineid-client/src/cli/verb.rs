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

//! Top-level subcommand dispatch.
//!
//! [`Verb`] is the typed enumeration of every operation
//! the `refineid` binary supports. Each variant *carries its
//! already-parsed typed `Args`*; [`parse_argv`] does verb
//! dispatch + Args parsing in a single trust-boundary call. The
//! consuming dispatch then matches a fully-typed value -- no
//! `RemainingArgv` survives into `main`.
//!
//! [`VerbTag`] is the data-less, operator-facing label form.
//! It's what [`super::ArgParseError`] carries for attribution
//! (a parse failure has no Args yet, so the data-carrying
//! [`Verb`] shape doesn't apply). [`VerbTag`] is finer-grained
//! than [`Verb`] for pair-shaped subcommands: where
//! `change-pin1` and `change-pin2` collapse into a single
//! `Verb::CardChangePin(ChangePinArgs)` (the slot lives inside
//! the Args), [`VerbTag`] keeps `CardChangePin1` and
//! `CardChangePin2` distinct so error wording can name the
//! exact subcommand that fired.
//!
//! Adding a new subcommand: add a [`VerbTag`] variant with its
//! `label`, `summary`, `help` and `parse_args` arms and its place
//! in [`VerbTag::ALL`]; add a [`Verb`] variant carrying the typed
//! Args (or extend an existing pair-shape Args with a new slot
//! enum value); add its words to [`route`]; describe it in
//! `man/refineid.1`. Match-exhaustiveness catches most omissions;
//! the man-page test catches the rest.

/// Data-less subcommand identifier. Used in
/// [`super::ArgParseError`] so an argv shape failure can name
/// which subcommand it refers to without needing a (yet
/// unconstructed) typed Args value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerbTag {
    /// `card` -- per-card readout (the default).
    CardCheck,
    /// `card emrtd` -- eMRTD data-group read via PACE.
    CardEmrtd,
    /// `card sign-auth` -- PIN1-gated RSA signature on the
    /// auth key.
    CardSignAuth,
    /// `card sign-qualified` -- PIN2-gated RSA signature on
    /// the non-repudiation key.
    CardSignQualified,
    /// `document sign` -- a signature in a format a
    /// counterparty can open: `PAdES`, `CAdES`, `ASiC-E` or `BDOC`.
    DocumentSign,
    /// `card decrypt-auth` -- PIN1-gated RSA decrypt on the
    /// auth key.
    CardDecryptAuth,
    /// `card pubkey` -- read pub key from a slot's cert and
    /// emit as OpenSSH wire or PEM SPKI.
    CardPubkey,
    /// `card export-all` -- bulk export of every readable
    /// slot's cert + pub key.
    CardExportAll,
    /// `card activate` -- one-time DVV activation flow.
    CardActivate,
    /// `card change-pin1` -- rotate PIN1.
    CardChangePin1,
    /// `card change-pin2` -- rotate PIN2.
    CardChangePin2,
    /// `card unblock-pin1` -- PUK-driven unblock of PIN1.
    CardUnblockPin1,
    /// `card unblock-pin2` -- PUK-driven unblock of PIN2.
    CardUnblockPin2,
    /// `reader keyboard` -- ACS reader host-interface
    /// (keyboard wedge) status / control.
    ReaderKeyboard,
    /// `verify` -- offline RSA-PKCS#1 v1.5 signature verify.
    Verify,
    /// `cert show` -- pretty-print a DER/PEM cert.
    CertShow,
    /// `cert chain` -- walk a cert's chain to a self-signed
    /// root.
    CertChain,
    /// `pair` -- pair with a mobile device (iPhone/Android).
    CardPair,
    /// `pairs` -- list paired mobile devices.
    CardPairs,
    /// `unpair` -- forget the paired phone.
    CardUnpair,
    /// `auth` -- authenticate to a TLS site via paired mobile device.
    CardAuth,
}

impl VerbTag {
    /// Operator-facing label, e.g. `"card change-pin1"`. Single
    /// source of truth for subcommand strings -- consumed by
    /// [`super::ArgParseError`]'s `Display` impl.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CardCheck => "card",
            Self::CardEmrtd => "card emrtd",
            Self::CardSignAuth => "card sign-auth",
            Self::CardSignQualified => "card sign-qualified",
            Self::DocumentSign => "document sign",
            Self::CardDecryptAuth => "card decrypt-auth",
            Self::CardPubkey => "card pubkey",
            Self::CardExportAll => "card export-all",
            Self::CardActivate => "card activate",
            Self::CardChangePin1 => "card change-pin1",
            Self::CardChangePin2 => "card change-pin2",
            Self::CardUnblockPin1 => "card unblock-pin1",
            Self::CardUnblockPin2 => "card unblock-pin2",
            Self::ReaderKeyboard => "reader keyboard",
            Self::Verify => "verify",
            Self::CertShow => "cert show",
            Self::CertChain => "cert chain",
            Self::CardPair => "pair",
            Self::CardPairs => "pairs",
            Self::CardUnpair => "unpair",
            Self::CardAuth => "auth",
        }
    }

    /// Every subcommand, in the order the short synopsis lists them.
    /// Groups are the [`Self::label`]'s first word; a blank line in
    /// the synopsis separates them.
    pub const ALL: &'static [Self] = &[
        Self::CardCheck,
        Self::CardEmrtd,
        Self::CardActivate,
        Self::CardChangePin1,
        Self::CardChangePin2,
        Self::CardUnblockPin1,
        Self::CardUnblockPin2,
        Self::CardSignAuth,
        Self::CardSignQualified,
        Self::CardDecryptAuth,
        Self::CardPubkey,
        Self::CardExportAll,
        Self::DocumentSign,
        Self::CardPair,
        Self::CardPairs,
        Self::CardUnpair,
        Self::CardAuth,
        Self::Verify,
        Self::CertShow,
        Self::CertChain,
        Self::ReaderKeyboard,
    ];

    /// A few words on what the subcommand does: its line in the short
    /// synopsis. The detail is in [`Self::help`] and refineid(1).
    #[must_use]
    pub const fn summary(self) -> &'static str {
        match self {
            Self::CardCheck => "read the card: certificates, revocation, PINs",
            Self::CardEmrtd => "read the travel-document data with the CAN",
            Self::CardActivate => "activate a new card",
            Self::CardChangePin1 => "change PIN1",
            Self::CardChangePin2 => "change PIN2",
            Self::CardUnblockPin1 => "unblock PIN1 with the PUK",
            Self::CardUnblockPin2 => "unblock PIN2 with the PUK",
            Self::CardSignAuth => "sign a file with the authentication key",
            Self::CardSignQualified => "sign a file with the qualified-signature key",
            Self::CardDecryptAuth => "decrypt a file with the authentication key",
            Self::CardPubkey => "print a public key as SSH or PEM",
            Self::CardExportAll => "write every public artefact to a directory",
            Self::DocumentSign => "sign files as PAdES, CAdES or ASiC-E",
            Self::CardPair => "pair with a phone",
            Self::CardPairs => "show the paired phone",
            Self::CardUnpair => "forget the paired phone",
            Self::CardAuth => "log in to a TLS site through the phone",
            Self::Verify => "verify a raw signature offline",
            Self::CertShow => "print a certificate",
            Self::CertChain => "walk a certificate chain to its root",
            Self::ReaderKeyboard => "show or set an ACS reader's keyboard mode",
        }
    }

    /// The detailed help `refineid <label> help` prints. Each text
    /// lives beside its verb's parser; refineid(1) carries the same
    /// facts.
    #[must_use]
    pub const fn help(self) -> &'static str {
        match self {
            Self::CardCheck => super::card::HELP,
            Self::CardEmrtd => super::card_emrtd::HELP,
            Self::CardActivate => super::card_activate::HELP,
            Self::CardChangePin1 | Self::CardChangePin2 => super::card_change_pin::HELP,
            Self::CardUnblockPin1 | Self::CardUnblockPin2 => super::card_unblock_pin::HELP,
            Self::CardSignAuth | Self::CardSignQualified => super::card_sign::HELP,
            Self::CardDecryptAuth => super::card_decrypt_auth::HELP,
            Self::CardPubkey => super::card_pubkey::HELP,
            Self::CardExportAll => super::card_export_all::HELP,
            Self::DocumentSign => super::document_sign::HELP,
            Self::CardPair => super::card_pair::PAIR_HELP,
            Self::CardPairs => super::card_pair::PAIRS_HELP,
            Self::CardUnpair => super::card_pair::UNPAIR_HELP,
            Self::CardAuth => super::card_pair::AUTH_HELP,
            Self::Verify => super::verify::HELP,
            Self::CertShow => super::cert_show::HELP,
            Self::CertChain => super::cert_chain::HELP,
            Self::ReaderKeyboard => super::reader_keyboard::HELP,
        }
    }

    /// The group the subcommand belongs to: the first word of its
    /// label (`card`, `document`, `cert`, ...).
    #[must_use]
    pub fn group(self) -> &'static str {
        self.label()
            .split_once(' ')
            .map_or(self.label(), |(group, _)| group)
    }

    /// Parse the argv that follows this subcommand's words into the
    /// typed [`Verb`].
    ///
    /// # Errors
    /// The subcommand's [`super::ArgParseError`] when its parser
    /// rejects the argv.
    pub fn parse_args(
        self,
        rest: super::argv::RemainingArgv,
    ) -> Result<Verb, super::ArgParseError> {
        use crate::card_pin::PinManageSlot;
        use crate::card_sign::SignSlot;
        Ok(match self {
            Self::CardCheck => Verb::CardCheck(super::card::CardArgs::parse(rest)?),
            Self::CardEmrtd => Verb::CardEmrtd(super::card_emrtd::EmrtdArgs::parse(rest)?),
            Self::CardSignAuth => {
                Verb::CardSign(super::card_sign::SignArgs::parse(SignSlot::Auth, rest)?)
            }
            Self::CardSignQualified => Verb::CardSign(super::card_sign::SignArgs::parse(
                SignSlot::Qualified,
                rest,
            )?),
            Self::DocumentSign => {
                Verb::DocumentSign(super::document_sign::DocumentSignArgs::parse(rest)?)
            }
            Self::CardDecryptAuth => {
                Verb::CardDecryptAuth(super::card_decrypt_auth::DecryptAuthArgs::parse(rest)?)
            }
            Self::CardPubkey => Verb::CardPubkey(super::card_pubkey::PubkeyArgs::parse(rest)?),
            Self::CardExportAll => {
                Verb::CardExportAll(super::card_export_all::ExportAllArgs::parse(rest)?)
            }
            Self::CardActivate => {
                Verb::CardActivate(super::card_activate::ActivateArgs::parse(rest)?)
            }
            Self::CardChangePin1 => Verb::CardChangePin(
                super::card_change_pin::ChangePinArgs::parse(PinManageSlot::Pin1, rest)?,
            ),
            Self::CardChangePin2 => Verb::CardChangePin(
                super::card_change_pin::ChangePinArgs::parse(PinManageSlot::Pin2, rest)?,
            ),
            Self::CardUnblockPin1 => Verb::CardUnblockPin(
                super::card_unblock_pin::UnblockPinArgs::parse(PinManageSlot::Pin1, rest)?,
            ),
            Self::CardUnblockPin2 => Verb::CardUnblockPin(
                super::card_unblock_pin::UnblockPinArgs::parse(PinManageSlot::Pin2, rest)?,
            ),
            Self::ReaderKeyboard => {
                Verb::ReaderKeyboard(super::reader_keyboard::ReaderKeyboardArgs::parse(rest)?)
            }
            Self::Verify => Verb::Verify(super::verify::VerifyArgs::parse(rest)?),
            Self::CertShow => Verb::CertShow(super::cert_show::CertShowArgs::parse(rest)?),
            Self::CertChain => Verb::CertChain(super::cert_chain::CertChainArgs::parse(rest)?),
            Self::CardPair => Verb::CardPair(super::card_pair::PairArgs::parse(rest)?),
            Self::CardPairs => Verb::CardPairs(super::card_pair::PairsArgs::parse(rest)?),
            Self::CardUnpair => Verb::CardUnpair(super::card_pair::UnpairArgs::parse(rest)?),
            Self::CardAuth => Verb::CardAuth(super::card_pair::AuthArgs::parse(rest)?),
        })
    }
}

/// Fully-parsed subcommand: variant identifies the operation,
/// payload is the typed Args struct that operation consumes.
///
/// Produced by [`parse_argv`] (the single trust boundary for
/// CLI input). The dispatch in [`Verb::run`] hands each typed
/// Args to its handler -- no argv-string handling, no untyped
/// slice survives.
///
/// Variant-pair subcommands (`sign-auth` vs `sign-qualified`,
/// `change-pin1` vs `change-pin2`, ...) collapse to a single
/// `Verb` variant; the slot identity is carried inside the
/// typed Args (`SignArgs::slot`, `ChangePinArgs::slot`, ...).
/// [`VerbTag`] *does* split them because it's the error-
/// attribution label and operator messages need to name the
/// exact subcommand that fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verb {
    /// `card` -- per-card readout (the default).
    CardCheck(super::card::CardArgs),
    /// `card emrtd` -- eMRTD data-group read via PACE.
    CardEmrtd(super::card_emrtd::EmrtdArgs),
    /// `card sign-auth` / `card sign-qualified` (slot pivot
    /// inside `SignArgs::slot`).
    CardSign(super::card_sign::SignArgs),
    /// `document sign` -- a signed document rather than
    /// signature bytes.
    DocumentSign(super::document_sign::DocumentSignArgs),
    /// `card decrypt-auth`.
    CardDecryptAuth(super::card_decrypt_auth::DecryptAuthArgs),
    /// `card pubkey`.
    CardPubkey(super::card_pubkey::PubkeyArgs),
    /// `card export-all`.
    CardExportAll(super::card_export_all::ExportAllArgs),
    /// `card activate`.
    CardActivate(super::card_activate::ActivateArgs),
    /// `card change-pin1` / `card change-pin2` (slot pivot
    /// inside `ChangePinArgs::slot`).
    CardChangePin(super::card_change_pin::ChangePinArgs),
    /// `card unblock-pin1` / `card unblock-pin2` (slot pivot
    /// inside `UnblockPinArgs::slot`).
    CardUnblockPin(super::card_unblock_pin::UnblockPinArgs),
    /// `reader keyboard` -- ACS reader host-interface control.
    ReaderKeyboard(super::reader_keyboard::ReaderKeyboardArgs),
    /// `verify` -- offline signature verify.
    Verify(super::verify::VerifyArgs),
    /// `cert show` -- pretty-print a cert file.
    CertShow(super::cert_show::CertShowArgs),
    /// `cert chain` -- chain walk.
    CertChain(super::cert_chain::CertChainArgs),
    /// `pair` -- pair with mobile device.
    CardPair(super::card_pair::PairArgs),
    /// `pairs` -- list paired mobile devices.
    CardPairs(super::card_pair::PairsArgs),
    /// `unpair` -- forget the paired phone.
    CardUnpair(super::card_pair::UnpairArgs),
    /// `auth` -- authenticate to a TLS site via paired mobile device.
    CardAuth(super::card_pair::AuthArgs),
}

impl Verb {
    /// The data-less tag identifying which subcommand this is.
    ///
    /// For variant-pair shapes (sign / change-pin / unblock-pin)
    /// the tag pivots off the slot field inside the Args.
    #[must_use]
    pub const fn tag(&self) -> VerbTag {
        use crate::card_pin::PinManageSlot;
        use crate::card_sign::SignSlot;
        match self {
            Self::CardCheck(_) => VerbTag::CardCheck,
            Self::CardEmrtd(_) => VerbTag::CardEmrtd,
            Self::CardSign(a) => match a.slot {
                SignSlot::Auth => VerbTag::CardSignAuth,
                SignSlot::Qualified => VerbTag::CardSignQualified,
            },
            Self::DocumentSign(_) => VerbTag::DocumentSign,
            Self::CardDecryptAuth(_) => VerbTag::CardDecryptAuth,
            Self::CardPubkey(_) => VerbTag::CardPubkey,
            Self::CardExportAll(_) => VerbTag::CardExportAll,
            Self::CardActivate(_) => VerbTag::CardActivate,
            Self::CardChangePin(a) => match a.slot {
                PinManageSlot::Pin1 => VerbTag::CardChangePin1,
                PinManageSlot::Pin2 => VerbTag::CardChangePin2,
            },
            Self::CardUnblockPin(a) => match a.slot {
                PinManageSlot::Pin1 => VerbTag::CardUnblockPin1,
                PinManageSlot::Pin2 => VerbTag::CardUnblockPin2,
            },
            Self::ReaderKeyboard(_) => VerbTag::ReaderKeyboard,
            Self::Verify(_) => VerbTag::Verify,
            Self::CertShow(_) => VerbTag::CertShow,
            Self::CertChain(_) => VerbTag::CertChain,
            Self::CardPair(_) => VerbTag::CardPair,
            Self::CardPairs(_) => VerbTag::CardPairs,
            Self::CardUnpair(_) => VerbTag::CardUnpair,
            Self::CardAuth(_) => VerbTag::CardAuth,
        }
    }

    /// Execute the parsed verb. An operation prints nothing on
    /// success unless `verbose`, so it takes the flag; a query prints
    /// its result either way and does not. The slot identity (where it
    /// matters) was written into the typed Args by the parser, so the
    /// dispatch carries no per-subcommand plumbing.
    #[must_use]
    pub fn run(self, verbose: bool) -> std::process::ExitCode {
        match self {
            Self::CardCheck(a) => a.run(verbose),
            Self::CardEmrtd(a) => a.run(),
            Self::CardSign(a) => a.run(verbose),
            Self::DocumentSign(a) => a.run(verbose),
            Self::CardDecryptAuth(a) => a.run(verbose),
            Self::CardPubkey(a) => a.run(),
            Self::CardExportAll(a) => a.run(verbose),
            Self::CardActivate(a) => a.run(verbose),
            Self::CardChangePin(a) => a.run(verbose),
            Self::CardUnblockPin(a) => a.run(verbose),
            Self::ReaderKeyboard(a) => a.run(verbose),
            Self::Verify(a) => a.run(),
            Self::CertShow(a) => a.run(),
            Self::CertChain(a) => a.run(),
            Self::CardPair(a) => a.run(verbose),
            Self::CardPairs(a) => a.run(),
            Self::CardUnpair(a) => a.run(verbose),
            Self::CardAuth(a) => a.run(verbose),
        }
    }
}

/// A parsed command line: the subcommand and the global options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// The subcommand with its typed arguments.
    pub verb: Verb,
    /// `-v` / `--verbose` given anywhere: show what each step did.
    pub verbose: bool,
}

impl Invocation {
    /// Execute the subcommand with the global options.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        self.verb.run(self.verbose)
    }
}

/// Top-level subcommand parse failure -- verb dispatch only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerbParseError {
    /// `args[1..]` didn't contain a subcommand at all (just the
    /// program name, or empty).
    Missing,
    /// `args[1..]` named something we don't recognise.
    Unrecognized {
        /// The literal argv token that wasn't recognised as a
        /// subcommand. Tier 0 `String` from `std::env::args()`.
        got: String,
    },
    /// `refineid cert <verb>` reached without a recognised
    /// `<verb>` (`show` / `chain`).
    UnknownCertVerb {
        /// The literal argv token after `cert` that wasn't
        /// recognised. Tier 0 `String` from `std::env::args()`.
        got: String,
    },
}

impl core::fmt::Display for VerbParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing => f.write_str("no subcommand supplied"),
            Self::Unrecognized { got } => write!(f, "unrecognised subcommand {got:?}"),
            Self::UnknownCertVerb { got } => {
                write!(f, "unknown `cert` verb {got:?}; try `show` or `chain`")
            }
        }
    }
}

impl core::error::Error for VerbParseError {}

/// Combined parse failure -- verb dispatch failure (no Args
/// even attempted) OR per-subcommand argv shape failure (verb
/// recognised, Args parse rejected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Top-level verb-dispatch failure (subcommand missing /
    /// unrecognised). No `Args` parse was attempted.
    Verb(VerbParseError),
    /// Verb recognised; the per-subcommand `Args` parse rejected
    /// the argv shape.
    Args(super::ArgParseError),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Verb(e) => write!(f, "{e}"),
            Self::Args(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for ParseError {}

impl From<VerbParseError> for ParseError {
    fn from(e: VerbParseError) -> Self {
        Self::Verb(e)
    }
}

impl From<super::ArgParseError> for ParseError {
    fn from(e: super::ArgParseError) -> Self {
        Self::Args(e)
    }
}

/// Parse a [`super::argv::ProcessArgv`] into a fully-typed
/// [`Verb`].
///
/// The single trust boundary for CLI input: `route` names the
/// subcommand, then [`VerbTag::parse_args`] parses its argv, so
/// downstream code sees only a parsed-and-typed value.
///
/// # Errors
/// [`ParseError::Verb`] on verb dispatch failure (no
/// subcommand / unrecognised / unknown cert verb);
/// [`ParseError::Args`] when the verb is recognised but the
/// subcommand's typed Args parser rejects the remaining argv.
pub fn parse_argv(argv: &super::argv::ProcessArgv) -> Result<Verb, ParseError> {
    let (tag, rest) = route(argv)?;
    Ok(tag.parse_args(rest)?)
}

/// Name the subcommand the argv's leading words select and return
/// the argv that follows them. Bare `card` and `card --flag ...`
/// route to [`VerbTag::CardCheck`] with every token after `card`.
///
/// # Errors
/// [`VerbParseError`] when no subcommand is given or the words name
/// none.
pub fn route(
    argv: &super::argv::ProcessArgv,
) -> Result<(VerbTag, super::argv::RemainingArgv), VerbParseError> {
    use super::argv::RemainingArgv;
    let (tag, rest) = match argv.after_program() {
        [c, v, rest @ ..] if c == "card" => match card_verb(v) {
            Some(tag) => (tag, rest),
            // Not a verb: the token is the first of bare `card`'s
            // own arguments.
            None => {
                let mut full = Vec::with_capacity(rest.len().saturating_add(1));
                full.push(v.clone());
                full.extend_from_slice(rest);
                return Ok((VerbTag::CardCheck, RemainingArgv::from_vec(full)));
            }
        },
        [c] if c == "card" => (VerbTag::CardCheck, &[][..]),
        [c, v, rest @ ..] if c == "cert" => match v.as_str() {
            "show" => (VerbTag::CertShow, rest),
            "chain" => (VerbTag::CertChain, rest),
            other => {
                return Err(VerbParseError::UnknownCertVerb {
                    got: other.to_owned(),
                });
            }
        },
        [c] if c == "cert" => {
            return Err(VerbParseError::UnknownCertVerb { got: String::new() });
        }
        [c, rest @ ..] if c == "verify" => (VerbTag::Verify, rest),
        [c, rest @ ..] if c == "pair" => (VerbTag::CardPair, rest),
        [c, rest @ ..] if c == "pairs" => (VerbTag::CardPairs, rest),
        [c, rest @ ..] if c == "unpair" => (VerbTag::CardUnpair, rest),
        [c, rest @ ..] if c == "auth" => (VerbTag::CardAuth, rest),
        [c, v, rest @ ..] if c == "reader" && v == "keyboard" => (VerbTag::ReaderKeyboard, rest),
        [c, v, ..] if c == "reader" => {
            return Err(VerbParseError::Unrecognized {
                got: format!("reader {v}"),
            });
        }
        [c] if c == "reader" => {
            return Err(VerbParseError::Unrecognized {
                got: "reader (missing sub-verb, try: reader keyboard)".to_owned(),
            });
        }
        [c, v, rest @ ..] if c == "document" && v == "sign" => (VerbTag::DocumentSign, rest),
        [c, v, ..] if c == "document" => {
            return Err(VerbParseError::Unrecognized {
                got: format!("document {v}"),
            });
        }
        [c] if c == "document" => {
            return Err(VerbParseError::Unrecognized {
                got: "document (missing sub-verb, try: document sign)".to_owned(),
            });
        }
        [other, ..] => return Err(VerbParseError::Unrecognized { got: other.clone() }),
        [] => return Err(VerbParseError::Missing),
    };
    Ok((tag, RemainingArgv::from_slice(rest)))
}

/// The `card <verb>` sub-verbs. `None` for a token that is not one.
fn card_verb(token: &str) -> Option<VerbTag> {
    Some(match token {
        "emrtd" => VerbTag::CardEmrtd,
        "sign-auth" => VerbTag::CardSignAuth,
        "sign-qualified" => VerbTag::CardSignQualified,
        "decrypt-auth" => VerbTag::CardDecryptAuth,
        "pubkey" => VerbTag::CardPubkey,
        "export-all" => VerbTag::CardExportAll,
        "activate" => VerbTag::CardActivate,
        "change-pin1" => VerbTag::CardChangePin1,
        "change-pin2" => VerbTag::CardChangePin2,
        "unblock-pin1" => VerbTag::CardUnblockPin1,
        "unblock-pin2" => VerbTag::CardUnblockPin2,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::process_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn bare_card_dispatches_to_check() -> TestResult {
        let sub = parse_argv(&argv(&["refineid", "card"]))?;
        check(&sub.tag(), &VerbTag::CardCheck, "tag")
    }

    #[test]
    fn card_with_flags_dispatches_to_check() -> TestResult {
        let sub = parse_argv(&argv(&["refineid", "card", "--offline", "--no-can"]))?;
        check(&sub.tag(), &VerbTag::CardCheck, "tag")
    }

    #[test]
    fn card_emrtd_wins_over_card_catch_all() -> TestResult {
        let sub = parse_argv(&argv(&["refineid", "card", "emrtd", "--can", "123456"]))?;
        check(&sub.tag(), &VerbTag::CardEmrtd, "tag")
    }

    #[test]
    fn each_card_verb_has_a_dispatch() -> TestResult {
        // Each verb with the minimum argv it needs to parse.
        for (verb, extra, expected) in [
            ("emrtd", vec!["--can", "123456"], VerbTag::CardEmrtd),
            (
                "sign-auth",
                vec!["--in", "/i", "--out", "/o"],
                VerbTag::CardSignAuth,
            ),
            (
                "sign-qualified",
                vec!["--in", "/i", "--out", "/o"],
                VerbTag::CardSignQualified,
            ),
            (
                "decrypt-auth",
                vec!["--in", "/i", "--out", "/o"],
                VerbTag::CardDecryptAuth,
            ),
            ("pubkey", vec![], VerbTag::CardPubkey),
            ("export-all", vec!["/out"], VerbTag::CardExportAll),
            ("activate", vec![], VerbTag::CardActivate),
            ("change-pin1", vec![], VerbTag::CardChangePin1),
            ("change-pin2", vec![], VerbTag::CardChangePin2),
            ("unblock-pin1", vec![], VerbTag::CardUnblockPin1),
            ("unblock-pin2", vec![], VerbTag::CardUnblockPin2),
        ] {
            let mut a = vec!["refineid", "card", verb];
            a.extend(extra.iter().copied());
            let sub = parse_argv(&argv(&a).clone())?;
            check(&sub.tag(), &expected, &format!("tag for verb {verb}"))?;
        }
        Ok(())
    }

    #[test]
    fn document_sign_subcommand() -> TestResult {
        let sub = parse_argv(&argv(&[
            "refineid",
            "document",
            "sign",
            "/documents/report.pdf",
        ]))?;
        check(&sub.tag(), &VerbTag::DocumentSign, "tag")?;
        for unknown in [
            vec!["refineid", "document"],
            vec!["refineid", "document", "bogus"],
        ] {
            check_true(
                matches!(
                    parse_argv(&argv(&unknown)),
                    Err(ParseError::Verb(VerbParseError::Unrecognized { .. }))
                ),
                "missing or unknown document verb",
            )?;
        }
        Ok(())
    }

    #[test]
    fn verify_subcommand() -> TestResult {
        let sub = parse_argv(&argv(&[
            "refineid", "verify", "--cert", "/c", "--in", "/i", "--sig", "/s",
        ]))?;
        check(&sub.tag(), &VerbTag::Verify, "tag")
    }

    #[test]
    fn cert_show_and_chain() -> TestResult {
        let sub = parse_argv(&argv(&["refineid", "cert", "show", "/c"]))?;
        check(&sub.tag(), &VerbTag::CertShow, "show tag")?;
        let sub = parse_argv(&argv(&["refineid", "cert", "chain", "/c"]))?;
        check(&sub.tag(), &VerbTag::CertChain, "chain tag")
    }

    #[test]
    fn unknown_cert_verb_rejected() -> TestResult {
        let r = parse_argv(&argv(&["refineid", "cert", "bogus"]));
        check_true(
            matches!(
                r,
                Err(ParseError::Verb(VerbParseError::UnknownCertVerb { .. }))
            ),
            "UnknownCertVerb",
        )
    }

    #[test]
    fn unknown_top_level_subcommand_rejected() -> TestResult {
        let r = parse_argv(&argv(&["refineid", "bogus"]));
        match r {
            Err(ParseError::Verb(VerbParseError::Unrecognized { got })) => {
                check(got.as_str(), "bogus", "got")
            }
            other => Err(format!("expected Unrecognized, got {other:?}").into()),
        }
    }

    #[test]
    fn no_subcommand_rejected() -> TestResult {
        let r = parse_argv(&argv(&["refineid"]));
        check_true(
            matches!(r, Err(ParseError::Verb(VerbParseError::Missing))),
            "Missing",
        )
    }

    #[test]
    fn malformed_args_surface_as_args_error() -> TestResult {
        let r = parse_argv(&argv(&["refineid", "card", "emrtd", "--can", "abc"]));
        check_true(matches!(r, Err(ParseError::Args(_))), "Args(_)")
    }

    #[test]
    fn pair_and_auth_subcommands() -> TestResult {
        let sub = parse_argv(&argv(&["refineid", "pair"]))?;
        check(&sub.tag(), &VerbTag::CardPair, "pair prompts for the code")?;
        if parse_argv(&argv(&["refineid", "pair", "7K X4 M9"])).is_ok() {
            return Err("the code is never taken from the command line".into());
        }
        if parse_argv(&argv(&["refineid", "pair", "--code", "7kx4m9"])).is_ok() {
            return Err("--code is not an option".into());
        }
        let sub = parse_argv(&argv(&["refineid", "pairs"]))?;
        check(&sub.tag(), &VerbTag::CardPairs, "pairs tag")?;
        let sub = parse_argv(&argv(&["refineid", "unpair"]))?;
        check(&sub.tag(), &VerbTag::CardUnpair, "unpair tag")?;
        let sub = parse_argv(&argv(&["refineid", "auth", "https://card.refineid.fi"]))?;
        check(&sub.tag(), &VerbTag::CardAuth, "auth tag")?;
        let sub = parse_argv(&argv(&["refineid", "auth"]))?;
        check(&sub.tag(), &VerbTag::CardAuth, "auth tag")?;
        check_true(
            parse_argv(&argv(&["refineid", "card", "auth"])).is_err(),
            "auth has no card spelling",
        )
    }
}
