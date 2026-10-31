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
//! `sign-auth` and `sign-qualified` collapse into a single
//! `Verb::CardSign(SignArgs)` (the slot lives inside the Args),
//! [`VerbTag`] keeps `CardSignAuth` and `CardSignQualified`
//! distinct so error wording can name the exact subcommand that
//! fired. The `pin` commands take the PIN as an argument, so one
//! tag covers both PINs.
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
    /// `document verify` -- the signatures of a signed document and
    /// their verdict.
    DocumentVerify,
    /// `card decrypt-auth` -- PIN1-gated RSA decrypt on the
    /// auth key.
    CardDecryptAuth,
    /// `card pubkey` -- read pub key from a slot's cert and
    /// emit as OpenSSH wire or PEM SPKI.
    CardPubkey,
    /// `card export-all` -- bulk export of every readable
    /// slot's cert + pub key.
    CardExportAll,
    /// `pin activate [1|2]` -- one-time DVV activation flow.
    PinActivate,
    /// `pin change 1|2` -- rotate a PIN.
    PinChange,
    /// `pin unblock 1|2` -- PUK-driven unblock of a PIN.
    PinUnblock,
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
    /// `phone` -- show the paired phone.
    PhoneCheck,
    /// `phone pair` -- pair with a phone.
    PhonePair,
    /// `phone unpair` -- forget the paired phone.
    PhoneUnpair,
    /// `phone auth` -- log in to a TLS site through the paired phone.
    PhoneAuth,
}

impl VerbTag {
    /// Operator-facing label, e.g. `"pin change"`. Single
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
            Self::DocumentVerify => "document verify",
            Self::CardDecryptAuth => "card decrypt-auth",
            Self::CardPubkey => "card pubkey",
            Self::CardExportAll => "card export-all",
            Self::PinActivate => "pin activate",
            Self::PinChange => "pin change",
            Self::PinUnblock => "pin unblock",
            Self::ReaderKeyboard => "reader keyboard",
            Self::Verify => "verify",
            Self::CertShow => "cert show",
            Self::CertChain => "cert chain",
            Self::PhoneCheck => "phone",
            Self::PhonePair => "phone pair",
            Self::PhoneUnpair => "phone unpair",
            Self::PhoneAuth => "phone auth",
        }
    }

    /// Every subcommand, in the order the short synopsis lists them.
    /// Groups are the [`Self::label`]'s first word; a blank line in
    /// the synopsis separates them.
    pub const ALL: &'static [Self] = &[
        Self::CardCheck,
        Self::CardEmrtd,
        Self::CardSignAuth,
        Self::CardSignQualified,
        Self::CardDecryptAuth,
        Self::CardPubkey,
        Self::CardExportAll,
        Self::PinActivate,
        Self::PinChange,
        Self::PinUnblock,
        Self::DocumentSign,
        Self::DocumentVerify,
        Self::PhoneCheck,
        Self::PhonePair,
        Self::PhoneUnpair,
        Self::PhoneAuth,
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
            Self::PinActivate => "activate a new card's PINs",
            Self::PinChange => "change PIN 1 or PIN 2",
            Self::PinUnblock => "unblock PIN 1 or PIN 2 with the PUK",
            Self::CardSignAuth => "sign a file with the authentication key",
            Self::CardSignQualified => "sign a file with the qualified-signature key",
            Self::CardDecryptAuth => "decrypt a file with the authentication key",
            Self::CardPubkey => "print a public key as SSH or PEM",
            Self::CardExportAll => "write every public artefact to a directory",
            Self::DocumentSign => "sign files as PAdES, CAdES or ASiC-E",
            Self::DocumentVerify => "verify a signed document's signatures",
            Self::PhonePair => "pair with a phone",
            Self::PhoneCheck => "show the paired phone",
            Self::PhoneUnpair => "forget the paired phone",
            Self::PhoneAuth => "log in to a TLS site through the phone",
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
            Self::PinActivate => super::pin_activate::HELP,
            Self::PinChange => super::pin_change::HELP,
            Self::PinUnblock => super::pin_unblock::HELP,
            Self::CardSignAuth | Self::CardSignQualified => super::card_sign::HELP,
            Self::CardDecryptAuth => super::card_decrypt_auth::HELP,
            Self::CardPubkey => super::card_pubkey::HELP,
            Self::CardExportAll => super::card_export_all::HELP,
            Self::DocumentSign => super::document_sign::HELP,
            Self::DocumentVerify => super::document_verify::HELP,
            Self::PhonePair => super::card_pair::PAIR_HELP,
            Self::PhoneCheck => super::card_pair::PAIRS_HELP,
            Self::PhoneUnpair => super::card_pair::UNPAIR_HELP,
            Self::PhoneAuth => super::card_pair::AUTH_HELP,
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

    /// Every group word once, in listing order: the first words of
    /// the labels.
    pub fn groups() -> impl Iterator<Item = &'static str> {
        let mut seen: Vec<&'static str> = Vec::new();
        Self::ALL.iter().filter_map(move |tag| {
            let group = tag.group();
            if seen.contains(&group) {
                None
            } else {
                seen.push(group);
                Some(group)
            }
        })
    }

    /// The verbs of `group` with their subcommands, in listing order:
    /// the second word of every two-word label in the group.
    pub fn verbs_of(group: &str) -> impl Iterator<Item = (&'static str, Self)> + '_ {
        Self::ALL.iter().filter_map(move |tag| {
            let (own, verb) = tag.label().split_once(' ')?;
            (own == group).then_some((verb, *tag))
        })
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
            Self::DocumentVerify => {
                Verb::DocumentVerify(super::document_verify::DocumentVerifyArgs::parse(rest)?)
            }
            Self::CardDecryptAuth => {
                Verb::CardDecryptAuth(super::card_decrypt_auth::DecryptAuthArgs::parse(rest)?)
            }
            Self::CardPubkey => Verb::CardPubkey(super::card_pubkey::PubkeyArgs::parse(rest)?),
            Self::CardExportAll => {
                Verb::CardExportAll(super::card_export_all::ExportAllArgs::parse(rest)?)
            }
            Self::PinActivate => Verb::PinActivate(super::pin_activate::ActivateArgs::parse(rest)?),
            Self::PinChange => Verb::PinChange(super::pin_change::ChangePinArgs::parse(rest)?),
            Self::PinUnblock => Verb::PinUnblock(super::pin_unblock::UnblockPinArgs::parse(rest)?),
            Self::ReaderKeyboard => {
                Verb::ReaderKeyboard(super::reader_keyboard::ReaderKeyboardArgs::parse(rest)?)
            }
            Self::Verify => Verb::Verify(super::verify::VerifyArgs::parse(rest)?),
            Self::CertShow => Verb::CertShow(super::cert_show::CertShowArgs::parse(rest)?),
            Self::CertChain => Verb::CertChain(super::cert_chain::CertChainArgs::parse(rest)?),
            Self::PhonePair => Verb::PhonePair(super::card_pair::PairArgs::parse(rest)?),
            Self::PhoneCheck => Verb::PhoneCheck(super::card_pair::PairsArgs::parse(rest)?),
            Self::PhoneUnpair => Verb::PhoneUnpair(super::card_pair::UnpairArgs::parse(rest)?),
            Self::PhoneAuth => Verb::PhoneAuth(super::card_pair::AuthArgs::parse(rest)?),
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
/// Variant-pair subcommands (`sign-auth` vs `sign-qualified`)
/// collapse to a single `Verb` variant; the slot identity is
/// carried inside the typed Args (`SignArgs::slot`).
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
    /// `document verify` -- the signatures of a signed document.
    DocumentVerify(super::document_verify::DocumentVerifyArgs),
    /// `card decrypt-auth`.
    CardDecryptAuth(super::card_decrypt_auth::DecryptAuthArgs),
    /// `card pubkey`.
    CardPubkey(super::card_pubkey::PubkeyArgs),
    /// `card export-all`.
    CardExportAll(super::card_export_all::ExportAllArgs),
    /// `pin activate [1|2]`.
    PinActivate(super::pin_activate::ActivateArgs),
    /// `pin change 1|2` (slot inside `ChangePinArgs::slot`).
    PinChange(super::pin_change::ChangePinArgs),
    /// `pin unblock 1|2` (slot inside `UnblockPinArgs::slot`).
    PinUnblock(super::pin_unblock::UnblockPinArgs),
    /// `reader keyboard` -- ACS reader host-interface control.
    ReaderKeyboard(super::reader_keyboard::ReaderKeyboardArgs),
    /// `verify` -- offline signature verify.
    Verify(super::verify::VerifyArgs),
    /// `cert show` -- pretty-print a cert file.
    CertShow(super::cert_show::CertShowArgs),
    /// `cert chain` -- chain walk.
    CertChain(super::cert_chain::CertChainArgs),
    /// `phone` -- show the paired phone.
    PhoneCheck(super::card_pair::PairsArgs),
    /// `phone pair` -- pair with a phone.
    PhonePair(super::card_pair::PairArgs),
    /// `phone unpair` -- forget the paired phone.
    PhoneUnpair(super::card_pair::UnpairArgs),
    /// `phone auth` -- log in to a TLS site through the paired phone.
    PhoneAuth(super::card_pair::AuthArgs),
}

impl Verb {
    /// The data-less tag identifying which subcommand this is.
    ///
    /// For the sign pair the tag pivots off the slot field inside
    /// the Args.
    #[must_use]
    pub const fn tag(&self) -> VerbTag {
        use crate::card_sign::SignSlot;
        match self {
            Self::CardCheck(_) => VerbTag::CardCheck,
            Self::CardEmrtd(_) => VerbTag::CardEmrtd,
            Self::CardSign(a) => match a.slot {
                SignSlot::Auth => VerbTag::CardSignAuth,
                SignSlot::Qualified => VerbTag::CardSignQualified,
            },
            Self::DocumentSign(_) => VerbTag::DocumentSign,
            Self::DocumentVerify(_) => VerbTag::DocumentVerify,
            Self::CardDecryptAuth(_) => VerbTag::CardDecryptAuth,
            Self::CardPubkey(_) => VerbTag::CardPubkey,
            Self::CardExportAll(_) => VerbTag::CardExportAll,
            Self::PinActivate(_) => VerbTag::PinActivate,
            Self::PinChange(_) => VerbTag::PinChange,
            Self::PinUnblock(_) => VerbTag::PinUnblock,
            Self::ReaderKeyboard(_) => VerbTag::ReaderKeyboard,
            Self::Verify(_) => VerbTag::Verify,
            Self::CertShow(_) => VerbTag::CertShow,
            Self::CertChain(_) => VerbTag::CertChain,
            Self::PhonePair(_) => VerbTag::PhonePair,
            Self::PhoneCheck(_) => VerbTag::PhoneCheck,
            Self::PhoneUnpair(_) => VerbTag::PhoneUnpair,
            Self::PhoneAuth(_) => VerbTag::PhoneAuth,
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
            Self::DocumentVerify(a) => a.run(verbose),
            Self::CardDecryptAuth(a) => a.run(verbose),
            Self::CardPubkey(a) => a.run(),
            Self::CardExportAll(a) => a.run(verbose),
            Self::PinActivate(a) => a.run(verbose),
            Self::PinChange(a) => a.run(verbose),
            Self::PinUnblock(a) => a.run(verbose),
            Self::ReaderKeyboard(a) => a.run(verbose),
            Self::Verify(a) => a.run(),
            Self::CertShow(a) => a.run(),
            Self::CertChain(a) => a.run(),
            Self::PhonePair(a) => a.run(verbose),
            Self::PhoneCheck(a) => a.run(),
            Self::PhoneUnpair(a) => a.run(verbose),
            Self::PhoneAuth(a) => a.run(verbose),
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
    /// A shortened command word that starts several commands.
    Ambiguous {
        /// The words as typed, the group word first when the second
        /// is the ambiguous one. Tier 0 `String` from
        /// `std::env::args()`.
        got: String,
        /// The commands it could mean, in listing order.
        candidates: Vec<String>,
    },
}

impl core::fmt::Display for VerbParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing => f.write_str("no subcommand supplied"),
            Self::Unrecognized { got } => write!(f, "unrecognised subcommand {got:?}"),
            Self::Ambiguous { got, candidates } => {
                write!(f, "ambiguous command {got:?}: {}", candidates.join(", "))
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
/// subcommand / unrecognised / ambiguous);
/// [`ParseError::Args`] when the verb is recognised but the
/// subcommand's typed Args parser rejects the remaining argv.
pub fn parse_argv(argv: &super::argv::ProcessArgv) -> Result<Verb, ParseError> {
    let (tag, rest) = route(argv)?;
    Ok(tag.parse_args(rest)?)
}

/// Resolve the leading argv words to a subcommand and hand back the
/// rest. A command word may be shortened to any prefix that names one
/// command; a prefix that fits several is refused with the
/// candidates. The first word names a group (`card`, `pin`, `phone`,
/// ...) or a one-word command (`verify`); the second names the verb
/// in a group that has them. A group whose bare word is itself a
/// command (`card`, `phone`) takes a second word that names no verb
/// as the first of its own arguments.
///
/// # Errors
/// [`VerbParseError::Missing`] with no words, `Unrecognized` for a
/// word that starts nothing or a group given no verb, `Ambiguous` for
/// a word that starts several.
pub fn route(
    argv: &super::argv::ProcessArgv,
) -> Result<(VerbTag, super::argv::RemainingArgv), VerbParseError> {
    use super::argv::RemainingArgv;
    use super::word::{Match, resolve};
    let [first, rest @ ..] = argv.after_program() else {
        return Err(VerbParseError::Missing);
    };
    let group = match resolve(first, VerbTag::groups()) {
        Match::One(group) => group,
        Match::None => {
            return Err(VerbParseError::Unrecognized { got: first.clone() });
        }
        Match::Several(candidates) => {
            return Err(VerbParseError::Ambiguous {
                got: first.clone(),
                candidates: candidates.into_iter().map(str::to_owned).collect(),
            });
        }
    };
    let bare = VerbTag::ALL
        .iter()
        .copied()
        .find(|tag| tag.label() == group);
    let verbs: Vec<(&str, VerbTag)> = VerbTag::verbs_of(group).collect();
    let Some((&(first_verb, _), _)) = verbs.split_first() else {
        // A one-word command: `verify`.
        return bare
            .map(|tag| (tag, RemainingArgv::from_slice(rest)))
            .ok_or_else(|| VerbParseError::Unrecognized { got: first.clone() });
    };
    let (tag, rest) = match rest {
        [second, more @ ..] if !second.starts_with(OPTION_START) => {
            match resolve(second, verbs.iter().map(|(word, _)| *word)) {
                Match::One(word) => match verbs.iter().find(|(verb, _)| *verb == word) {
                    Some((_, tag)) => (*tag, more),
                    None => {
                        return Err(VerbParseError::Unrecognized {
                            got: format!("{first} {second}"),
                        });
                    }
                },
                Match::None => match bare {
                    Some(tag) => (tag, rest),
                    None => {
                        return Err(VerbParseError::Unrecognized {
                            got: format!("{first} {second}"),
                        });
                    }
                },
                Match::Several(words) => {
                    return Err(VerbParseError::Ambiguous {
                        got: format!("{first} {second}"),
                        candidates: words.iter().map(|word| format!("{group} {word}")).collect(),
                    });
                }
            }
        }
        _ => match bare {
            Some(tag) => (tag, rest),
            None => {
                return Err(VerbParseError::Unrecognized {
                    got: format!("{first} (missing sub-verb, try: {group} {first_verb})"),
                });
            }
        },
    };
    Ok((tag, RemainingArgv::from_slice(rest)))
}

/// The first character of an option, which a verb never starts with.
const OPTION_START: char = '-';

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
        ] {
            let mut a = vec!["refineid", "card", verb];
            a.extend(extra.iter().copied());
            let sub = parse_argv(&argv(&a).clone())?;
            check(&sub.tag(), &expected, &format!("tag for verb {verb}"))?;
        }
        Ok(())
    }

    #[test]
    fn pin_group_dispatches_noun_then_verb() -> TestResult {
        for (words, expected) in [
            (vec!["pin", "activate"], VerbTag::PinActivate),
            (vec!["pin", "activate", "2"], VerbTag::PinActivate),
            (vec!["pin", "change", "1"], VerbTag::PinChange),
            (vec!["pin", "unblock", "2"], VerbTag::PinUnblock),
        ] {
            let mut a = vec!["refineid"];
            a.extend(words.iter().copied());
            let sub = parse_argv(&argv(&a))?;
            check(&sub.tag(), &expected, &format!("tag for {words:?}"))?;
        }
        for unknown in [vec!["refineid", "pin"], vec!["refineid", "pin", "bogus"]] {
            check_true(
                matches!(
                    parse_argv(&argv(&unknown)),
                    Err(ParseError::Verb(VerbParseError::Unrecognized { .. }))
                ),
                "missing or unknown pin verb",
            )?;
        }
        for old in ["activate", "change-pin1", "unblock-pin2"] {
            check_true(
                !matches!(
                    route(&argv(&["refineid", "card", old])),
                    Ok((
                        VerbTag::PinActivate | VerbTag::PinChange | VerbTag::PinUnblock,
                        _
                    ))
                ),
                &format!("card {old} is not a pin command"),
            )?;
            check_true(
                parse_argv(&argv(&["refineid", "card", old])).is_err(),
                &format!("card {old} is refused"),
            )?;
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
        for unknown in [vec!["refineid", "cert"], vec!["refineid", "cert", "bogus"]] {
            check_true(
                matches!(
                    parse_argv(&argv(&unknown)),
                    Err(ParseError::Verb(VerbParseError::Unrecognized { .. }))
                ),
                "missing or unknown cert verb",
            )?;
        }
        Ok(())
    }

    #[test]
    fn a_unique_prefix_names_the_command() -> TestResult {
        for (words, expected) in [
            (
                vec!["doc", "s", "/documents/report.pdf"],
                VerbTag::DocumentSign,
            ),
            (
                vec!["doc", "v", "/documents/report-signed.pdf"],
                VerbTag::DocumentVerify,
            ),
            (vec!["ph", "pa"], VerbTag::PhonePair),
            (vec!["phone"], VerbTag::PhoneCheck),
            (vec!["pin", "c", "1"], VerbTag::PinChange),
            (vec!["pin", "u", "2"], VerbTag::PinUnblock),
            (
                vec!["v", "--cert", "/c", "--in", "/i", "--sig", "/s"],
                VerbTag::Verify,
            ),
            (vec!["r", "k"], VerbTag::ReaderKeyboard),
            (vec!["card", "em", "--can", "123456"], VerbTag::CardEmrtd),
            (
                vec!["card", "sign-a", "--in", "/i", "--out", "/o"],
                VerbTag::CardSignAuth,
            ),
            (vec!["ce", "sh", "/c"], VerbTag::CertShow),
        ] {
            let mut a = vec!["refineid"];
            a.extend(words.iter().copied());
            let (tag, _) = route(&argv(&a))?;
            check(&tag, &expected, &format!("tag for {words:?}"))?;
        }
        let (tag, rest) = route(&argv(&["refineid", "card", "--offline"]))?;
        check(
            &tag,
            &VerbTag::CardCheck,
            "an option after card is card's own",
        )?;
        check(
            &rest.into_vec(),
            &vec!["--offline".to_owned()],
            "card keeps its option",
        )?;
        let (tag, rest) = route(&argv(&["refineid", "card", "x"]))?;
        check(
            &tag,
            &VerbTag::CardCheck,
            "a non-verb after card is card's own",
        )?;
        check(
            &rest.into_vec(),
            &vec!["x".to_owned()],
            "card keeps the word",
        )?;
        let (tag, rest) = route(&argv(&["refineid", "card"]))?;
        check(&tag, &VerbTag::CardCheck, "bare card")?;
        check_true(rest.as_slice().is_empty(), "bare card has no arguments")?;
        // `phone` is shaped like `card`: an unknown second word is its
        // own argument, which its parser then refuses.
        let (tag, rest) = route(&argv(&["refineid", "phone", "foo"]))?;
        check(
            &tag,
            &VerbTag::PhoneCheck,
            "a non-verb after phone is phone's own",
        )?;
        check(
            &rest.into_vec(),
            &vec!["foo".to_owned()],
            "phone keeps the word",
        )?;
        check_true(
            matches!(
                parse_argv(&argv(&["refineid", "phone", "foo"])),
                Err(ParseError::Args(_))
            ),
            "phone refuses the word as an argument",
        )
    }

    #[test]
    fn an_ambiguous_prefix_names_the_candidates() -> TestResult {
        match route(&argv(&["refineid", "c"])) {
            Err(VerbParseError::Ambiguous { got, candidates }) => {
                check(got.as_str(), "c", "got")?;
                check(
                    &candidates,
                    &vec!["card".to_owned(), "cert".to_owned()],
                    "groups",
                )?;
            }
            other => return Err(format!("expected Ambiguous, got {other:?}").into()),
        }
        match route(&argv(&["refineid", "ca", "e"])) {
            Err(VerbParseError::Ambiguous { got, candidates }) => {
                check(got.as_str(), "ca e", "the words as typed")?;
                check(
                    &candidates,
                    &vec!["card emrtd".to_owned(), "card export-all".to_owned()],
                    "verbs",
                )?;
            }
            other => return Err(format!("expected Ambiguous, got {other:?}").into()),
        }
        match route(&argv(&["refineid", "doc", "bogus"])) {
            Err(VerbParseError::Unrecognized { got }) => {
                check(got.as_str(), "doc bogus", "the words as typed")?;
            }
            other => return Err(format!("expected Unrecognized, got {other:?}").into()),
        }
        match route(&argv(&["refineid", "card", "s", "--in", "/i"])) {
            Err(VerbParseError::Ambiguous { got, candidates }) => {
                check(got.as_str(), "card s", "got")?;
                check(
                    &candidates,
                    &vec![
                        "card sign-auth".to_owned(),
                        "card sign-qualified".to_owned(),
                    ],
                    "verbs",
                )?;
            }
            other => return Err(format!("expected Ambiguous, got {other:?}").into()),
        }
        check_true(
            matches!(
                route(&argv(&["refineid", "p", "change"])),
                Err(VerbParseError::Ambiguous { .. })
            ),
            "p is pin or phone",
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
    fn phone_subcommands() -> TestResult {
        let sub = parse_argv(&argv(&["refineid", "phone", "pair"]))?;
        check(&sub.tag(), &VerbTag::PhonePair, "pair prompts for the code")?;
        if parse_argv(&argv(&["refineid", "phone", "pair", "7K X4 M9"])).is_ok() {
            return Err("the code is never taken from the command line".into());
        }
        if parse_argv(&argv(&["refineid", "phone", "pair", "--code", "7kx4m9"])).is_ok() {
            return Err("--code is not an option".into());
        }
        let sub = parse_argv(&argv(&["refineid", "phone"]))?;
        check(
            &sub.tag(),
            &VerbTag::PhoneCheck,
            "bare phone is the readout",
        )?;
        let sub = parse_argv(&argv(&["refineid", "phone", "unpair"]))?;
        check(&sub.tag(), &VerbTag::PhoneUnpair, "unpair tag")?;
        let sub = parse_argv(&argv(&[
            "refineid",
            "phone",
            "auth",
            "https://card.refineid.fi",
        ]))?;
        check(&sub.tag(), &VerbTag::PhoneAuth, "auth tag")?;
        let sub = parse_argv(&argv(&["refineid", "phone", "auth"]))?;
        check(&sub.tag(), &VerbTag::PhoneAuth, "auth tag")?;
        for old in [
            &["refineid", "pair"][..],
            &["refineid", "pairs"],
            &["refineid", "unpair"],
            &["refineid", "auth"],
        ] {
            check_true(
                parse_argv(&argv(old)).is_err(),
                "the bare spellings are gone",
            )?;
        }
        check_true(
            parse_argv(&argv(&["refineid", "phone", "bogus"])).is_err(),
            "an unknown phone verb is an error",
        )
    }
}
