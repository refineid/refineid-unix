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

//! Help and version text.
//!
//! `refineid` shows the commands, one line each, and nothing more;
//! `refineid <command> help` shows that command's options; the man
//! page refineid(1) carries the detail. The version prints only when
//! asked, with `refineid -V` or `refineid --version`: no command
//! prints a banner or its version unasked. `-v` / `--verbose`,
//! anywhere on the command line, asks for each step's details.

use super::verb::VerbTag;

/// The words that ask for help: as the first argument they ask for
/// the synopsis, right after a command's words for that command's help.
const HELP_WORDS: &[&str] = &["help", "-h", "--help"];
/// The options that ask for a command's help, as its first argument.
const HELP_OPTIONS: &[&str] = &["-h", "--help"];
/// The options that ask for the version.
const VERSION_OPTIONS: &[&str] = &["-V", "--version"];
/// The global options that ask for each step's details, accepted
/// anywhere on the command line.
const VERBOSE_OPTIONS: &[&str] = &["-v", "--verbose"];
/// The program name the help and version text use.
const PROGRAM: &str = "refineid";
/// The synopsis's first line.
const SYNOPSIS_USAGE: &str = "usage: refineid [-vV] <command> [args]";
/// The synopsis line on the global verbose option.
const SYNOPSIS_VERBOSE: &str = "-v, --verbose  show what each step did";
/// The synopsis line on the version option.
const SYNOPSIS_VERSION: &str = "-V, --version  print the version";
/// The synopsis's last line.
const SYNOPSIS_POINTER: &str = "refineid <command> help shows its options; see refineid(1).";
/// The heading of a group's command list.
const GROUP_COMMANDS: &str = "commands:";
/// The indent of a command line.
const INDENT: &str = "  ";
/// The spaces between a command's name and its summary.
const SUMMARY_GAP: usize = 2;

/// The blocks of the synopsis; a blank line separates them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Block {
    /// The card: readout, PINs, keys.
    Card,
    /// Signed documents.
    Document,
    /// The paired phone.
    Phone,
    /// Offline signature and certificate tools.
    Offline,
    /// The card reader itself.
    Reader,
}

impl Block {
    /// The block a subcommand is listed in.
    const fn of(tag: VerbTag) -> Self {
        match tag {
            VerbTag::CardCheck
            | VerbTag::CardEmrtd
            | VerbTag::CardActivate
            | VerbTag::CardChangePin1
            | VerbTag::CardChangePin2
            | VerbTag::CardUnblockPin1
            | VerbTag::CardUnblockPin2
            | VerbTag::CardSignAuth
            | VerbTag::CardSignQualified
            | VerbTag::CardDecryptAuth
            | VerbTag::CardPubkey
            | VerbTag::CardExportAll => Self::Card,
            VerbTag::DocumentSign => Self::Document,
            VerbTag::CardPair | VerbTag::CardPairs | VerbTag::CardUnpair | VerbTag::CardAuth => {
                Self::Phone
            }
            VerbTag::Verify | VerbTag::CertShow | VerbTag::CertChain => Self::Offline,
            VerbTag::ReaderKeyboard => Self::Reader,
        }
    }
}

/// `true` for a word that asks for help.
#[must_use]
pub fn is_help_word(token: &str) -> bool {
    HELP_WORDS.contains(&token)
}

/// `true` for an option that asks for the version.
#[must_use]
pub fn is_version_option(token: &str) -> bool {
    VERSION_OPTIONS.contains(&token)
}

/// `true` for the global option that asks for each step's details.
#[must_use]
pub fn is_verbose_option(token: &str) -> bool {
    VERBOSE_OPTIONS.contains(&token)
}

/// `true` when the argv after a command's words asks for its help:
/// a help word or a help option as the first argument. Later
/// positions are the command's own, where `help` may be a file name
/// and an option's value may spell like a help option.
#[must_use]
pub fn asks_command_help(rest: &[String]) -> bool {
    rest.first()
        .is_some_and(|first| is_help_word(first) || HELP_OPTIONS.contains(&first.as_str()))
}

/// `refineid <version>`, the whole output of `refineid --version`.
#[must_use]
pub fn version() -> String {
    format!("{PROGRAM} {}", refineid_lib_core::VERSION)
}

/// The short synopsis: the usage line, one line per command, and the
/// pointer to the per-command help and the man page.
#[must_use]
pub fn synopsis() -> String {
    let mut out = format!("{SYNOPSIS_USAGE}\n");
    let mut block = None;
    for &tag in VerbTag::ALL {
        if block != Some(Block::of(tag)) {
            out.push('\n');
            block = Some(Block::of(tag));
        }
        push_command_line(&mut out, tag);
    }
    out.push('\n');
    out.push_str(SYNOPSIS_VERBOSE);
    out.push('\n');
    out.push_str(SYNOPSIS_VERSION);
    out.push('\n');
    out.push_str(SYNOPSIS_POINTER);
    out.push('\n');
    out
}

/// The help of a group named by its first word, as `refineid card
/// help` asks for it: one line per command in the group, after bare
/// `card`'s own help for the card group. `None` when `word` names no
/// group of several words.
#[must_use]
pub fn group(word: &str) -> Option<String> {
    let members: Vec<VerbTag> = VerbTag::ALL
        .iter()
        .copied()
        .filter(|tag| tag.label() != tag.group() && tag.group() == word)
        .collect();
    if members.is_empty() {
        return None;
    }
    let mut out = String::new();
    if word == VerbTag::CardCheck.label() {
        out.push_str(VerbTag::CardCheck.help());
        out.push('\n');
    }
    out.push_str(GROUP_COMMANDS);
    out.push('\n');
    for tag in members {
        push_command_line(&mut out, tag);
    }
    Some(out)
}

/// The help `refineid <command> help` prints. Bare `card` is also
/// the card group, so its help lists the group's commands.
#[must_use]
pub fn command(tag: VerbTag) -> String {
    group(tag.label()).unwrap_or_else(|| tag.help().to_owned())
}

/// The hint a parse error ends with.
#[must_use]
pub fn hint(tag: VerbTag) -> String {
    format!("try: {PROGRAM} {} help", tag.label())
}

/// Append one command's synopsis line, its summary aligned past the
/// longest name.
fn push_command_line(out: &mut String, tag: VerbTag) {
    let width = VerbTag::ALL
        .iter()
        .map(|t| t.label().len())
        .max()
        .unwrap_or_default()
        .saturating_add(SUMMARY_GAP);
    let line = format!("{INDENT}{:<width$}{}", tag.label(), tag.summary());
    out.push_str(line.trim_end());
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check, check_true};

    /// The man page the help texts must agree with.
    const MAN_PAGE: &str = include_str!("../../man/refineid.1");
    /// The most lines the synopsis may take: one terminal screen.
    const SCREEN_LINES: usize = 40;

    #[test]
    fn synopsis_fits_one_screen_and_names_every_command() -> TestResult {
        let text = synopsis();
        check_true(text.lines().count() <= SCREEN_LINES, "synopsis fits")?;
        check_true(!text.contains(refineid_lib_core::VERSION), "no version")?;
        for tag in VerbTag::ALL {
            check_true(
                text.lines().any(|line| {
                    line.trim_start()
                        .strip_prefix(tag.label())
                        .is_some_and(|after| after.starts_with(' '))
                }),
                tag.label(),
            )?;
        }
        Ok(())
    }

    #[test]
    fn version_is_program_and_version() -> TestResult {
        check(
            version().as_str(),
            format!("refineid {}", refineid_lib_core::VERSION).as_str(),
            "version",
        )?;
        check_true(is_version_option("-V"), "-V")?;
        check_true(is_version_option("--version"), "--version")?;
        check_true(!is_version_option("-v"), "-v is not the version option")?;
        check_true(!is_verbose_option("-V"), "-V is not the verbose option")
    }

    #[test]
    fn groups_list_their_commands_only() -> TestResult {
        let document = group("document").ok_or("document group")?;
        check_true(document.contains("document sign"), "document sign")?;
        check_true(!document.contains("cert show"), "no cert")?;
        let card = group("card").ok_or("card group")?;
        check_true(card.starts_with(VerbTag::CardCheck.help()), "card readout")?;
        check_true(card.contains("card activate"), "card activate")?;
        check(
            &command(VerbTag::CardCheck),
            &card,
            "card help is the group",
        )?;
        check_true(group("verify").is_none(), "verify is one command")?;
        check_true(group("bogus").is_none(), "no such group")
    }

    #[test]
    fn command_help_is_asked_first_or_by_option() -> TestResult {
        let words = |s: &[&str]| s.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        check_true(asks_command_help(&words(&["help"])), "help first")?;
        check_true(asks_command_help(&words(&["--help"])), "--help first")?;
        check_true(
            !asks_command_help(&words(&["--reader", "Synthetic Card Reader", "--help"])),
            "--help later is the command's own argument",
        )?;
        check_true(
            !asks_command_help(&words(&["--reason", "help"])),
            "help as a value",
        )?;
        check_true(
            !asks_command_help(&words(&["--reason", "--help", "report.pdf"])),
            "a help option as a value",
        )
    }

    /// The command headings of the man page's COMMANDS section: each
    /// `.It Cm ...` line and each line that opens an `.It Xo` item.
    fn man_command_headings() -> Vec<Vec<&'static str>> {
        let commands = MAN_PAGE
            .split_once(".Sh COMMANDS")
            .and_then(|(_, after)| after.split_once("\n.Sh "))
            .map_or("", |(section, _)| section);
        let mut headings = Vec::new();
        let mut after_xo = false;
        for line in commands.lines() {
            if after_xo || line.starts_with(".It Cm ") {
                headings.push(line.split_whitespace().collect());
            }
            after_xo = line == ".It Xo";
        }
        headings
    }

    /// The options a subcommand's help text shows.
    fn help_options(tag: VerbTag) -> Vec<&'static str> {
        tag.help()
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .filter(|word| word.starts_with("--") && word.len() > "--".len())
            .collect()
    }

    #[test]
    fn man_page_names_every_command_and_option() -> TestResult {
        let headings = man_command_headings();
        for &tag in VerbTag::ALL {
            let words: Vec<&str> = tag.label().split(' ').collect();
            check_true(
                headings
                    .iter()
                    .any(|heading| words.iter().all(|word| heading.contains(word))),
                &format!("refineid.1 has a heading for {}", tag.label()),
            )?;
            for option in help_options(tag) {
                // mdoc writes an option as `Fl` and its name without
                // the first hyphen.
                let flag = option.strip_prefix('-').map(|name| format!("Fl {name}"));
                check_true(
                    flag.is_some_and(|flag| MAN_PAGE.contains(&flag)),
                    &format!("refineid.1 names {option} of {}", tag.label()),
                )?;
            }
        }
        Ok(())
    }
}
