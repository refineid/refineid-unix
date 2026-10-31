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

//! The zsh completion, generated from the command table.
//!
//! `packaging/zsh/_refineid` is the output of [`zsh`], checked in so
//! that every package installs a plain file and nothing runs at
//! package time. A test fails when the file is stale;
//! `cargo test -p refineid-client regenerate_zsh_completion -- --ignored`
//! rewrites it. The arguments each command completes are the tables
//! in [`arguments`]; a test holds their option names to the ones the
//! command's help text shows.
//!
//! A completion function runs under the completion system's own
//! shell options and must not reset them: `emulate -L zsh` inside one
//! silently disables `_arguments` specs.

use core::fmt::Write as _;

use super::verb::VerbTag;

/// What an option or a positional argument takes.
#[derive(Debug, Clone, Copy)]
pub enum Value {
    /// Nothing: a flag.
    None,
    /// A file path.
    File,
    /// A directory path.
    Directory,
    /// One of a fixed set of words.
    Words(&'static [&'static str]),
    /// A URL.
    Url,
    /// Free text, named by a noun.
    Text(&'static str),
}

/// An option of a command, as the completion describes it.
#[derive(Debug, Clone, Copy)]
pub struct Opt {
    /// The option as typed, with its dashes.
    pub flag: &'static str,
    /// A few words shown beside it.
    pub summary: &'static str,
    /// What follows it.
    pub value: Value,
}

/// A positional argument of a command.
#[derive(Debug, Clone, Copy)]
pub struct Positional {
    /// The noun shown while it is typed.
    pub name: &'static str,
    /// What it is.
    pub value: Value,
    /// `true` when any number may follow.
    pub repeated: bool,
}

/// Everything a command completes after its words.
#[derive(Debug, Clone, Copy)]
pub struct Arguments {
    /// In order.
    pub positionals: &'static [Positional],
    /// In the order they are listed.
    pub options: &'static [Opt],
}

/// The option that narrows the reader, shared by the card commands.
const READER: Opt = Opt {
    flag: "--reader",
    summary: "narrow to readers whose name contains S",
    value: Value::Text("substring"),
};
/// The option that gives the CAN, shared by the card commands.
const CAN: Opt = Opt {
    flag: "--can",
    summary: "CAN from the card front",
    value: Value::Text("six digits"),
};
/// The PIN number a pin command takes.
const PIN_NUMBER: Positional = Positional {
    name: "PIN",
    value: Value::Words(&["1", "2"]),
    repeated: false,
};
/// A command that completes nothing after its words.
const NOTHING: Arguments = Arguments {
    positionals: &[],
    options: &[],
};

/// The arguments the completion offers after a subcommand's words.
#[must_use]
pub const fn arguments(tag: VerbTag) -> Arguments {
    match tag {
        VerbTag::CardCheck => Arguments {
            positionals: &[],
            options: &[
                Opt {
                    flag: "--offline",
                    summary: "skip every network fetch",
                    value: Value::None,
                },
                READER,
                CAN,
                Opt {
                    flag: "--no-can",
                    summary: "skip the eMRTD section",
                    value: Value::None,
                },
                Opt {
                    flag: "--crl-file",
                    summary: "use a pre-fetched CRL",
                    value: Value::File,
                },
                Opt {
                    flag: "--save-cert",
                    summary: "write each slot's DER to a directory",
                    value: Value::Directory,
                },
                Opt {
                    flag: "--remote",
                    summary: "read the card through the paired phone only",
                    value: Value::None,
                },
            ],
        },
        VerbTag::CardEmrtd => Arguments {
            positionals: &[],
            options: &[
                CAN,
                Opt {
                    flag: "--save-face",
                    summary: "face image",
                    value: Value::File,
                },
                Opt {
                    flag: "--save-signature",
                    summary: "displayed-signature image",
                    value: Value::File,
                },
                READER,
            ],
        },
        VerbTag::CardSignAuth | VerbTag::CardSignQualified => Arguments {
            positionals: &[],
            options: &[
                Opt {
                    flag: "--in",
                    summary: "input file",
                    value: Value::File,
                },
                Opt {
                    flag: "--out",
                    summary: "output file for the raw signature",
                    value: Value::File,
                },
                Opt {
                    flag: "--save-cert",
                    summary: "also write the signing certificate's DER",
                    value: Value::File,
                },
                READER,
                CAN,
            ],
        },
        VerbTag::CardDecryptAuth => Arguments {
            positionals: &[],
            options: &[
                Opt {
                    flag: "--in",
                    summary: "ciphertext",
                    value: Value::File,
                },
                Opt {
                    flag: "--out",
                    summary: "output file for the plaintext",
                    value: Value::File,
                },
                READER,
            ],
        },
        VerbTag::CardPubkey => Arguments {
            positionals: &[],
            options: &[
                Opt {
                    flag: "--slot",
                    summary: "which key",
                    value: Value::Words(&["auth", "qualified"]),
                },
                Opt {
                    flag: "--format",
                    summary: "key format",
                    value: Value::Words(&["ssh", "pem"]),
                },
                Opt {
                    flag: "--out",
                    summary: "write all blocks to a file",
                    value: Value::File,
                },
                READER,
                Opt {
                    flag: "--comment",
                    summary: "SSH comment",
                    value: Value::Text("comment"),
                },
            ],
        },
        VerbTag::CardExportAll => Arguments {
            positionals: &[Positional {
                name: "directory",
                value: Value::Directory,
                repeated: false,
            }],
            options: &[READER],
        },
        VerbTag::PinActivate => Arguments {
            positionals: &[PIN_NUMBER],
            options: &[
                Opt {
                    flag: "--allow-reactivate",
                    summary: "run on a card that already looks activated",
                    value: Value::None,
                },
                READER,
            ],
        },
        VerbTag::PinChange => Arguments {
            positionals: &[PIN_NUMBER],
            options: &[READER, CAN],
        },
        VerbTag::PinUnblock => Arguments {
            positionals: &[PIN_NUMBER],
            options: &[READER],
        },
        VerbTag::DocumentSign => Arguments {
            positionals: &[Positional {
                name: "file",
                value: Value::File,
                repeated: true,
            }],
            options: &[
                Opt {
                    flag: "--format",
                    summary: "signature format",
                    value: Value::Words(&[
                        "pades",
                        "cades",
                        "cades-detached",
                        "asice",
                        "bdoc",
                        "asice-cades",
                    ]),
                },
                Opt {
                    flag: "--out",
                    summary: "the finished document",
                    value: Value::File,
                },
                Opt {
                    flag: "--slot",
                    summary: "which key",
                    value: Value::Words(&["qualified", "auth"]),
                },
                Opt {
                    flag: "--reason",
                    summary: "PAdES /Reason",
                    value: Value::Text("text"),
                },
                Opt {
                    flag: "--location",
                    summary: "PAdES /Location",
                    value: Value::Text("text"),
                },
                READER,
                CAN,
                Opt {
                    flag: "--timestamp",
                    summary: "timestamp authority URL or named set",
                    value: Value::Url,
                },
                Opt {
                    flag: "--no-stamp",
                    summary: "no visible seal on the PDF",
                    value: Value::None,
                },
            ],
        },
        VerbTag::PhoneCheck | VerbTag::PhonePair | VerbTag::PhoneUnpair => NOTHING,
        VerbTag::PhoneAuth => Arguments {
            positionals: &[Positional {
                name: "url",
                value: Value::Url,
                repeated: false,
            }],
            options: &[],
        },
        VerbTag::Verify => Arguments {
            positionals: &[],
            options: &[
                Opt {
                    flag: "--cert",
                    summary: "certificate in PEM or DER",
                    value: Value::File,
                },
                Opt {
                    flag: "--in",
                    summary: "the message that was signed",
                    value: Value::File,
                },
                Opt {
                    flag: "--sig",
                    summary: "the raw signature",
                    value: Value::File,
                },
            ],
        },
        VerbTag::CertShow => Arguments {
            positionals: &[Positional {
                name: "certificate",
                value: Value::File,
                repeated: false,
            }],
            options: &[],
        },
        VerbTag::CertChain => Arguments {
            positionals: &[Positional {
                name: "certificate",
                value: Value::File,
                repeated: false,
            }],
            options: &[
                Opt {
                    flag: "--issuer-dir",
                    summary: "directory of candidate issuer certificates",
                    value: Value::Directory,
                },
                Opt {
                    flag: "--aia-fetch",
                    summary: "fetch missing issuers over HTTP",
                    value: Value::None,
                },
            ],
        },
        VerbTag::ReaderKeyboard => Arguments {
            positionals: &[Positional {
                name: "mode",
                value: Value::Words(&["status", "on", "off"]),
                repeated: false,
            }],
            options: &[READER],
        },
    }
}

/// The line a group gets in the top-level listing: its bare command's
/// summary where the bare word is a command, its only verb's where it
/// has one verb, and a line of its own otherwise.
fn group_summary(group: &str) -> Option<&'static str> {
    if let Some(bare) = VerbTag::ALL.iter().find(|tag| tag.label() == group) {
        return Some(bare.summary());
    }
    let verbs: Vec<VerbTag> = VerbTag::verbs_of(group).map(|(_, tag)| tag).collect();
    match verbs.as_slice() {
        [only] => Some(only.summary()),
        _ => GROUP_SUMMARIES
            .iter()
            .find(|(name, _)| *name == group)
            .map(|(_, summary)| *summary),
    }
}

/// The groups whose listing line is not any one command's summary.
const GROUP_SUMMARIES: &[(&str, &str)] = &[
    ("pin", "activate, change or unblock a PIN"),
    ("cert", "print a certificate or walk its chain"),
];

/// The word that lists the advanced commands, and its line.
const EXPERT: (&str, &str) = ("expert", "list the advanced commands");
/// The word that lists the commands, and its line.
const HELP: (&str, &str) = ("help", "list the commands");

/// A string inside single quotes in zsh: a quote closes, escapes and
/// reopens.
fn quoted(text: &str) -> String {
    text.replace('\'', "'\\''")
}

/// A `_describe` entry `'word:description'`; a colon in the
/// description is escaped so it is not read as the separator.
fn entry(word: &str, description: &str) -> String {
    format!("'{word}:{}'", quoted(description).replace(':', "\\:"))
}

/// The completer for a value, if any.
fn completer(value: Value) -> Option<String> {
    match value {
        Value::None | Value::Text(_) => None,
        Value::File => Some("_files".to_owned()),
        Value::Directory => Some("_files -/".to_owned()),
        Value::Words(words) => Some(format!("({})", words.join(" "))),
        Value::Url => Some("_urls".to_owned()),
    }
}

/// The noun an option's value is shown under.
fn value_name(opt: &Opt) -> &'static str {
    match opt.value {
        Value::None => "",
        Value::File => "file",
        Value::Directory => "directory",
        Value::Url => "url",
        Value::Text(noun) => noun,
        Value::Words(_) => opt.flag.trim_start_matches('-'),
    }
}

/// An `_arguments` spec for an option.
fn option_spec(opt: &Opt) -> String {
    let mut spec = format!("'{}[{}]", opt.flag, quoted(opt.summary));
    if !matches!(opt.value, Value::None) {
        let _ = write!(spec, ":{}", value_name(opt));
        if let Some(completer) = completer(opt.value) {
            let _ = write!(spec, ":{completer}");
        }
    }
    spec.push('\'');
    spec
}

/// An `_arguments` spec for a positional argument at `index`.
fn positional_spec(index: usize, positional: &Positional) -> String {
    let place = if positional.repeated {
        "*".to_owned()
    } else {
        index.saturating_add(1).to_string()
    };
    let mut spec = format!("'{place}:{}", positional.name);
    if let Some(completer) = completer(positional.value) {
        let _ = write!(spec, ":{completer}");
    }
    spec.push('\'');
    spec
}

/// The `_arguments` call for a command's arguments, indented, or
/// nothing when there is nothing to complete.
fn arguments_call(out: &mut String, indent: &str, arguments: Arguments) {
    let mut specs: Vec<String> = arguments
        .positionals
        .iter()
        .enumerate()
        .map(|(index, positional)| positional_spec(index, positional))
        .collect();
    specs.extend(arguments.options.iter().map(option_spec));
    if specs.is_empty() {
        return;
    }
    let _ = writeln!(out, "{indent}_arguments \\");
    let last = specs.len().saturating_sub(1);
    for (index, spec) in specs.iter().enumerate() {
        let tail = if index == last { "" } else { " \\" };
        let _ = writeln!(out, "{indent}  {spec}{tail}");
    }
}

/// The function that completes one group's arguments.
fn group_function(out: &mut String, group: &str) {
    let bare = VerbTag::ALL
        .iter()
        .copied()
        .find(|tag| tag.label() == group);
    let verbs: Vec<(&str, VerbTag)> = VerbTag::verbs_of(group).collect();
    let _ = writeln!(out, "\n_refineid_{group}() {{");
    if verbs.is_empty() {
        if let Some(bare) = bare {
            arguments_call(out, "  ", arguments(bare));
        }
        out.push_str("}\n");
        return;
    }
    out.push_str("  if _refineid_verbs; then\n    local -a verbs\n    verbs=(\n");
    for (verb, tag) in &verbs {
        let _ = writeln!(out, "      {}", entry(verb, tag.summary()));
    }
    let _ = writeln!(
        out,
        "      {}",
        entry(HELP.0, &format!("show the {group} commands"))
    );
    let _ = writeln!(
        out,
        "    )\n    _describe -t verbs '{group} command' verbs\n    return\n  fi"
    );
    let names: Vec<&str> = verbs.iter().map(|(verb, _)| *verb).collect();
    let _ = writeln!(
        out,
        "  local verb\n  verb=$(_refineid_expand \"$words[2]\" {})\n  case $verb in",
        names.join(" ")
    );
    for (verb, tag) in &verbs {
        let arguments = arguments(*tag);
        if arguments.positionals.is_empty() && arguments.options.is_empty() {
            continue;
        }
        let _ = writeln!(out, "    {verb})\n      shift words; (( CURRENT-- ))");
        arguments_call(out, "      ", arguments);
        out.push_str("      ;;\n");
    }
    if let Some(bare) = bare {
        let arguments = arguments(bare);
        if !arguments.positionals.is_empty() || !arguments.options.is_empty() {
            // Only an option after the bare word reaches here; an
            // unknown or ambiguous verb completes nothing.
            out.push_str("    -*)\n");
            arguments_call(out, "      ", arguments);
            out.push_str("      ;;\n");
        }
    }
    out.push_str("  esac\n}\n");
}

/// The whole completion file.
#[must_use]
pub fn zsh() -> String {
    let groups: Vec<&str> = VerbTag::groups().collect();
    let mut out = String::from(
        "#compdef refineid\n\
         # zsh completion for refineid(1), generated from the command table by\n\
         # crates/refineid-client/src/cli/completion.rs. Do not edit; run\n\
         #   cargo test -p refineid-client regenerate_zsh_completion -- --ignored\n\
         # after a command or option changes. A test fails while this file is\n\
         # stale.\n\
         \n\
         _refineid() {\n\
         \x20 local curcontext=\"$curcontext\" state line ret=1\n\
         \x20 typeset -A opt_args\n\
         \n\
         \x20 _arguments -C \\\n\
         \x20   '(-v --verbose)'{-v,--verbose}'[show each step]' \\\n\
         \x20   '(-V --version)'{-V,--version}'[print the version]' \\\n\
         \x20   '1:command:->command' \\\n\
         \x20   '*::arguments:->arguments' && ret=0\n\
         \n\
         \x20 case $state in\n\
         \x20   command)\n\
         \x20     local -a commands\n\
         \x20     commands=(\n",
    );
    for group in &groups {
        let summary = group_summary(group).unwrap_or_default();
        let _ = writeln!(out, "        {}", entry(group, summary));
    }
    let _ = writeln!(out, "        {}", entry(EXPERT.0, EXPERT.1));
    let _ = writeln!(out, "        {}", entry(HELP.0, HELP.1));
    let _ = write!(
        out,
        "      )\n\
         \x20     _describe -t commands 'command' commands && ret=0\n\
         \x20     ;;\n\
         \x20   arguments)\n\
         \x20     # words[1] is the command word, possibly shortened.\n\
         \x20     local group\n\
         \x20     group=$(_refineid_expand \"$words[1]\" {} {} {})\n\
         \x20     curcontext=\"${{curcontext%:*:*}}:refineid-$group:\"\n\
         \x20     case $group in\n",
        groups.join(" "),
        EXPERT.0,
        HELP.0
    );
    for group in &groups {
        let _ = writeln!(out, "        {group}) _refineid_{group} && ret=0 ;;");
    }
    let _ = writeln!(
        out,
        "        {}) _refineid_{} && ret=0 ;;",
        EXPERT.0, EXPERT.0
    );
    out.push_str(
        "      esac\n\
         \x20     ;;\n\
         \x20 esac\n\
         \x20 return ret\n\
         }\n\
         \n\
         # The whole word among the candidates that a possibly shortened word\n\
         # names: the word itself when it is one, else the only candidate it\n\
         # starts. Prints the word unchanged when it names nothing or several.\n\
         _refineid_expand() {\n\
         \x20 local word=$1; shift\n\
         \x20 local -a candidates=(\"$@\")\n\
         \x20 if (( ${candidates[(Ie)$word]} )); then\n\
         \x20   print -r -- \"$word\"\n\
         \x20   return\n\
         \x20 fi\n\
         \x20 local -a hits=(${(M)candidates:#\"$word\"*})\n\
         \x20 if (( $#hits == 1 )); then\n\
         \x20   print -r -- \"$hits[1]\"\n\
         \x20 else\n\
         \x20   print -r -- \"$word\"\n\
         \x20 fi\n\
         }\n\
         \n\
         # True while the second word of a group is being typed and is not an\n\
         # option: the verbs are offered then.\n\
         _refineid_verbs() {\n\
         \x20 (( CURRENT == 2 )) && [[ $words[2] != -* ]]\n\
         }\n",
    );
    for group in &groups {
        group_function(&mut out, group);
    }
    let _ = write!(
        out,
        "\n_refineid_{}() {{\n\
         \x20 if (( CURRENT == 2 )); then\n\
         \x20   local -a words_after\n\
         \x20   words_after=({})\n\
         \x20   _describe -t words 'word' words_after\n\
         \x20 fi\n\
         }}\n\
         \n\
         _refineid \"$@\"\n",
        EXPERT.0,
        entry(HELP.0, EXPERT.1)
    );
    out
}

#[cfg(test)]
mod tests {
    use super::{Value, arguments, group_summary, zsh};
    use crate::cli::help::help_options;
    use crate::cli::verb::VerbTag;
    use crate::test_util::{TestResult, check, check_true};

    /// The checked-in completion file.
    const FILE: &str = include_str!("../../../../packaging/zsh/_refineid");
    /// Where the regenerating test writes it.
    const FILE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/zsh/_refineid");

    #[test]
    fn the_checked_in_completion_is_the_generated_one() -> TestResult {
        check_true(
            FILE == zsh(),
            "packaging/zsh/_refineid is stale; run \
             cargo test -p refineid-client regenerate_zsh_completion -- --ignored",
        )
    }

    #[test]
    #[ignore = "rewrites packaging/zsh/_refineid"]
    fn regenerate_zsh_completion() -> TestResult {
        std::fs::write(FILE_PATH, zsh()).map_err(|e| format!("write {FILE_PATH}: {e}"))?;
        Ok(())
    }

    #[test]
    fn every_option_a_help_text_names_is_completed_and_no_other() -> TestResult {
        for &tag in VerbTag::ALL {
            let mut completed: Vec<&str> = arguments(tag).options.iter().map(|o| o.flag).collect();
            completed.sort_unstable();
            completed.dedup();
            let mut shown = help_options(tag);
            shown.sort_unstable();
            shown.dedup();
            check(&completed, &shown, &format!("options of {}", tag.label()))?;
        }
        Ok(())
    }

    /// A value's words and nouns are emitted raw, so they carry no
    /// quote, colon or space.
    fn plain_value(value: Value, owner: &str) -> TestResult {
        match value {
            Value::Words(words) => {
                check_true(!words.is_empty(), &format!("{owner} words"))?;
                for word in words {
                    check_true(
                        !word.contains([':', '\'', ' ', '(', ')']),
                        &format!("{word} of {owner} is plain"),
                    )?;
                }
                Ok(())
            }
            Value::Text(noun) => check_true(
                !noun.contains([':', '\'']),
                &format!("{noun} of {owner} is plain"),
            ),
            Value::None | Value::File | Value::Directory | Value::Url => Ok(()),
        }
    }

    #[test]
    fn every_group_has_a_listing_line_and_no_text_breaks_the_quoting() -> TestResult {
        for group in VerbTag::groups() {
            check_true(group_summary(group).is_some(), &format!("{group} summary"))?;
        }
        for &tag in VerbTag::ALL {
            let arguments = arguments(tag);
            for opt in arguments.options {
                check_true(
                    !opt.summary.contains(['[', ']']),
                    &format!("{} of {} has no brackets", opt.flag, tag.label()),
                )?;
                plain_value(opt.value, opt.flag)?;
            }
            for positional in arguments.positionals {
                check_true(
                    !positional.name.contains([':', '\'', ' ']),
                    &format!("{} name is plain", positional.name),
                )?;
                plain_value(positional.value, positional.name)?;
            }
        }
        Ok(())
    }
}
