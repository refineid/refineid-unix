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

//! `pin activate [1|2]` typed arguments.

use std::process::ExitCode;

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct PinActivateHelpers;

use refineid_lib_core::auth::UnblockOutcome;
use refineid_lib_core::pin::ActivationCode;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};
use crate::card_pin::{
    ActivateReport, ActivationCardContext, ActivationTarget, CardPinError, CardTrustAttestation,
    PinManageSlot,
};
use crate::exit_status::ExitStatus;

/// What `refineid pin activate help`
/// prints. The man page refineid(1) carries the same facts.
pub const HELP: &str = "\
usage: refineid pin activate [1|2] [--allow-reactivate] [--reader SUBSTR]

First-time DVV card activation. Prompts for the activation PIN, then
new PIN 1 and PIN 2, or only the PIN named. Prints nothing on success,
except a line on stderr when the other PIN is still unactivated; -v
shows each step.
  --allow-reactivate  run on a card that already looks activated
  --reader S          narrow to readers whose name contains S
WARNING: wrong tries consume the activation PIN's retry counter;
locking it leaves recovery to the separately orderable paid PUK.
";

/// Parsed `pin activate [1|2] [--allow-reactivate] [--reader SUBSTR]`
/// arguments.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActivateArgs {
    /// The PIN to activate: the optional `1|2` argument. `None`
    /// activates both, PIN 1 then PIN 2.
    pub slot: Option<PinManageSlot>,
    /// Override the pre-flight refusal on an apparently-
    /// activated card. Rarely the right answer; the prompt
    /// in the activate flow itself explains the trade-off.
    pub allow_reactivate: bool,
    /// Optional reader-name substring (`--reader SUBSTR`).
    /// Tier 0 `String`; presentational input to `ReaderFilter`.
    pub reader_filter: Option<String>,
}

/// The prefix of every operator-facing message, after the PIN the
/// invocation activates.
const fn cmd(slot: Option<PinManageSlot>) -> &'static str {
    match slot {
        None => "pin activate",
        Some(PinManageSlot::Pin1) => "pin activate 1",
        Some(PinManageSlot::Pin2) => "pin activate 2",
    }
}

/// The length hint of a new PIN's first prompt.
const fn digit_hint(slot: PinManageSlot) -> &'static str {
    match slot {
        PinManageSlot::Pin1 => "basic, 4-12 digits",
        PinManageSlot::Pin2 => "signature, 6-12 digits",
    }
}

/// The env var consulted for a new PIN; see [`ENV_NEW_PIN1`].
const fn env_new_pin(slot: PinManageSlot) -> &'static str {
    match slot {
        PinManageSlot::Pin1 => ENV_NEW_PIN1,
        PinManageSlot::Pin2 => ENV_NEW_PIN2,
    }
}

/// The PIN a one-PIN activation leaves as it was.
const fn other_pin(slot: PinManageSlot) -> PinManageSlot {
    match slot {
        PinManageSlot::Pin1 => PinManageSlot::Pin2,
        PinManageSlot::Pin2 => PinManageSlot::Pin1,
    }
}

/// Env var consulted (alpha-period debug aid) for the 7-/8-digit
/// activation PIN before the interactive prompt. See
/// [`PinActivateHelpers::read_pin_env_or_prompt`] for the
/// semantics and the AGENTS.md §6 alpha exception.
const ENV_ACTIVATION_PIN: &str = "REFINEID_ACTIVATION_PIN";
/// Env var consulted (alpha-period debug aid) for the new PIN1
/// value before the interactive new-PIN prompt + confirm.
const ENV_NEW_PIN1: &str = "REFINEID_NEW_PIN1";
/// Env var consulted (alpha-period debug aid) for the new PIN2
/// value before the interactive new-PIN prompt + confirm.
const ENV_NEW_PIN2: &str = "REFINEID_NEW_PIN2";

impl ActivateArgs {
    /// Execute the `pin activate` verb. Silent on success; `verbose`
    /// prints the step report. A one-PIN activation that leaves the
    /// other PIN unactivated says so on stderr.
    #[must_use]
    pub fn run(self, verbose: bool) -> ExitCode {
        let Self {
            slot,
            allow_reactivate,
            reader_filter,
        } = self;
        let cmd = cmd(slot);
        let target = slot.map_or(ActivationTarget::Both, ActivationTarget::One);
        let backend = refineid_lib_pcsc::PcscBackend;
        let typed_reader_filter = reader_filter
            .as_deref()
            .map(refineid_lib_core::backend::ReaderFilter::new);
        let ctx = match crate::card_pin::classify_card_for_activation(
            backend,
            typed_reader_filter.as_ref(),
        ) {
            Ok(c) => c,
            Err(CardPinError::ReaderPick(pe)) => {
                return super::util::reader_pick_exit(cmd, &pe);
            }
            Err(e) => {
                eprintln!("{cmd}: {e}");
                return ExitStatus::RuntimeFailure.into();
            }
        };
        let Some(expected_len) = ctx.expected_activation_pin_length() else {
            eprintln!(
                "{cmd}: couldn't classify card generation from auth cert; \
                 refusing to guess at activation PIN length"
            );
            return ExitStatus::RuntimeFailure.into();
        };
        if verbose {
            PinActivateHelpers::note_generation_disagreement(cmd, &ctx, verbose);
        }
        // Refuse an activated card, or a counter below the retry floor,
        // before prompting.
        match crate::card_pin::probe_activation_gate_for_cli(
            backend,
            &ctx,
            target,
            allow_reactivate,
        ) {
            Ok(None) => {}
            Ok(Some(refused)) => {
                let status = PinActivateHelpers::activate_outcome_status(&refused);
                super::util::show_outcome(verbose, status == ExitStatus::Ok, &refused);
                return status.into();
            }
            Err(e @ CardPinError::RetryFloor(_)) => {
                eprintln!("{cmd}: {e}");
                return ExitStatus::CardCredentialRejected.into();
            }
            Err(e) => {
                eprintln!("{cmd}: {e}");
                return ExitStatus::RuntimeFailure.into();
            }
        }
        PinActivateHelpers::emit_preflight_event(&ctx, expected_len);
        let activation_pin = match PinActivateHelpers::prompt_activation_pin(cmd, expected_len) {
            Ok(p) => p,
            Err(exit) => return exit,
        };
        let new_pin = |slot: PinManageSlot| {
            super::util::new_pin_env_or_prompt(
                cmd,
                env_new_pin(slot),
                super::util::pin_name(slot),
                Some(digit_hint(slot)),
            )
        };
        let result = match slot {
            None => {
                let pin1_new = match new_pin(PinManageSlot::Pin1) {
                    Ok(p) => p,
                    Err(exit) => return exit,
                };
                let pin2_new = match new_pin(PinManageSlot::Pin2) {
                    Ok(p) => p,
                    Err(exit) => return exit,
                };
                crate::card_pin::activate_first(
                    backend,
                    ctx,
                    crate::card_pin::ActivateOptions {
                        activation_pin,
                        new_pin1: pin1_new,
                        new_pin2: pin2_new,
                        allow_reactivate,
                    },
                )
            }
            Some(slot) => {
                let new = match new_pin(slot) {
                    Ok(p) => p,
                    Err(exit) => return exit,
                };
                crate::card_pin::activate_one_first(
                    backend,
                    ctx,
                    crate::card_pin::ActivateOneOptions {
                        activation_pin,
                        slot,
                        new_pin: new,
                        allow_reactivate,
                    },
                )
            }
        };
        drop(reader_filter);
        match result {
            Ok(report) => {
                let status = PinActivateHelpers::activate_outcome_status(&report);
                super::util::show_outcome(verbose, status == ExitStatus::Ok, &report);
                if let (ExitStatus::Ok, ActivationTarget::One(done)) = (status, report.target)
                    && report.other_looks_unactivated
                {
                    eprintln!(
                        "{cmd}: {} is not activated; the card is not fully active",
                        super::util::pin_name(other_pin(done))
                    );
                }
                status.into()
            }
            Err(CardPinError::ReaderPick(pe)) => super::util::reader_pick_exit(cmd, &pe),
            Err(e @ (CardPinError::PinPolicy(_) | CardPinError::RetryFloor(_))) => {
                eprintln!("{cmd}: {e}");
                ExitStatus::CardCredentialRejected.into()
            }
            Err(e) => {
                eprintln!("{cmd}: {e}");
                ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut slot: Option<PinManageSlot> = None;
        let mut allow_reactivate = false;
        let mut reader_filter: Option<String> = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--allow-reactivate" => allow_reactivate = true,
                "--reader" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::PinActivate,
                        flag: "--reader",
                    })?;
                    reader_filter = Some(value.clone());
                }
                other => match super::util::pin_number(other) {
                    Some(number) if slot.is_none() => slot = Some(number),
                    _ => {
                        return Err(ArgParseError::Unexpected {
                            cmd: VerbTag::PinActivate,
                            got: other.to_owned(),
                        });
                    }
                },
            }
        }
        Ok(Self {
            slot,
            allow_reactivate,
            reader_filter,
        })
    }
}

/// Single-line note when the issuance-date generation verdict
/// disagrees with the issuer-CN heuristic. The issuance-date
/// verdict wins regardless; the line just records the
/// disagreement for the operator's log.
impl PinActivateHelpers {
    /// Print a one-line operator note when the two card-
    /// generation signals disagree; the caller does so under `-v`.
    ///
    /// The card-issuance-date signal (FINEID S4-1 v4.2 §1.3
    /// table) and the auth-cert issuer-CN heuristic should
    /// usually agree on whether this is a 7- or 8-digit-PIN
    /// generation. Disagreement is uncommon but not fatal --
    /// the issuance-date verdict wins and the flow continues;
    /// the note exists so the discrepancy lands in the audit
    /// log.
    fn note_generation_disagreement(cmd: &str, ctx: &ActivationCardContext, verbose: bool) {
        if verbose
            && ctx.generation != ctx.generation_by_issuer_cn
            && ctx.generation_by_issuer_cn != refineid_lib_core::pkcs15::CardGeneration::Unknown
        {
            eprintln!(
                "{cmd}: note: card generation by issuance-date ({:?}) disagrees with \
             issuer-CN heuristic ({:?}); proceeding with the issuance-date verdict",
                ctx.generation, ctx.generation_by_issuer_cn,
            );
        }
    }
}

/// Emit the JSONL pre-flight event with trust-state + card-model
/// metadata. The operator's `pin activate` invocation flushes
/// this *before* the activation-PIN prompt so log scrapers can
/// pair the prompt with the targeted card.
impl PinActivateHelpers {
    /// Emit the `card.activate.preflight.ready` JSONL event.
    ///
    /// Captures the trust state, card-model facts, and the
    /// declared activation-PIN length *before* the operator
    /// is prompted for the PIN, so a downstream scraper can
    /// pair the JSONL line with the human prompt. Required by
    /// `doc/observability.md` -- the pre-flight event is part
    /// of the audit baseline.
    fn emit_preflight_event(ctx: &ActivationCardContext, expected_len: usize) {
        let (trust_root_label, trust_root_sha256_hex) = match &ctx.trust {
            CardTrustAttestation::PinnedRootMatched {
                root_label,
                root_sha256,
            } => (*root_label, format!("{root_sha256}")),
            CardTrustAttestation::PinnedRootMismatch { .. }
            | CardTrustAttestation::RootCertUnavailable { .. } => ("", String::new()),
        };
        let card_issued = format!(
            "{:04}-{:02}-{:02}",
            ctx.issuance_date.year(),
            ctx.issuance_date.month(),
            ctx.issuance_date.day(),
        );
        let activation_pin_length_str = format!("{expected_len}");
        let model = ctx.model;
        crate::events::CardActivatePreflightReady {
            trust_state: "pinned_root_matched",
            trust_root_label,
            trust_root_sha256: &trust_root_sha256_hex,
            card_issued: &card_issued,
            card_type: model.card_type().as_dvv_label(),
            card_vendor: model.vendor().as_dvv_label(),
            card_vendor_product: model.vendor_product(),
            card_vendor_product_version: model.vendor_product_version(),
            fineid_specification: model.fineid_specification(),
            fineid_specification_version: model.fineid_specification_version(),
            activation_pin_length: &activation_pin_length_str,
            wrong_tries_to_lock: "5",
            attempts_this_invocation: "1",
        }
        .emit();
    }
}

/// Prompt for the activation PIN and wrap it in the typed
/// [`ActivationCode`] variant that matches `expected_len` (7
/// for current-generation DVV cards, 8 for legacy). Either
/// length-typed constructor rejects a mistyped value at the
/// trust boundary so the activate call only sees the in-shape
/// form.
impl PinActivateHelpers {
    /// Prompt for the activation PIN and lift it into the
    /// length-typed [`ActivationCode`] variant.
    ///
    /// FINEID S4-1 §4.6 -- 7 digits for newer cards, 8 for
    /// older. The length-typed constructor rejects out-of-shape
    /// input at the trust boundary so downstream code only
    /// ever sees an in-shape value. An "unexpected length
    /// contract" return is a host bug, not a card outcome --
    /// the calling site should already have classified the
    /// generation.
    fn prompt_activation_pin(cmd: &str, expected_len: usize) -> Result<ActivationCode, ExitCode> {
        let raw = super::util::pin_env_or_prompt(
            cmd,
            ENV_ACTIVATION_PIN,
            super::util::PROMPT_ACTIVATION_PIN,
        )?;
        match expected_len {
            7 => refineid_lib_core::pin::ActivationPinSeven::new(raw)
                .map(ActivationCode::Seven)
                .map_err(|e| {
                    eprintln!("{cmd}: activation PIN: {e}");
                    ExitCode::from(ExitStatus::BadInvocation)
                }),
            8 => refineid_lib_core::pin::ActivationPinEight::new(raw)
                .map(ActivationCode::Eight)
                .map_err(|e| {
                    eprintln!("{cmd}: activation PIN: {e}");
                    ExitCode::from(ExitStatus::BadInvocation)
                }),
            other => {
                eprintln!("{cmd}: unexpected activation PIN length contract: {other}");
                Err(ExitStatus::RuntimeFailure.into())
            }
        }
    }
}

/// Map the card-side per-PIN outcome pair to the project's exit
/// status convention:
///
/// - Every targeted PIN Ok -> `Ok`.
/// - Pre-flight refused (rerun with `--allow-reactivate`) ->
///   `NoReaders` (no-cards-applied "config-like" exit; not a
///   hard failure).
/// - Either PIN rejected by card (wrong PUK / locked /
///   invalidated) -> `CardCredentialRejected`.
/// - Anything else -> `RuntimeFailure`.
impl PinActivateHelpers {
    /// Translate the [`ActivateReport`] into an
    /// [`ExitStatus`].
    ///
    /// `Ok` only when every targeted PIN succeeded; otherwise the
    /// mapping is per the project exit-status contract:
    /// pre-flight refusal -> `NoReaders`,
    /// `WrongPuk`/`PukLocked`/`Invalidated` ->
    /// `CardCredentialRejected`, anything else ->
    /// `RuntimeFailure`. The mapping table is the single
    /// source of truth; the CLI shell honours it for the
    /// process exit code.
    fn activate_outcome_status(report: &ActivateReport) -> ExitStatus {
        let all_ok = match report.target {
            ActivationTarget::Both => matches!(
                (&report.pin1_outcome, &report.pin2_outcome),
                (Some(UnblockOutcome::Ok), Some(UnblockOutcome::Ok))
            ),
            ActivationTarget::One(PinManageSlot::Pin1) => {
                matches!(report.pin1_outcome, Some(UnblockOutcome::Ok))
            }
            ActivationTarget::One(PinManageSlot::Pin2) => {
                matches!(report.pin2_outcome, Some(UnblockOutcome::Ok))
            }
        };
        if all_ok {
            return ExitStatus::Ok;
        }
        match (&report.pin1_outcome, &report.pin2_outcome) {
            (None, None) => ExitStatus::NoReaders,
            (o1, o2)
                if matches!(
                    o1,
                    Some(
                        UnblockOutcome::WrongPuk { .. }
                            | UnblockOutcome::PukLocked
                            | UnblockOutcome::Invalidated
                    )
                ) || matches!(
                    o2,
                    Some(
                        UnblockOutcome::WrongPuk { .. }
                            | UnblockOutcome::PukLocked
                            | UnblockOutcome::Invalidated
                    )
                ) =>
            {
                ExitStatus::CardCredentialRejected
            }
            _ => ExitStatus::RuntimeFailure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn defaults() -> TestResult {
        let a = ActivateArgs::parse(argv(&[]))?;
        check_true(a.slot.is_none(), "both PINs")?;
        check_true(!a.allow_reactivate, "allow_reactivate=false")?;
        check_true(a.reader_filter.is_none(), "reader_filter=None")
    }

    #[test]
    fn parses_allow_reactivate_and_reader() -> TestResult {
        let a = ActivateArgs::parse(argv(&["--allow-reactivate", "--reader", "ACS"]))?;
        check_true(a.allow_reactivate, "allow_reactivate=true")?;
        check(&a.reader_filter.as_deref(), &Some("ACS"), "reader_filter")
    }

    #[test]
    fn parses_optional_pin_number() -> TestResult {
        let a = ActivateArgs::parse(argv(&["2", "--allow-reactivate"]))?;
        check(&a.slot, &Some(PinManageSlot::Pin2), "slot")?;
        check_true(a.allow_reactivate, "allow_reactivate=true")?;
        for bad in [&["3"][..], &["1", "2"]] {
            check_true(
                matches!(
                    ActivateArgs::parse(argv(bad)),
                    Err(ArgParseError::Unexpected { .. })
                ),
                &format!("{bad:?} rejected"),
            )?;
        }
        Ok(())
    }

    #[test]
    fn unknown_flag_rejected() -> TestResult {
        let r = ActivateArgs::parse(argv(&["--enforce-strong"]));
        check_true(
            matches!(r, Err(ArgParseError::Unexpected { .. })),
            "Unexpected(--enforce-strong)",
        )
    }
}
