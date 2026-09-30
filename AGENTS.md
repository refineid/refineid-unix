- RULE #1: PIN CODES NEVER TRAVEL OVER ANY NETWORK.
  PIN1 and PIN2 NEVER leave the phone when accessed via RAPP.
  RAPP MUST ABSOLUTELY DENY AND PRECLUDE ALL ATTEMPTS TO TRANSPORT PIN CODES ANYWHERE.
  PIN1 stays cached on the mobile device. PIN2 prompts appear strictly on the mobile
  device screen. The host computer and browsers operate via a protected authentication
  path (CKF_PROTECTED_AUTHENTICATION_PATH) and never prompt for or handle PIN codes.
- RULE #2: ZERO PIN DATA AND CANDIDATE PIN-LENGTH LOGGING ACROSS ALL ENVIRONMENTS.
  Never log, trace, display, or format PIN bytes, character offsets, supplied/candidate
  PIN lengths, or development PIN role identifiers in log sinks, audit records, or
  error strings. Only static specification policy bounds may be reported. Never commit
  test PINs or card secrets.
- Please No AI attribution spam in commits.
  No `Co-authored-by` / `Signed-off-by` / `Reviewed-by`
  or any AI-naming trailer; subject + body only. 
- ASCII only in source, UTF-8 only where required.
- No Magic Codes - define everything.   
- Commit often when compiles and lint is clean.
- Push when feature is ready.
- Native Git hooks are mandatory. Install them with
  `script/install-githook.sh`; keep `core.hooksPath=script/githook` active and
  never bypass or disable the hooks. Pre-commit checks formatting and the
  workspace; pre-push runs the complete local build, test, Clippy, and rustdoc
  floor. GitHub Nix builds are available manually and run weekly for both
  x86_64 and arm64 coverage; they do not replace local hooks.
- Verify from specifications, don't wild guess.
  `doc/references.md` indexes which one governs what.
  Cite what a source proves, and say what it does not.
- Never put a git worktree under `/tmp`. It is cleared on reboot and
  takes the branch's only checkout with it. Keep worktrees beside the
  repository.
- Less is more. Terse is better.
- Do not leak personal or private information in commits.
- When stuck, research with fellow AI available.
- If something is not working, it is by default a bug in code,
  not a feature of the platform.

## Source comments

- Comments explain what the code does now and the constraints it honors.
  Past bugs, previous implementations, and explanations of what a fix changed
  belong in commit messages, not source comments.

## Commits and integration

- Commits are cheap backups. Make small, focused commits often, without
  asking for permission, once the required commit checks pass.
- Complete the integration without waiting for another instruction: push
  the task branch, open a pull request, and merge it into `main` once the
  required checks pass. Sync local `main` with the merged remote.
  Use squash merges to keep the `main` history linear; do not use merge commits.

## Record deferred findings

- While working, file a GitHub issue in the owning repository for each
  confirmed, actionable defect or quality gap that cannot reasonably be
  fixed within the current task. Filing these issues is authorized; do not
  wait for a separate instruction for each finding.
- Search existing open issues first. Reuse the matching issue and add only
  new, useful evidence instead of creating a duplicate. Group findings only
  when they share a cause and can be resolved by one focused change.
- State the observed behavior, expected behavior, affected repository-relative
  paths, reproduction or inspection evidence, impact, and acceptance checks.
  Distinguish observations from hypotheses and specification requirements.
  Never claim an unexecuted test or hardware operation was verified.
- Keep speculative improvements in working notes until they have a concrete
  problem and useful acceptance criteria. Avoid issue spam and severity claims
  unsupported by evidence.
- Never put credentials, PIN data or candidate lengths, card secrets,
  personal data, private workspace paths, or persistent device identifiers
  in issue text, logs, screenshots, attachments, or reproduction fixtures.
  Report security-sensitive findings through the repository's private
  reporting process; if no safe channel is available, notify the user
  without publishing sensitive details.
- An issue does not excuse a broken gate or incomplete work needed to make
  the current task correct. Fix findings required for the task before handing
  it over; file independently deferred work with a clear scope.
- Link newly filed or reused issues in the task handoff. If issue creation is
  unavailable, preserve a sanitized finding locally and report that it was
  not filed; never silently discard it.
