# Agent Worktrees

Status: Active

## Context

Several agents (and the owner) work on this repository at the same time.
One task, one worktree, one branch, one pull request keeps that work from
colliding and keeps the main checkout pristine for integration.

## Topology and naming

- Reading does not require a worktree; writing does. The main checkout is
  never edited directly. It integrates and releases.
- Each task gets a worktree strictly under `../wt/`, never loose beside
  repositories, in a parent directory or under `/tmp/`:
  `../wt/refineid-unix-<topic>` on branch `<topic>`.
- One branch carries one pull request. Never stack unrelated work onto a
  branch that already has an open pull request.

## Starting a task

1. Update local main: `git checkout main && git pull --ff-only`.
2. Run `script/agent-housekeeping.sh` and act on what it reports.
3. Create the worktree under `../wt/`:
   `git worktree add ../wt/refineid-unix-<topic> -b <topic>`.
4. Make sure the quality gate hooks are installed. `script/install-githook.sh`
   sets `core.hooksPath` in the shared repository configuration, so this is
   once per clone, not per worktree; `script/install-githook.sh --check`
   verifies it.

The Cargo registry and git caches live outside the checkout, so a fresh
worktree downloads only what main has not already fetched. Each worktree
has its own `target/`, so the first build compiles every crate,
dependencies included, from scratch.

## Housekeeping

`script/agent-housekeeping.sh` reports every worktree with its branch,
merge state, dirty files, commits beyond main (`unpushed`), activity
freshness, and disk use. With `--clean` it removes only what is provably
done:

- The branch is merged into main, the tree is clean, and the branch has no
  commits beyond main. The work is fully preserved in main, so deleting the
  worktree loses nothing. The branch goes with it.

That predicate does not look at activity: a worktree that qualifies is
removed however recent its activity, and a just-created worktree still at
main qualifies. Housekeeping therefore runs before `git worktree add`, and
the first edit (which makes the tree dirty) takes the worktree out of
reach.

Everything else is reported, never destroyed, with the latest commit headline
quoted so the evaluator (owner or agent) can decide in seconds whether to
resume work or clean up. In particular:

- Uncommitted changes or commits beyond main are never auto-deleted.
- Fresh activity on such a worktree reads `KEEP`; stale activity reads
  `REVIEW` and waits for an owner decision.
- A worktree outside `../wt/` (resolved next to the main checkout) is
  flagged as non-compliant.

## Finishing a task

1. Run the quality gates in the worktree: `script/verify-commit.sh` is the
   pre-commit floor and `script/verify-push.sh` the full pre-push floor
   (format, build, tests, Clippy, rustdoc).
2. Commit on the task branch (imperative subject and explanatory body only;
   no attribution trailers) and push.
3. Open one pull request for the branch and review its diff independently
   as AGENTS.md describes.
4. Squash-merge after the local gates pass and the review is complete, so
   the `main` history stays linear. The pull request preserves the branch
   history; the manual Nix workflow is a portability check, not a merge
   gate.
5. Remove the worktree (`git worktree remove`), delete the branch, and
   fast-forward local main.

## Out of scope

Physical readers and FINEID cards are owner-coordinated. Agents do not
arbitrate or reserve PC/SC readers; if a reader is busy, the work waits.
Hardware claims require a real reader and card.
