#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

PYTHONDONTWRITEBYTECODE=1 python3 "$REPO_ROOT/script/test-documentation-gate.py"

if ! command -v cargo >/dev/null 2>&1; then
    echo "verify-push: cargo not found on PATH" >&2
    exit 1
fi

echo "== verify-push: format check =="
cargo fmt --all --check

echo "== verify-push: magic-number policy =="
if [ -n "${REFINEID_MAGIC_DIFF_BASE:-}" ]; then
    cargo run -q -p xtask -- check-magic-numbers --diff-base "$REFINEID_MAGIC_DIFF_BASE"
elif git rev-parse --verify -q origin/main >/dev/null 2>&1; then
    cargo run -q -p xtask -- check-magic-numbers --diff-base origin/main
else
    cargo run -q -p xtask -- check-magic-numbers
fi

RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }-D warnings"
RUSTDOCFLAGS="${RUSTDOCFLAGS:+${RUSTDOCFLAGS} }-D warnings"
export RUSTFLAGS RUSTDOCFLAGS

echo "== verify-push: workspace build =="
cargo build --workspace --all-targets

echo "== verify-push: unit tests =="
cargo test --workspace
cargo test --workspace --examples

echo "== verify-push: clippy =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== verify-push: rustdoc =="
cargo doc --workspace --no-deps

echo "pre-push full floor passed."
