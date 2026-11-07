#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Moves the refineid-core git dependencies to core main, then moves every
# package locked at more than one version as far up as its users allow.
# `cargo update --package refineid-apdu` alone re-resolves the users of a
# duplicated package differently on each run, so the lock file flipped
# between versions from one commit to the next.
#
# Usage: script/update-core.sh [cargo update options]; exits as cargo does.
set -eu
cd "$(git rev-parse --show-toplevel)"

cargo update --quiet --package refineid-apdu "$@"

awk '
    /^name = / { name = $3; gsub(/"/, "", name) }
    /^version = / { version = $3; gsub(/"/, "", version); print name, version }
' Cargo.lock | sort -k1,1 -k2,2V | awk '
    { seen[$1]++; if (seen[$1] == 1) lowest[$1] = $2 }
    END { for (name in seen) if (seen[name] > 1) print name "@" lowest[name] }
' | while read -r spec; do
    cargo update --quiet --offline --package "$spec" || true
done
