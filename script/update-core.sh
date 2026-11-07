#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Moves the refineid-core git dependencies to core main, then has cargo
# re-resolve the users of every registry package locked at more than one
# version, with that package held at its locked version, until the lock
# file stops changing. Its users move to a version the lock file already
# holds, so no new version enters and none skips the 48-hour cooldown.
# `cargo update --package refineid-apdu` alone re-resolves the users of a
# duplicated package differently on each run, so the lock file flipped
# between versions from one commit to the next.
#
# Usage: script/update-core.sh; exits as the core update does. Set
# CARGO_NET_OFFLINE=true to keep the locked core revision.
set -eu
cd "$(git rev-parse --show-toplevel)"

cargo update --quiet --package refineid-apdu

# Prints name@lowest-version for each registry package locked more than
# once.
duplicates() {
    awk '
        /^\[\[package\]\]/ { if (name != "" && registry) print name, version; name = ""; version = ""; registry = 0 }
        /^name = / { name = $3; gsub(/"/, "", name) }
        /^version = "/ { version = $3; gsub(/"/, "", version) }
        /^source = "registry\+/ { registry = 1 }
        END { if (name != "" && registry) print name, version }
    ' Cargo.lock | sort -k1,1 -k2,2V | awk '
        { seen[$1]++; if (seen[$1] == 1) lowest[$1] = $2 }
        END { for (name in seen) if (seen[name] > 1) print name "@" lowest[name] }
    ' | sort
}

pass=0
while [ "$pass" -lt 3 ]; do
    pass=$((pass + 1))
    before=$(cksum < Cargo.lock)
    duplicates | while read -r spec; do
        cargo update --quiet --offline --package "$spec" --precise "${spec#*@}" ||
            echo "update-core: could not settle $spec" >&2
    done
    [ "$(cksum < Cargo.lock)" = "$before" ] && break
done
