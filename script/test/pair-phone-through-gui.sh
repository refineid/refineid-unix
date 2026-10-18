#!/bin/sh
# Copyright 2026 Petri Koistinen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Pairs a Unix host's RefineID with an iPhone through both applications,
# with nobody typing: the phone, on USB to the Mac this runs on, is
# launched in the mode that prints its pairing code; the host's window
# is opened on the Phone tab and the code is typed into its boxes; the
# stored pairing and the certificate read through the phone are then
# checked on the host.
#
# usage: script/test/pair-phone-through-gui.sh <ssh host> <phone udid> [display]
#
# Needs: Xcode (xcrun devicectl) and the phone paired for development on
# this Mac; on the host, refineid-gui and refineid installed, xdotool,
# and an X session on <display> (default :0) that the ssh user owns.
set -eu

host=${1:?ssh host}
udid=${2:?phone udid}
display=${3:-:0}
bundle=fi.refineid.ReFineID
code_wait_seconds=40
pair_wait_seconds=120
read_wait_seconds=90

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

say() { printf '%s %s\n' "$(date -u '+%H:%M:%S')" "$*"; }

# Launches the phone in the mode that prints its code and writes the
# code to $work/code; the launch keeps running until the ceremony ends.
phone_offer() {
    : > "$work/offer.log"
    xcrun devicectl device process launch --device "$udid" --console \
        --terminate-existing "$bundle" --offer-remote-reader \
        < /dev/null > "$work/offer.log" 2>&1 &
    waited=0
    while [ "$waited" -lt "$code_wait_seconds" ]; do
        tr -d '\r' < "$work/offer.log" | grep -o 'offer-remote-reader: offer [0-9A-Z]\{6\}' \
            | tail -n 1 | sed 's/.* //' > "$work/code"
        if [ -s "$work/code" ]; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    say "the phone showed no code within ${code_wait_seconds} s"
    cat "$work/offer.log"
    return 1
}

phone_serve() {
    xcrun devicectl device process launch --device "$udid" --terminate-existing "$bundle" \
        > /dev/null 2>&1
}

host_sh() {
    ssh -o BatchMode=yes "$host" sh -s
}

host_type_code() {
    host_sh <<EOS
pkill -x refineid-gui >/dev/null 2>&1 || true
sleep 1
cd "\$HOME" && DISPLAY=$display nohup refineid-gui --pair > /dev/null 2>&1 &
export DISPLAY=$display
window=\$(xdotool search --sync --onlyvisible --name RefineID | head -n 1)
xdotool windowactivate --sync "\$window"
sleep 1
xdotool type --delay 120 "$1"
EOS
}

host_pairs() {
    host_sh <<'EOS'
refineid pairs 2>/dev/null
EOS
}

# The pairing identifiers the host lists.
pair_ids() {
    host_pairs | sed -n 's/^      Pair ID: *//p'
}

# The listing's entry, name line and certificate line joined, of `pair_id`.
entry_of() {
    host_pairs | awk -v id="$1" '
        /^  \[/ { name = $0; next }
        /Pair ID:/ { found = ($NF == id); next }
        found && /Cert cache:/ { print name " " $0; exit }'
}

# Waits until a pairing not in `known` exists whose entry matches `pattern`,
# and prints its identifier.
wait_for() {
    known=$1
    pattern=$2
    seconds=$3
    waited=0
    while [ "$waited" -lt "$seconds" ]; do
        for id in $(pair_ids); do
            case " $known " in *" $id "*) continue ;; esac
            if entry_of "$id" | grep -q "$pattern"; then
                printf '%s\n' "$id"
                return 0
            fi
        done
        sleep 3
        waited=$((waited + 3))
    done
    return 1
}

known=$(pair_ids | tr '\n' ' ')
say "asking the phone for a code"
phone_offer
code=$(cat "$work/code")
say "code shown; typing it into the host's boxes"
host_type_code "$code"

say "waiting for the pairing on the host"
if ! new_id=$(wait_for "$known" '^  \[[0-9]*\] [^ ]* ([A-Za-z]*) ' "$pair_wait_seconds"); then
    say "FAIL: no usable pairing within ${pair_wait_seconds} s"
    host_pairs
    exit 1
fi
say "paired as $new_id; the phone serves again"
phone_serve

say "waiting for the certificate read through the phone"
if ! wait_for "$known" '^  \[[0-9]*\] [^ ]* ([A-Za-z]*) .*Cert cache: Cached' "$read_wait_seconds" > /dev/null; then
    say "FAIL: the certificate was not read within ${read_wait_seconds} s"
    host_pairs
    exit 1
fi
say "PASS"
host_pairs
