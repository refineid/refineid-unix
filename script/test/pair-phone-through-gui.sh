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
offer_pid=
trap 'kill "${offer_pid:-}" 2>/dev/null; rm -rf "$work"' EXIT

say() { printf '%s %s\n' "$(date -u '+%H:%M:%S')" "$*"; }

# Launches the phone in the mode that prints its code and writes the
# code to $work/code; the launch keeps running until the ceremony ends.
phone_offer() {
    : > "$work/offer.log"
    xcrun devicectl device process launch --device "$udid" --console \
        --terminate-existing "$bundle" --offer-remote-reader \
        < /dev/null > "$work/offer.log" 2>&1 &
    offer_pid=$!
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

# Opens the host's window on the Phone tab and types the code; fails
# when the old window does not go or the new one does not come.
host_type_code() {
    host_sh <<EOS
export DISPLAY=$display
pkill -x refineid-gui >/dev/null 2>&1 || true
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    xdotool search --onlyvisible --name RefineID >/dev/null 2>&1 || break
    sleep 1
done
cd "\$HOME" && nohup refineid-gui --pair > /dev/null 2>&1 &
window=
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    window=\$(xdotool search --onlyvisible --name RefineID 2>/dev/null | head -n 1)
    [ -n "\$window" ] && break
    sleep 1
done
[ -n "\$window" ] || { echo "no RefineID window on $display" >&2; exit 1; }
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

# The pairing identifiers in a listing.
pair_ids() {
    sed -n 's/^      Pair ID: *//p'
}

# The listing's entry of `pair_id` as one line: its name line and its
# certificate line.
entry_of() {
    awk -v id="$1" '
        /^  \[/ { name = $0; next }
        /Pair ID:/ { found = ($NF == id); next }
        found && /Cert cache:/ { print name " " $0; exit }'
}

# Waits until a pairing not in `known` exists whose entry matches
# `wanted` and not `unwanted`, and prints its identifier.
wait_for() {
    known=$1
    wanted=$2
    unwanted=$3
    seconds=$4
    waited=0
    while [ "$waited" -lt "$seconds" ]; do
        host_pairs > "$work/listing"
        for id in $(pair_ids < "$work/listing"); do
            case " $known " in *" $id "*) continue ;; esac
            if entry_of "$id" < "$work/listing" | grep -q "$wanted" \
                && ! entry_of "$id" < "$work/listing" | grep -q "$unwanted"; then
                printf '%s\n' "$id"
                return 0
            fi
        done
        sleep 3
        waited=$((waited + 3))
    done
    return 1
}

known=$(host_pairs | pair_ids | tr '\n' ' ')
say "asking the phone for a code"
phone_offer
code=$(cat "$work/code")
say "code shown; typing it into the host's boxes"
host_type_code "$code"

say "waiting for the pairing on the host"
if ! new_id=$(wait_for "$known" '^  \[[0-9]*\] ' ' -- ' "$pair_wait_seconds"); then
    say "FAIL: no usable pairing within ${pair_wait_seconds} s"
    host_pairs
    exit 1
fi
say "paired as $new_id; the phone serves again"
phone_serve

say "waiting for the certificate read through the phone"
if ! wait_for "$known" 'Cert cache: Cached' ' -- ' "$read_wait_seconds" > /dev/null; then
    say "FAIL: the certificate was not read within ${read_wait_seconds} s"
    host_pairs
    exit 1
fi
say "PASS"
host_pairs || true
exit 0
