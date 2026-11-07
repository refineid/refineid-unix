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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

# Print the project version YY.M.D.B: the workspace version YY.M.D from
# Cargo.toml and the build number B, the UTC time of day as hour * 100 +
# minute with no leading zeros (7 at 00:07, 2105 at 21:05). B is
# REFINEID_BUILD_NUMBER when set, else the clock, as in
# crates/refineid-lib-core/build.rs; a build that exports the number it
# printed gives the binaries the same B. --day prints YY.M.D alone.
#
# Usage: script/version.sh [--day]

set -eu
cd "$(dirname "$0")/.."

day="$(sed -n 's/^version = "\([0-9.]*\)"$/\1/p' Cargo.toml | head -n 1)"
[ -n "$day" ] || { echo "version: no workspace version in Cargo.toml" >&2; exit 1; }

case "${1:-}" in
    --day) printf '%s\n' "$day"; exit 0 ;;
    '') ;;
    *) echo "usage: script/version.sh [--day]" >&2; exit 1 ;;
esac

if [ -n "${REFINEID_BUILD_NUMBER+set}" ]; then
    number="$REFINEID_BUILD_NUMBER"
else
    number="$(date -u '+%H%M' | sed 's/^0*\(.\)/\1/')"
fi
case "$number" in
    ''|*[!0-9]*|0?*) valid=0 ;;
    *) valid=1 ;;
esac
if [ "$valid" -eq 0 ] || [ "${#number}" -gt 4 ] || [ "$number" -gt 2359 ] \
    || [ $((number % 100)) -ge 60 ]; then
    echo "version: REFINEID_BUILD_NUMBER=$number is not hour * 100 + minute" >&2
    exit 1
fi
printf '%s.%s\n' "$day" "$number"
