#!/usr/bin/env bash
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

# Stamp the workspace version YY.M.D in Cargo.toml and Cargo.lock with
# the UTC day, so the version names the day the code last changed. The
# build number that completes the project version YY.M.D.B is taken at
# build time (crates/refineid-lib-core/build.rs) and never committed.
#
# Usage: script/version-stamp.sh

set -eu
cd "$(dirname "$0")/.."

today="$(date -u '+%y.%-m.%-d')"
old="$(script/version.sh)"

old_ifs=$IFS
IFS=.
set -- $today
IFS=$old_ifs
[ "$#" -eq 3 ] || { echo "version-stamp: invalid date stamp $today" >&2; exit 1; }
for component in "$@"; do
    case "$component" in
        ''|*[!0-9]*) echo "version-stamp: non-numeric component $component" >&2; exit 1 ;;
    esac
    [ "$component" -le 255 ] || {
        echo "version-stamp: component $component exceeds PKCS#11 byte range" >&2
        exit 1
    }
done

[ "$old" != "$today" ] || exit 0

awk -v version="$today" '
    /^version = "/ && !done { sub(/"[^"]*"/, "\"" version "\""); done=1 }
    { print }
' Cargo.toml > Cargo.toml.tmp.$$ && mv Cargo.toml.tmp.$$ Cargo.toml

awk -v old="$old" -v version="$today" '
    function flush_package(    i, line) {
        for (i = 0; i < count; i++) {
            line = lines[i]
            if (!has_source && line == "version = \"" old "\"") {
                line = "version = \"" version "\""
            }
            print line
        }
        in_package=0; count=0; has_source=0
    }
    /^\[\[package\]\]/ { in_package=1; count=0; has_source=0 }
    in_package {
        lines[count++] = $0
        if ($0 ~ /^source = /) has_source=1
        if ($0 == "") flush_package()
        next
    }
    { print }
    END { if (in_package) flush_package() }
' Cargo.lock > Cargo.lock.tmp.$$ && mv Cargo.lock.tmp.$$ Cargo.lock

printf 'version-stamp: %s -> %s\n' "$old" "$today"
