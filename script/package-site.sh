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

# Write the front page of the package site: the install commands for each
# repository, taken from doc/packages.md so that there is one copy of them,
# and the newest version each repository holds. An empty repository is an
# error: the page never publishes without packages behind it.
#
# Usage: script/package-site.sh <site-dir>

set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 <site-dir>" >&2; exit 2; }
SITE="$1"
DOC="$(dirname "$0")/../doc/packages.md"
[ -d "$SITE" ] || { echo "error: no site directory $SITE" >&2; exit 1; }
[ -f "$DOC" ] || { echo "error: no $DOC" >&2; exit 1; }

# The first ```sh block after the given heading.
commands() {
    awk -v heading="$1" '
        $0 == heading { in_section = 1; next }
        in_section && /^#/ { exit }
        in_section && /^```sh$/ { in_block = 1; next }
        in_block && /^```$/ { exit }
        in_block { print }
    ' "$DOC"
}

escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

newest() {
    # Versions sort by the day fields then the build number.
    printf '%s\n' "$@" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | tail -n 1
}

ubuntu_version() {
    set -- "$SITE"/ubuntu/pool/main/r/refineid/refineid_*_arm64.deb \
           "$SITE"/ubuntu/pool/main/r/refineid/refineid_*_amd64.deb
    versions=""
    for deb; do
        [ -f "$deb" ] || continue
        v="${deb##*/refineid_}"
        versions="$versions ${v%_*.deb}"
    done
    [ -n "$versions" ] || { echo "error: no refineid .deb under $SITE/ubuntu" >&2; exit 1; }
    # shellcheck disable=SC2086
    newest $versions
}

freebsd_version() {
    versions=""
    for pkg in "$SITE"/freebsd/*/All/refineid-*.pkg; do
        [ -f "$pkg" ] || continue
        v="${pkg##*/refineid-}"
        versions="$versions ${v%.pkg}"
    done
    [ -n "$versions" ] || { echo "error: no refineid .pkg under $SITE/freebsd" >&2; exit 1; }
    # shellcheck disable=SC2086
    newest $versions
}

ubuntu_commands="$(commands '### Ubuntu 26.04' | escape)"
freebsd_commands="$(commands '### FreeBSD 15' | escape)"
[ -n "$ubuntu_commands" ] || { echo "error: no Ubuntu commands in $DOC" >&2; exit 1; }
[ -n "$freebsd_commands" ] || { echo "error: no FreeBSD commands in $DOC" >&2; exit 1; }
ubuntu_newest="$(ubuntu_version | escape)"
freebsd_newest="$(freebsd_version | escape)"

cat > "$SITE/index.html" <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RefineID packages</title>
<style>
body { font: 16px/1.5 system-ui, sans-serif; max-width: 44rem; margin: 2rem auto; padding: 0 1rem; color: #222; background: #fff; }
pre { background: #f4f4f4; padding: 0.75rem 1rem; overflow-x: auto; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.15rem; margin-top: 2rem; }
@media (prefers-color-scheme: dark) { body { color: #ddd; background: #111; } pre { background: #1e1e1e; } }
</style>
</head>
<body>
<h1>RefineID packages</h1>
<p>Signed package repositories for the RefineID smart card software on Ubuntu and FreeBSD. Source, issues and the full installation notes are at <a href="https://github.com/refineid/refineid-unix">github.com/refineid/refineid-unix</a>.</p>
<h2>Ubuntu 26.04</h2>
<p>Newest version: $ubuntu_newest</p>
<pre>$ubuntu_commands</pre>
<p>Key: <a href="ubuntu/refineid.asc">ubuntu/refineid.asc</a>.</p>
<h2>FreeBSD 15</h2>
<p>Newest version: $freebsd_newest</p>
<p>As root:</p>
<pre>$freebsd_commands</pre>
<p>Key: <a href="freebsd/refineid.pub">freebsd/refineid.pub</a>.</p>
</body>
</html>
HTML
echo "wrote $SITE/index.html"
