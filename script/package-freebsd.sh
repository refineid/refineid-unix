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

# Build the FreeBSD package target/freebsd/refineid-<VERSION>.pkg: the CLI
# and its manual page, the GUI, the PKCS#11 module with its p11-kit
# registration, the Firefox policy and the autostart entry that gives
# Chromium the module. The
# dependencies are pcsc-lite, libccid, p11-kit, nss, xdg-desktop-portal-gtk
# (the file chooser on a desktop whose portal has no FileChooser backend)
# and every package that provides a shared library the binaries link, at
# the versions installed on the build host. packaging/freebsd/+POST_INSTALL enables pcscd.
#
# Usage:
#   script/package-freebsd.sh [--skip-build]

set -eu
cd "$(dirname "$0")/.."

DO_BUILD=1
for arg in "$@"; do
    case "$arg" in
        --skip-build) DO_BUILD=0 ;;
        -h|--help) echo "Usage: $0 [--skip-build]"; exit 0 ;;
        *) echo "error: unknown argument: $arg" >&2; exit 1 ;;
    esac
done

if [ "$(uname -s)" != "FreeBSD" ]; then
    echo "error: FreeBSD packages are built on FreeBSD" >&2
    exit 1
fi

VERSION="$(script/version.sh)"

PREFIX="/usr/local"
RUNTIME_DEPS="pcsc-lite libccid p11-kit nss xdg-desktop-portal-gtk"
for name in $RUNTIME_DEPS; do
    pkg info -e "$name" || { echo "error: $name is not installed" >&2; exit 1; }
done

# FLTK's CMake finds linux/input.h from evdev-proto under /usr/local/include;
# crates/refineid-gui-fltk/build.rs links the libraries FLTK needs.
if [ "$DO_BUILD" -eq 1 ]; then
    CFLAGS="-I$PREFIX/include"
    CXXFLAGS="-I$PREFIX/include"
    CMAKE_INCLUDE_PATH="$PREFIX/include"
    export CFLAGS CXXFLAGS CMAKE_INCLUDE_PATH
    cargo build --release --workspace
fi

OUT="target/freebsd"
STAGE="$OUT/stage"
META="$OUT/meta"
rm -rf "$STAGE" "$META" "$OUT/refineid-$VERSION.pkg"
mkdir -p "$STAGE" "$META"

ROOT="$STAGE$PREFIX"
MODULE="$PREFIX/lib/refineid/librefineid_pkcs11.so"
TOKEN="$PREFIX/libexec/refineid/refineid-browser-token"

install -d \
    "$ROOT/bin" \
    "$ROOT/lib/refineid" \
    "$ROOT/lib/firefox/distribution" \
    "$ROOT/libexec/refineid" \
    "$ROOT/etc/xdg/autostart" \
    "$ROOT/share/p11-kit/modules" \
    "$ROOT/share/applications" \
    "$ROOT/share/icons/hicolor/scalable/apps" \
    "$ROOT/share/man/man1" \
    "$ROOT/share/zsh/site-functions"

install -m 755 target/release/refineid "$ROOT/bin/refineid"
gzip -9n < crates/refineid-client/man/refineid.1 > "$ROOT/share/man/man1/refineid.1.gz"
chmod 644 "$ROOT/share/man/man1/refineid.1.gz"
install -m 644 packaging/zsh/_refineid "$ROOT/share/zsh/site-functions/_refineid"
install -m 755 target/release/refineid-gui "$ROOT/bin/refineid-gui"
install -m 755 target/release/librefineid_pkcs11.so "$STAGE$MODULE"

printf 'module: %s\ncritical: no\ntrust-policy: no\n' "$MODULE" \
    > "$ROOT/share/p11-kit/modules/refineid.module"
printf '{ "policies": { "SecurityDevices": { "RefineID": "%s" } } }\n' "$MODULE" \
    > "$ROOT/lib/firefox/distribution/policies.json"
sed "s|@MODULE@|$MODULE|" packaging/refineid-browser-token > "$STAGE$TOKEN"
chmod 755 "$STAGE$TOKEN"
sed "s|@EXEC@|$TOKEN|" packaging/refineid-browser-token.desktop \
    > "$ROOT/etc/xdg/autostart/refineid-browser-token.desktop"
install -m 644 packaging/refineid.desktop "$ROOT/share/applications/refineid.desktop"
install -m 644 crates/refineid-gui/assets/app-icon.svg \
    "$ROOT/share/icons/hicolor/scalable/apps/refineid.svg"

# Every file belongs to root:wheel whoever runs the build.
(cd "$STAGE" && find . -type f | sort) | while read -r path; do
    path="${path#.}"
    mode="$(stat -f '%Lp' "$STAGE$path")"
    printf '@(root,wheel,%s) %s\n' "$mode" "$path"
done > "$META/plist"

# Dependencies: the named runtime packages and the owner of every
# non-base shared library the binaries load.
DEPS="$(
    echo "$RUNTIME_DEPS" | tr ' ' '\n'
    for binary in "$ROOT/bin/refineid" "$ROOT/bin/refineid-gui" "$STAGE$MODULE"; do
        ldd -f '%p\n' "$binary"
    done | grep "^$PREFIX/" | sort -u | while read -r library; do
        pkg which -q "$library"
    done | while read -r owner; do
        pkg query '%n' "$owner"
    done
)"

{
    sed "s|@VERSION@|$VERSION|" "packaging/freebsd/+MANIFEST.in"
    echo "deps: {"
    printf '%s\n' "$DEPS" | sort -u | while read -r name; do
        [ -n "$name" ] || continue
        pkg query '  "%n": { origin: "%o", version: "%v" }' "$name"
    done
    echo "}"
} > "$META/+MANIFEST"
install -m 755 packaging/freebsd/+POST_INSTALL "$META/+POST_INSTALL"

pkg create -m "$META" -p "$META/plist" -r "$STAGE" -o "$OUT"
rm -rf "$STAGE" "$META"

echo "built $OUT/refineid-$VERSION.pkg"
pkg info -F "$OUT/refineid-$VERSION.pkg" -d
