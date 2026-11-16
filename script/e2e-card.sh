#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# End-to-end test against a real card in a real reader, with real PINs.
#
# Runs the installed `refineid` against the card in the reader: reads it,
# signs with PIN 1 and the authentication key, signs a document with PIN 2
# and the qualified key, and verifies the document. The PINs come from the
# holder's keyring or two mode-0600 files the holder creates, and reach the
# CLI through standard input only: never a command line, never the
# environment, never this script's output.
#
# Usage:
#   script/e2e-card.sh [--pin-dir DIR] [--reader SUBSTR]
#
# The PINs come from the holder's keyring by default:
# - On macOS, the login Keychain items `refineid` / `test-pin1` and
#   `test-pin2`, stored once by the holder with
#     security add-generic-password -U -s refineid -a test-pin1 -l 'RefineID test PIN 1' -w
#     security add-generic-password -U -s refineid -a test-pin2 -l 'RefineID test PIN 2' -w
# - On Secret Service desktops (Linux, *BSD), the items
#   `refineid test-pin1` and `refineid test-pin2`, stored once with
#     secret-tool store --label 'RefineID test PIN 1' refineid test-pin1
#     secret-tool store --label 'RefineID test PIN 2' refineid test-pin2
#   Over SSH the script reaches the desktop session's keyring through the
#   user's session bus.
# Each command prompts for the digits; nothing goes on the command line.
# With --pin-dir DIR, for UNIX hosts without a keyring, DIR must hold
# `test-pin1` and `test-pin2`, each one line, regular file, mode 0600.
#
# Prints one line per step with `ok` or `FAIL` and exits non-zero on the
# first failure. Every step that spends a PIN try runs once; the retry
# floor in the CLI refuses the attempt if the card reports two or fewer
# tries left. No PIN ever appears in a command line, the environment or
# this script's output.

set -eu

pin_dir=""
reader=""
while [ $# -gt 0 ]; do
    case "$1" in
        --pin-dir) pin_dir="$2"; shift 2 ;;
        --reader) reader="$2"; shift 2 ;;
        *) echo "usage: $0 [--pin-dir DIR] [--reader SUBSTR]" >&2; exit 2 ;;
    esac
done

# pin_source NAME writes the PIN named NAME (test-pin1 or test-pin2) to
# standard output, from the keyring or from the file directory.
pin_source() {
    if [ -n "$pin_dir" ]; then
        pin_f="$pin_dir/$1"
        case "$pin_f" in
            -*) pin_f="./$pin_f" ;;
        esac
        if [ ! -f "$pin_f" ]; then
            echo "missing PIN file: $pin_f (one line, mode 0600, created by the holder)" >&2
            return 2
        fi
        # IEEE Std 1003.1 ls -ld: regular file (-), owner rw only (rw-------);
        # allow SELinux (.) and macOS xattr (@) column-11 markers, reject +.
        # On macOS @ masks + in column 11, so find -acl checks extended ACLs.
        case "$(LC_ALL=C ls -ld "$pin_f")" in
            -rw-------[[:space:].@]*) ;;
            *) echo "refusing $pin_f: must be a regular file with mode 0600 and no ACL" >&2; return 2 ;;
        esac
        if [ "$(uname -s)" = "Darwin" ] && [ -n "$(find "$pin_f" -maxdepth 0 -acl)" ]; then
            echo "refusing $pin_f: must be a regular file with mode 0600 and no ACL" >&2
            return 2
        fi
        cat "$pin_f"
        return
    fi
    if [ "$(uname -s)" = "Darwin" ]; then
        pin_rc=0
        security find-generic-password -w -s refineid -a "$1" || pin_rc=$?
        if [ "$pin_rc" -eq 44 ]; then
            echo "Keychain item 'refineid' / '$1' not found; store it with:" >&2
            echo "  security add-generic-password -U -s refineid -a $1 -w" >&2
            echo "or use --pin-dir DIR" >&2
            return 2
        fi
        return "$pin_rc"
    fi
    if ! command -v secret-tool >/dev/null 2>&1; then
        echo "secret-tool not found: install libsecret-tools, or use --pin-dir DIR" >&2
        return 2
    fi
    if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
        pin_uid="$(id -u)"
        for pin_bus_dir in "${XDG_RUNTIME_DIR:-}" "/run/user/$pin_uid" "/var/run/user/$pin_uid"; do
            if [ -n "$pin_bus_dir" ] && [ -S "$pin_bus_dir/bus" ]; then
                DBUS_SESSION_BUS_ADDRESS="unix:path=$pin_bus_dir/bus"
                export DBUS_SESSION_BUS_ADDRESS
                break
            fi
        done
    fi
    if ! secret-tool lookup refineid "$1"; then
        echo "Secret Service item 'refineid $1' not found; store it with:" >&2
        echo "  secret-tool store --label 'RefineID test PIN' refineid $1" >&2
        echo "or use --pin-dir DIR" >&2
        return 2
    fi
}

reader_arg=""
if [ -n "$reader" ]; then
    reader_arg="--reader $reader"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

step() {
    name="$1"; shift
    if "$@" >"$work/step.out" 2>&1; then
        echo "ok    $name"
    else
        echo "FAIL  $name"
        sed 's/^/      /' "$work/step.out"
        exit 1
    fi
}

# 1. Read the card: certificates, revocation, counters. No PIN or CAN.
# shellcheck disable=SC2086
step "card read" refineid card --no-can $reader_arg

# 2. PIN 1: raw signature with the authentication key, verified by the CLI
#    against the on-card certificate. The PIN reaches the CLI as its
#    standard input; the CLI reads one line when stdin is not a terminal.
sign_auth() {
    # shellcheck disable=SC2086
    pin_source test-pin1 | refineid card sign-auth --in "$1" --out "$2" --save-cert "$3" $reader_arg
}
sign_document() {
    # shellcheck disable=SC2086
    pin_source test-pin2 | refineid document sign "$1" --out "$2" $reader_arg
}

printf 'refineid end-to-end %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$work/message"
step "PIN 1 authentication signature" sign_auth "$work/message" "$work/auth.sig" "$work/auth.der"
step "authentication signature present" test -s "$work/auth.sig"
step "authentication certificate saved" test -s "$work/auth.der"

# 3. PIN 2: a PAdES signature on a one-page PDF written here, with a
#    correct cross-reference table, so the test carries no fixture.
write_pdf() {
    o1='<</Type/Catalog/Pages 2 0 R>>'
    o2='<</Type/Pages/Kids[3 0 R]/Count 1>>'
    o3='<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 100]>>'
    head='%PDF-1.4
'
    b1="1 0 obj
$o1
endobj
"
    b2="2 0 obj
$o2
endobj
"
    b3="3 0 obj
$o3
endobj
"
    off1=$(printf '%s' "$head" | wc -c)
    off2=$(printf '%s%s' "$head" "$b1" | wc -c)
    off3=$(printf '%s%s%s' "$head" "$b1" "$b2" | wc -c)
    xref=$(printf '%s%s%s%s' "$head" "$b1" "$b2" "$b3" | wc -c)
    {
        printf '%s%s%s%s' "$head" "$b1" "$b2" "$b3"
        printf 'xref\n0 4\n0000000000 65535 f \n'
        printf '%010d 00000 n \n%010d 00000 n \n%010d 00000 n \n' "$off1" "$off2" "$off3"
        printf 'trailer\n<</Size 4/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n' "$xref"
    } >"$1"
}
write_pdf "$work/doc.pdf"
step "PIN 2 document signature" sign_document "$work/doc.pdf" "$work/doc-signed.pdf"
step "signed document present" test -s "$work/doc-signed.pdf"
step "document verifies" refineid document verify "$work/doc-signed.pdf"
sed 's/^/      /' "$work/step.out" | grep -v -i -E "signer:" || true

echo "all steps passed"
