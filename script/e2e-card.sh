#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# End-to-end test against a real card in a real reader, with real PINs.
#
# Runs the installed `refineid` against the card in the reader: reads it,
# signs with PIN 1 and the authentication key, signs a document with PIN 2
# and the qualified key, and verifies the document. The PINs come from two
# files the holder creates, readable by the holder alone, and reach the
# CLI through standard input only: never a command line, never the
# environment, never this script's output.
#
# Usage:
#   script/e2e-card.sh [--pin-dir DIR] [--reader SUBSTR]
#
# DIR defaults to ${XDG_CONFIG_HOME:-$HOME/.config}/refineid and must hold
# `test-pin1` and `test-pin2`, each one line, mode 0600. Prints one line
# per step with `ok` or `FAIL` and exits non-zero on the first failure.
# Every step that spends a PIN try runs once; the retry floor in the CLI
# refuses the attempt if the card reports two or fewer tries left.

set -eu

pin_dir="${XDG_CONFIG_HOME:-$HOME/.config}/refineid"
reader=""
while [ $# -gt 0 ]; do
    case "$1" in
        --pin-dir) pin_dir="$2"; shift 2 ;;
        --reader) reader="$2"; shift 2 ;;
        *) echo "usage: $0 [--pin-dir DIR] [--reader SUBSTR]" >&2; exit 2 ;;
    esac
done

pin1="$pin_dir/test-pin1"
pin2="$pin_dir/test-pin2"
for f in "$pin1" "$pin2"; do
    if [ ! -f "$f" ]; then
        echo "missing PIN file: $f (one line, mode 0600, created by the holder)" >&2
        exit 2
    fi
    case "$(stat -c %a "$f" 2>/dev/null || stat -f %Lp "$f")" in
        600) ;;
        *) echo "refusing $f: mode must be 0600" >&2; exit 2 ;;
    esac
done

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

# 1. Read the card: certificates, revocation, counters. No PIN.
# shellcheck disable=SC2086
step "card read" refineid card $reader_arg

# 2. PIN 1: raw signature with the authentication key, verified by the CLI
#    against the on-card certificate. The PIN file is the command's
#    standard input; the CLI reads one line from it when stdin is not a
#    terminal.
sign_auth() {
    # shellcheck disable=SC2086
    refineid card sign-auth --in "$1" --out "$2" --save-cert "$3" $reader_arg <"$pin1"
}
sign_document() {
    # shellcheck disable=SC2086
    refineid document sign "$1" --out "$2" $reader_arg <"$pin2"
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
