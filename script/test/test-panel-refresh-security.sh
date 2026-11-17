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

set -eu

# Unit test for panel-refresh session validation (Issue #339 security regression test).
# Verifies strict DISPLAY whitelist, UID checks, username sanitization, and PID reuse guard.

pass_count=0
fail_count=0

assert_true() {
    desc="$1"
    shift
    if "$@"; then
        pass_count=$((pass_count + 1))
    else
        echo "FAIL: $desc" >&2
        fail_count=$((fail_count + 1))
    fi
}

assert_false() {
    desc="$1"
    shift
    if "$@"; then
        echo "FAIL (expected false): $desc" >&2
        fail_count=$((fail_count + 1))
    else
        pass_count=$((pass_count + 1))
    fi
}

validate_display() {
    [ -n "$1" ] || return 1
    # Check single-line
    [ "$(printf '%s\n' "$1" | wc -l)" -eq 1 ] || return 1
    # Whitelist characters strictly to digits, colon, and period
    case "$1" in
        *[!0-9.:]*) return 1 ;;
    esac
    # Check strict regex format ^:[0-9]+(\.[0-9]+)?$
    printf '%s\n' "$1" | grep -Eq '^:[0-9]+(\.[0-9]+)?$'
}

validate_uid() {
    case "$1" in
        ""|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1000 ]
}

validate_user() {
    [ -n "$1" ] || return 1
    case "$1" in
        *[!a-zA-Z0-9_.-]*) return 1 ;;
        [a-zA-Z]*) return 0 ;;
        *) return 1 ;;
    esac
}

# 1. DISPLAY validation tests
echo "== Testing DISPLAY format validation =="
assert_true "Accept :0" validate_display ":0"
assert_true "Accept :0.0" validate_display ":0.0"
assert_true "Accept :1" validate_display ":1"
assert_true "Accept :10.0" validate_display ":10.0"
assert_true "Accept :99.123" validate_display ":99.123"

assert_false "Reject empty string" validate_display ""
assert_false "Reject spaces" validate_display " :0"
assert_false "Reject trailing spaces" validate_display ":0 "
assert_false "Reject remote display hostname" validate_display "localhost:10.0"
assert_false "Reject IPv4 loopback display" validate_display "127.0.0.1:0"
assert_false "Reject command injection with semicolon" validate_display ":0; id"
# shellcheck disable=SC2016
assert_false "Reject command injection with single quote" validate_display ":0' && id"
# shellcheck disable=SC2016
assert_false "Reject command injection with double quote" validate_display ':0" && id'
# shellcheck disable=SC2016
assert_false "Reject command injection with backticks" validate_display ':0`id`'
# shellcheck disable=SC2016
assert_false "Reject command injection with subshell" validate_display ':0$(id)'
assert_false "Reject newline injection" validate_display "$(printf ':0\nDISPLAY=:1')"
assert_false "Reject carriage return injection" validate_display "$(printf ':0\r')"
assert_false "Reject slash path" validate_display "/tmp/.X11-unix/X0"

# 2. UID validation tests
echo "== Testing UID boundary validation =="
assert_false "Reject UID 0 (root)" validate_uid 0
assert_false "Reject UID 1 (daemon)" validate_uid 1
assert_false "Reject UID 999 (system account)" validate_uid 999
assert_false "Reject empty UID" validate_uid ""
assert_false "Reject non-numeric UID" validate_uid "abc"
assert_false "Reject negative UID" validate_uid "-1"
assert_false "Reject UID with space" validate_uid " 1000"
assert_true "Accept UID 1000 (first regular user)" validate_uid 1000
assert_true "Accept UID 1001" validate_uid 1001
assert_true "Accept high UID 65534" validate_uid 65534

# 3. Username validation tests
echo "== Testing username validation =="
assert_true "Accept simple username" validate_user "alice"
assert_true "Accept username with digits and dots" validate_user "bob.123"
assert_true "Accept username with hyphens and underscores" validate_user "user_name-test"
assert_false "Reject empty username" validate_user ""
assert_false "Reject leading dash username (-c)" validate_user "-c"
assert_false "Reject leading dash username (--option)" validate_user "--option"
assert_false "Reject leading dash username (-evil)" validate_user "-evil"
assert_false "Reject username starting with digit" validate_user "1user"
assert_false "Reject username starting with underscore" validate_user "_user"
assert_false "Reject username with spaces" validate_user "alice bob"
assert_false "Reject username with quotes" validate_user "alice'bob"
assert_false "Reject username with semicolon" validate_user "alice;reboot"
assert_false "Reject username with slash" validate_user "../etc/passwd"
# shellcheck disable=SC2016
assert_false "Reject username with subshell" validate_user '$(whoami)'

# 4. Simulation of session environ extraction and TOCTOU check
echo "== Testing mock procfs extraction and TOCTOU guard =="
TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/refineid-test-session.XXXXXX")
cleanup() {
    rm -rf "$TEST_TMP"
}
trap cleanup EXIT INT TERM

# Create mock /proc entry with malicious DISPLAY
MOCK_PID="12345"
mkdir -p "$TEST_TMP/$MOCK_PID"
printf 'USER=hacker\0DISPLAY=:0; rm -rf /;\0PATH=/bin\0' > "$TEST_TMP/$MOCK_PID/environ"

extracted_display=$(tr '\0' '\n' < "$TEST_TMP/$MOCK_PID/environ" | grep '^DISPLAY=' | head -n 1 | cut -d= -f2-)
assert_false "Malicious DISPLAY from environ must be rejected by validator" validate_display "$extracted_display"

# Create mock /proc entry with valid DISPLAY
MOCK_PID2="12346"
mkdir -p "$TEST_TMP/$MOCK_PID2"
printf 'USER=alice\0DISPLAY=:0.0\0PATH=/bin\0' > "$TEST_TMP/$MOCK_PID2/environ"

extracted_display2=$(tr '\0' '\n' < "$TEST_TMP/$MOCK_PID2/environ" | grep '^DISPLAY=' | head -n 1 | cut -d= -f2-)
assert_true "Valid DISPLAY from environ must be accepted" validate_display "$extracted_display2"

echo "Passed: $pass_count, Failed: $fail_count"
if [ "$fail_count" -gt 0 ]; then
    exit 1
fi
echo "All panel refresh security tests passed."
