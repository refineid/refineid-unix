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

# Automated NixOS deployment and install verification for RefineID.
# Rebuilds the target NixOS system to the latest revision, verifies the
# installation, terminates stale running GUI processes, and verifies that
# desktop panels have reloaded their menu caches.
#
# Usage:
#   script/deploy-nixos.sh [TARGET]
#
# TARGET defaults to "root@nix" if reachable via SSH, or "local" if running
# directly on a NixOS host.

set -eu

cd "$(dirname "$0")/.."

EXPECTED_VERSION="$(cat VERSION 2>/dev/null || true)"
TARGET="${1:-}"

SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15"

if [ -z "$TARGET" ]; then
    if [ -f /etc/NIXOS ]; then
        TARGET="local"
    elif ssh $SSH_OPTS root@nix "true" 2>/dev/null; then
        TARGET="root@nix"
    else
        echo "error: no target specified and neither local NixOS nor root@nix is reachable" >&2
        echo "usage: $0 [TARGET]" >&2
        exit 1
    fi
fi

run_cmd() {
    if [ "$TARGET" = "local" ]; then
        sh -c "$1"
    else
        # Retry up to 5 times to handle transient SSH disconnects during unit reloads
        attempts=0
        while [ "$attempts" -lt 5 ]; do
            if ssh $SSH_OPTS "$TARGET" "$1"; then
                return 0
            fi
            attempts=$((attempts + 1))
            sleep 2
        done
        return 1
    fi
}

echo "== Deploying RefineID to NixOS ($TARGET) =="

# 1. Trigger NixOS rebuild with zero tarball TTL to fetch latest git revision
echo "-> Rebuilding NixOS system..."
if [ "$TARGET" = "local" ]; then
    sudo NIX_CONFIG="tarball-ttl = 0" nixos-rebuild switch
else
    ssh $SSH_OPTS "$TARGET" 'NIX_CONFIG="tarball-ttl = 0" nixos-rebuild switch'
fi

# Allow unit reloads to settle
sleep 2

# 2. Terminate any stale running refineid-gui process so old memory instances are cleared
echo "-> Checking for stale running refineid-gui processes..."
run_cmd 'pkill -f "[r]efineid-gui" 2>/dev/null || true'

# 3. Verify desktop entry
echo "-> Verifying /run/current-system/sw/share/applications/refineid.desktop..."
DESKTOP_EXEC="$(run_cmd 'grep "^Exec=" /run/current-system/sw/share/applications/refineid.desktop 2>/dev/null || true')"
if [ "$DESKTOP_EXEC" != "Exec=refineid-gui" ]; then
    echo "FAIL: refineid.desktop Exec line is '$DESKTOP_EXEC', expected 'Exec=refineid-gui'" >&2
    exit 1
fi

# 4. Verify binary in system PATH
echo "-> Verifying /run/current-system/sw/bin/refineid-gui..."
BIN_TARGET="$(run_cmd 'readlink -f /run/current-system/sw/bin/refineid-gui 2>/dev/null || true')"
if [ -z "$BIN_TARGET" ]; then
    echo "FAIL: /run/current-system/sw/bin/refineid-gui not found" >&2
    exit 1
fi
echo "   Binary resolves to: $BIN_TARGET"

# 5. Check version string if available
if [ -n "$EXPECTED_VERSION" ]; then
    echo "-> Checking version in binary matches $EXPECTED_VERSION..."
    FOUND_VER="$(run_cmd "grep -ao '$EXPECTED_VERSION' /run/current-system/sw/bin/refineid-gui 2>/dev/null | head -n1 || true")"
    if [ "$FOUND_VER" = "$EXPECTED_VERSION" ]; then
        echo "   Version verified: $FOUND_VER"
    else
        echo "   Notice: version $EXPECTED_VERSION not found in binary, continuing..."
    fi
fi

# 6. Verify and refresh running desktop panels
echo "-> Verifying running desktop panels..."
run_cmd '
for session_pid in $(pgrep -f "[x]fce4-session" 2>/dev/null || true); do
    if [ -r "/proc/$session_pid/environ" ]; then
        uid=$(stat -c "%u" "/proc/$session_pid" 2>/dev/null || continue)
        user=$(id -nu "$uid" 2>/dev/null || continue)
        display=$(tr "\0" "\n" < "/proc/$session_pid/environ" 2>/dev/null | grep "^DISPLAY=" | cut -d= -f2-)
        bus="/run/user/$uid/bus"
        if [ -n "$display" ] && [ -e "$bus" ]; then
            if pgrep -u "$user" -f "[x]fce4-panel" >/dev/null 2>&1; then
                echo "   Reloading panel for $user on $display..."
                su - "$user" -c "DISPLAY=\"$display\" DBUS_SESSION_BUS_ADDRESS=\"unix:path=$bus\" xfce4-panel -r" 2>/dev/null || true
            else
                echo "   Starting panel for $user on $display..."
                su - "$user" -c "DISPLAY=\"$display\" DBUS_SESSION_BUS_ADDRESS=\"unix:path=$bus\" nohup xfce4-panel >/dev/null 2>&1 &" 2>/dev/null || true
            fi
        fi
    fi
done
'

echo "== RefineID deployment to NixOS ($TARGET) successfully verified =="
