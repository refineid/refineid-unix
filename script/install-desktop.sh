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

# Install the RefineID desktop GUI outside of .deb packaging: binary,
# freedesktop launcher, icon, and the browser setup that makes Firefox and
# Chromium offer the card for every user without touching either browser:
# a Firefox enterprise policy naming the PKCS#11 module, and a desktop
# autostart entry that gives each signed-in user's NSS database the module.
#
# Usage:
#   script/install-desktop.sh [--prefix /usr/local] [--openbox-menu]
#
# --openbox-menu also adds a "RefineID" item under Applications/Accessories
# in Openbox. Openbox ships a fully static example menu, so this creates a
# user-level override at ~/.config/openbox/menu.xml (package files are left
# untouched) and reconfigures a running Openbox when DISPLAY is set.
#
# Environment:
#   BIN      path to the built GUI binary (default: target/release/refineid-gui)
#   DESTDIR  staging root, empty for a live install

set -eu

cd "$(dirname "$0")/.."

PREFIX="/usr/local"
OPENBOX_MENU=0

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --openbox-menu) OPENBOX_MENU=1; shift ;;
        *) echo "usage: $0 [--prefix DIR] [--openbox-menu]" >&2; exit 2 ;;
    esac
done

BIN="${BIN:-target/release/refineid-gui}"
DESTDIR="${DESTDIR:-}"

if [ ! -x "$BIN" ]; then
    echo "error: GUI binary not found or not executable: $BIN" >&2
    echo "build it first: cargo build --release -p refineid-gui" >&2
    exit 1
fi

install -d \
    "$DESTDIR$PREFIX/bin" \
    "$DESTDIR$PREFIX/share/applications" \
    "$DESTDIR$PREFIX/share/icons/hicolor/scalable/apps"

install -m 755 "$BIN" "$DESTDIR$PREFIX/bin/refineid-gui"
install -m 644 packaging/refineid.desktop \
    "$DESTDIR$PREFIX/share/applications/refineid.desktop"
install -m 644 crates/refineid-gui/assets/app-icon.svg \
    "$DESTDIR$PREFIX/share/icons/hicolor/scalable/apps/refineid.svg"
# Menus that do not rasterise SVG take the sizes the icon theme names.
if command -v rsvg-convert >/dev/null 2>&1; then
    for size in 16 22 24 32 48 64 128 256; do
        sized="$DESTDIR$PREFIX/share/icons/hicolor/${size}x${size}/apps"
        install -d "$sized"
        rsvg-convert -w "$size" -h "$size" -o "$sized/refineid.png" \
            crates/refineid-gui/assets/app-icon.svg
    done
fi

# Browsers. Firefox reads a system policy, so every profile of every user
# loads the module; the policy goes where this Firefox looks for it.
# Chromium reads the user's NSS database only, so an autostart entry
# gives it the module at each desktop login.
MODULE="$PREFIX/lib/refineid/librefineid_pkcs11.so"
if [ -d "$DESTDIR$PREFIX/lib/firefox" ]; then
    POLICY_DIR="$DESTDIR$PREFIX/lib/firefox/distribution"
else
    POLICY_DIR="$DESTDIR/etc/firefox/policies"
fi
if [ -d "$DESTDIR$PREFIX/etc/xdg" ]; then
    AUTOSTART_DIR="$DESTDIR$PREFIX/etc/xdg/autostart"
else
    AUTOSTART_DIR="$DESTDIR/etc/xdg/autostart"
fi
install -d "$POLICY_DIR" "$DESTDIR$PREFIX/libexec/refineid" "$AUTOSTART_DIR"
printf '{ "policies": { "SecurityDevices": { "RefineID": "%s" } } }\n' "$MODULE" \
    > "$POLICY_DIR/policies.json"
sed "s|@MODULE@|$MODULE|" packaging/refineid-browser-token \
    > "$DESTDIR$PREFIX/libexec/refineid/refineid-browser-token"
chmod 755 "$DESTDIR$PREFIX/libexec/refineid/refineid-browser-token"
sed "s|@EXEC@|$PREFIX/libexec/refineid/refineid-browser-token|" \
    packaging/refineid-browser-token.desktop \
    > "$AUTOSTART_DIR/refineid-browser-token.desktop"

# Slint's font stack (fontique) finds no system fonts on NetBSD, so the GUI
# aborts in font fallback unless told where a default font lives. When the
# NetBSD base fonts are present, wrap the launch command accordingly; the
# variables are ignored anywhere else, and a missing file is skipped, so
# this is a no-op on systems with working font discovery.
GUI_EXEC="$DESTDIR$PREFIX/bin/refineid-gui"
if [ -f /usr/X11R7/lib/X11/fonts/TTF/LiberationSans-Regular.ttf ]; then
    GUI_EXEC="env SLINT_DEFAULT_FONT=/usr/X11R7/lib/X11/fonts/TTF/LiberationSans-Regular.ttf SLINT_FONT_PATH=/usr/X11R7/lib/X11/fonts/TTF $GUI_EXEC"
    if [ -z "$DESTDIR" ]; then
        sed "s|^Exec=.*|Exec=$GUI_EXEC|" \
            "$DESTDIR$PREFIX/share/applications/refineid.desktop" \
            > "$DESTDIR$PREFIX/share/applications/refineid.desktop.new" \
            && mv "$DESTDIR$PREFIX/share/applications/refineid.desktop.new" \
                   "$DESTDIR$PREFIX/share/applications/refineid.desktop"
    fi
fi

if [ -z "$DESTDIR" ]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q "$PREFIX/share/applications" || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f "$PREFIX/share/icons/hicolor" || true
    fi

    # Refresh running XFCE panels so in-memory menu caches pick up changes immediately.
    for session_pid in $(pgrep -f '[x]fce4-session' 2>/dev/null || true); do
        if [ -r "/proc/$session_pid/environ" ]; then
            uid=$(stat -c '%u' "/proc/$session_pid" 2>/dev/null || continue)
            user=$(id -nu "$uid" 2>/dev/null || continue)
            display=$(tr '\0' '\n' < "/proc/$session_pid/environ" 2>/dev/null | grep '^DISPLAY=' | cut -d= -f2-)
            bus="/run/user/$uid/bus"
            if [ -n "$display" ] && [ -e "$bus" ]; then
                cmd="pkill -u '$user' -x xfce4-panel 2>/dev/null || true; sleep 1; nohup xfce4-panel >/dev/null 2>&1 &"
                if [ "$(id -u)" -eq 0 ] && [ "$uid" -ne 0 ]; then
                    su - "$user" -c "DISPLAY='$display' DBUS_SESSION_BUS_ADDRESS='unix:path=$bus' $cmd" 2>/dev/null || true
                elif [ "$uid" -eq "$(id -u)" ]; then
                    DISPLAY="$display" DBUS_SESSION_BUS_ADDRESS="unix:path=$bus" sh -c "$cmd" 2>/dev/null || true
                fi
            fi
        fi
    done
fi

if [ "$OPENBOX_MENU" -eq 1 ]; then
    MENU_HOME="${HOME:-/root}/.config/openbox/menu.xml"
    if [ ! -f "$MENU_HOME" ]; then
        SRC=""
        for d in "$PREFIX/etc/xdg/openbox" /usr/pkg/etc/xdg/openbox \
                 /etc/xdg/openbox /usr/local/etc/xdg/openbox; do
            if [ -f "$d/menu.xml" ]; then SRC="$d/menu.xml"; break; fi
        done
        if [ -z "$SRC" ]; then
            echo "error: no system openbox menu.xml found" >&2
            exit 1
        fi
        install -d "$(dirname "$MENU_HOME")"
        cp "$SRC" "$MENU_HOME"
    fi
    if grep -q 'label="RefineID"' "$MENU_HOME"; then
        sed "/label=\"RefineID\"/,/<\/item>/ s|<command>.*</command>|<command>$GUI_EXEC</command>|" \
            "$MENU_HOME" > "$MENU_HOME.new" \
            && mv "$MENU_HOME.new" "$MENU_HOME"
        echo "menu: RefineID command refreshed in $MENU_HOME"
    else
        awk '/^<\/menu>$/ && !done {
                 print "  <item label=\"RefineID\">"
                 print "    <action name=\"Execute\">"
                 print "      <command>'"$GUI_EXEC"'</command>"
                 print "      <startupnotify>"
                 print "        <enabled>yes</enabled>"
                 print "      </startupnotify>"
                 print "    </action>"
                 print "  </item>"
                 done=1
             } {print}' "$MENU_HOME" > "$MENU_HOME.new" \
            && mv "$MENU_HOME.new" "$MENU_HOME"
        echo "menu: RefineID added under Accessories in $MENU_HOME"
    fi
    if [ -n "${DISPLAY:-}" ] && command -v openbox >/dev/null 2>&1; then
        openbox --reconfigure 2>/dev/null || true
    else
        echo "menu: set DISPLAY and run 'openbox --reconfigure' to reload"
    fi
fi

echo "installed refineid-gui to $DESTDIR$PREFIX/bin/refineid-gui"
