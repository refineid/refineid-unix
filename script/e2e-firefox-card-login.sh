#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# End-to-end browser test: a card login to a TLS client-authenticated
# site in Firefox on the holder's own GNOME desktop, driven by reading
# the accessibility tree, never by timing. Each look at the screen is a
# fresh process over AT-SPI (script/e2e-firefox-a11y.py); nothing is
# typed until the password field reports keyboard focus; PIN 1 comes
# from the holder's keyring (`secret-tool store refineid test-pin1`)
# and reaches the field through a virtual keyboard (ydotool). Frames
# are captured with GNOME's own whole-screen shortcut every 1.5 s and
# assembled into an mp4 beside the run.
#
# Usage: script/e2e-firefox-card-login.sh [URL] [TITLE]
#   URL    the site; default https://card.refineid.fi/
#   TITLE  text the logged-in page's title must contain;
#          default "Card-authenticated guestbook"
# Needs: a GNOME Wayland session of the same user, python3-pyatspi,
# ydotool with its daemon on $YDOTOOL_SOCKET, libsecret-tools, ffmpeg,
# the Firefox policy that loads the module, and
# org.gnome.desktop.interface toolkit-accessibility = true.
# Exit 0 on a completed login; frames and e2e-firefox-login.mp4 in $OUT.
# Every look at the screen is a fresh process reading the accessibility tree;
# nothing is typed until the password field reports keyboard focus.
uid=$(id -u)
export XDG_RUNTIME_DIR="/run/user/$uid" WAYLAND_DISPLAY=wayland-0 DISPLAY=:0
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$uid/bus}"
URL=${1:-https://card.refineid.fi/}; TITLE=${2:-Card-authenticated guestbook}
HERE=$(cd "$(dirname "$0")" && pwd)
ACT="python3 -I $HERE/e2e-firefox-a11y.py"
SHOTS=$(xdg-user-dir PICTURES 2>/dev/null || echo "$HOME/Pictures")
OUT=${OUT:-$(mktemp -d)}
# The module log must be where the Firefox snap can write: its confinement
# gives it a private /tmp, so the log lives under the snap's common data
# when that exists, else beside the run.
if [ -d "$HOME/snap/firefox/common" ]; then LOG=$HOME/snap/firefox/common/e2e-pkcs11.log; else LOG=$OUT/pkcs11.log; fi
export YDOTOOL_SOCKET="${YDOTOOL_SOCKET:-/tmp/.ydotool_socket}"
until_ok() { desc=$1; shift; i=0; while [ $i -lt 60 ]; do $ACT "$@"; rc=$?; [ $rc -eq 0 ] && { echo "ok    $desc (${i}x0.5s)"; return 0; }; [ $rc -eq 4 ] && { echo "FAIL  $desc"; return 1; }; sleep 0.5; i=$((i+1)); done; echo "TIMEOUT $desc"; return 1; }
umask 077
PIN=/dev/shm/refineid-pin-$$
 secret-tool lookup refineid test-pin1 > "$PIN" || { echo "no PIN"; exit 2; }
pkill -u "$uid" -x firefox 2>/dev/null; sleep 3
for P in "$HOME"/snap/firefox/common/.mozilla/firefox/*.default* "$HOME"/.mozilla/firefox/*.default*; do [ -d "$P" ] && rm -f "$P/ClientAuthRememberList.bin"; done; rm -f "$LOG"
mkdir -p "$OUT/frames"; MARK=$OUT/start; touch "$MARK"
( i=0; while [ $i -lt 30 ]; do ydotool key 42:1 99:1 99:0 42:0; sleep 1.5; i=$((i+1)); done ) & SHOOTER=$!
sleep 2; GNOME_ACCESSIBILITY=1 REFINEID_PKCS11_LOG=$LOG setsid firefox --new-window "about:blank" >/dev/null 2>&1 < /dev/null &
RC=1
if until_ok "firefox on the accessibility bus" page "" ; then
    firefox --new-window "$URL" >/dev/null 2>&1 &
fi
if until_ok "certificate prompt accepted" cert-ok && until_ok "password field focused" pin-focus; then
    ydotool type --file "$PIN"; rm -f "$PIN"
    # The field still has focus: Enter confirms the dialog. The named-button
    # path (pin-ok) is the fallback if Enter did not close it.
    ydotool key 28:1 28:0; sleep 2
    $ACT pin-focus >/dev/null 2>&1 && until_ok "password dialog confirmed" pin-ok
    if until_ok "logged-in page shown" page "$TITLE"; then RC=0; fi
fi
rm -f "$PIN"; wait $SHOOTER; sleep 2
n=0; find "$SHOTS" -name "*.png" -newer "$MARK" -print0 | xargs -0 ls -tr | while IFS= read -r f; do n=$((n+1)); cp "$f" "$OUT/frames/$(printf %03d "$n").png"; done
echo "frames: $(ls "$OUT/frames" | wc -l) in $OUT/frames"
ffmpeg -v error -y -framerate 1.5 -i "$OUT/frames/%03d.png" -vf "scale=1440:-2,format=yuv420p" -c:v libx264 -crf 28 "$OUT/e2e-firefox-login.mp4" && echo "video: $OUT/e2e-firefox-login.mp4"
echo "--- module log"; grep -o -E "C_(Login|Sign)[^,]*rv=[0-9a-fx]*" "$LOG" | sort | uniq -c | head -4
exit $RC
