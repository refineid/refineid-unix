#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

"""AT-SPI2 / Dogtail GUI integration tests for RefineID.

Tests the live GTK 4 accessibility hierarchy without relying on hardcoded
screen coordinates or synthetic mouse clicks.

Prerequisites:
- at-spi2-core running on the active display.
- python3 with pyatspi and dogtail installed (or dogtail in PYTHONPATH).
"""

import glob
import os
import subprocess
import sys
import time

# Ensure dogtail can be imported
if "/home/pk/dogtail" not in sys.path and os.path.exists("/home/pk/dogtail"):
    sys.path.insert(0, "/home/pk/dogtail")

def setup_environment(display=":0"):
    """Prepare environment for AT-SPI2 communication with GTK 4."""
    env = os.environ.copy()
    env["DISPLAY"] = display
    env["GTK_A11Y"] = "atspi"

    # Search for D-Bus session bus address if not explicitly exported
    if "DBUS_SESSION_BUS_ADDRESS" not in env:
        bus_files = glob.glob(os.path.expanduser("~/.dbus/session-bus/*-0"))
        if bus_files:
            with open(bus_files[0]) as f:
                for line in f:
                    if line.startswith("DBUS_SESSION_BUS_ADDRESS="):
                        val = line.strip().split("=", 1)[1].strip("'\"")
                        env["DBUS_SESSION_BUS_ADDRESS"] = val
                        os.environ["DBUS_SESSION_BUS_ADDRESS"] = val
                        break

    # Standard XDG path for accessibility bus
    if "AT_SPI_BUS_ADDRESS" not in env:
        xdg_atspi = "/var/run/xdg/pk/at-spi/bus_0"
        if os.path.exists(xdg_atspi):
            env["AT_SPI_BUS_ADDRESS"] = f"unix:path={xdg_atspi}"
            os.environ["AT_SPI_BUS_ADDRESS"] = f"unix:path={xdg_atspi}"

    os.environ["DISPLAY"] = display
    os.environ["GTK_A11Y"] = "atspi"
    return env

def find_binary():
    """Locate refineid-gui binary to test."""
    if len(sys.argv) > 1:
        return sys.argv[1]
    candidates = [
        "target/release/refineid-gui",
        "target/debug/refineid-gui",
        os.path.expanduser("~/refineid-unix/target/release/refineid-gui"),
        "/usr/local/bin/refineid-gui",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return "refineid-gui"

def main():
    display = os.environ.get("DISPLAY", ":0")
    env = setup_environment(display)

    binary = find_binary()
    print(f"Launching GUI binary: {binary}")

    # Terminate any previously running instances
    subprocess.run(["pkill", "-f", "refineid-gui"], stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    proc = subprocess.Popen([binary], env=env)
    time.sleep(3.0)

    try:
        from dogtail.tree import root

        print("1. Locating application 'refineid-gui' in AT-SPI tree...")
        app = root.application("refineid-gui")
        assert app is not None, "Application node 'refineid-gui' not found"
        print(f"   Application node verified: {app.name}")

        print("2. Locating main window 'RefineID'...")
        win = app.child("RefineID", roleName="frame")
        assert win is not None, "Main window frame 'RefineID' not found"
        print(f"   Window frame verified: {win.name}")

        # Check standard widgets
        choose_btn = win.child("Choose…", roleName="button")
        assert choose_btn is not None, "'Choose…' button not found"
        print("   'Choose…' button verified")

        pair_btn = win.child("Pair Phone", roleName="button")
        assert pair_btn is not None, "'Pair Phone' button not found"
        print("   'Pair Phone' button verified")

        # 3. Enter pairing mode via AT-SPI Action
        print("3. Activating 'Pair Phone' via AT-SPI Action interface...")
        pair_btn.do_action(0)
        time.sleep(1.0)

        pairing_intro = win.child(
            "Open RefineID remote access on your phone and enter the pairing code:",
            roleName="label",
        )
        assert pairing_intro is not None, "Pairing intro label not found"
        print("   Pairing ceremony view opened successfully")

        # 4. Locate backing text entry and input pairing code
        print("4. Locating code entry and typing '7KX4M9'...")
        entry = win.child(roleName="text")
        assert entry is not None, "Backing code text entry not found"
        entry.set_text_contents("7KX4M9")
        time.sleep(1.0)

        # 5. Assert individual code box labels received the digits
        labels = win.findChildren(lambda n: n.roleName == "label")
        code_chars = [l.text for l in labels if l.text and len(l.text) == 1]
        print(f"   Discovered code box labels: {code_chars}")
        assert code_chars == ["7", "K", "X", "4", "M", "9"], (
            f"Expected ['7', 'K', 'X', '4', 'M', '9'], got {code_chars}"
        )
        print("   All 6 code boxes verified with exact characters")

        # 6. Cancel pairing mode
        cancel_btn = win.child("Cancel", roleName="button")
        assert cancel_btn is not None, "'Cancel' button not found"
        print("5. Activating 'Cancel' via AT-SPI Action interface...")
        cancel_btn.do_action(0)
        time.sleep(1.0)

        # 7. Verify return to normal identity view
        print("6. Verifying return to normal identity view...")
        assert win.child("Choose…", roleName="button") is not None
        print("ALL AT-SPI2 / DOGTAIL INTEGRATION TESTS PASSED (100% OK)")

    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    main()
