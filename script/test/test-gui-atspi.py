#!/usr/bin/env python3
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

"""Drives the GTK 4 window through its AT-SPI tree, by accessible names.

Opens refineid-gui with --pair on a host with no card in a reader and no
phone paired, so that remote use is on and the pairing prompt shows;
types four characters into the pairing code boxes and checks the boxes;
then turns remote use off with the header bar's switch and checks that
the prompt gives way to the reader line. Nothing is paired: the code is
never complete.

usage: script/test/test-gui-atspi.py [path to refineid-gui]

Needs: an X or Wayland session with at-spi2-core running, python3 with
dogtail (and pyatspi), DISPLAY and DBUS_SESSION_BUS_ADDRESS set.
"""

import os
import subprocess
import sys
import time

PROMPT = "Open RefineID remote access on your phone and enter the pairing code:"
READER_LINES = ("Connect a card reader.", "Insert the card into the reader.")
TYPED = "7KX4"
SETTLE_SECONDS = 1.0
LAUNCH_SECONDS = 3.0


def wait_for(predicate, what, seconds=10.0):
    """Polls `predicate` until it holds, or fails naming `what`."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise AssertionError(f"timed out waiting for {what}")


def labels(window):
    """The texts of every label showing in `window`."""
    return [
        node.name or node.text
        for node in window.findChildren(lambda n: n.roleName == "label" and n.showing)
    ]


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "refineid-gui"
    env = dict(os.environ, GTK_A11Y="atspi")
    subprocess.run(["pkill", "-x", "refineid-gui"], stderr=subprocess.DEVNULL, check=False)
    time.sleep(SETTLE_SECONDS)
    proc = subprocess.Popen([binary, "--driver", "gtk4", "--pair"], env=env)
    time.sleep(LAUNCH_SECONDS)
    try:
        from dogtail.tree import root

        app = root.application("refineid-gui")
        window = app.child(roleName="frame")
        assert window.name.startswith("RefineID"), window.name
        print("window:", window.name)

        wait_for(lambda: PROMPT in labels(window), "the pairing prompt")
        switch = window.child("Remote Access", roleName="toggle button")
        assert switch.checked, "remote use is on with --pair"
        print("pairing prompt shown, remote use on")

        entry = window.child("Pairing code", roleName="text")
        entry.grabFocus()
        entry.typeText(TYPED)
        time.sleep(SETTLE_SECONDS)
        boxes = [text for text in labels(window) if text and len(text) == 1]
        assert boxes == list(TYPED), f"boxes show {boxes}"
        print("code boxes:", boxes)

        switch.doActionNamed("click")
        wait_for(lambda: PROMPT not in labels(window), "the prompt to go")
        wait_for(
            lambda: any(line in labels(window) for line in READER_LINES),
            "the reader line",
        )
        assert not switch.checked, "remote use is off"
        print("remote use off; the line speaks of the readers here")
        print("PASS")
    finally:
        proc.terminate()
        proc.wait()


if __name__ == "__main__":
    main()
