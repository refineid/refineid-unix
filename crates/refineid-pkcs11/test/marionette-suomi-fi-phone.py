#!/usr/bin/env python3
"""
Drive Firefox to log in to Suomi.fi through the paired phone's token.

The module is the one Firefox loads from its policy, in the user's own
profile; the phone verifies PIN 1, so no PIN is typed here. The
certificate chooser is accepted when it appears.

Usage:
  ./crates/refineid-pkcs11/test/marionette-suomi-fi-phone.py [start-url]
"""
import json
import re
import socket
import subprocess
import sys
import threading
import time

MARIONETTE_PORT = 2828
START_URL = "https://www.suomi.fi/etusivu"


class Marionette:
    def __init__(self, port=MARIONETTE_PORT):
        for _ in range(60):
            try:
                self.sock = socket.create_connection(("127.0.0.1", port), timeout=120)
                break
            except OSError:
                time.sleep(0.5)
        else:
            raise RuntimeError("Marionette port never answered")
        self.next_id = 0
        self._recv()

    def _recv(self):
        buf = b""
        while b":" not in buf:
            buf += self.sock.recv(1)
        length = int(buf[:-1])
        data = b""
        while len(data) < length:
            data += self.sock.recv(length - len(data))
        return json.loads(data)

    def cmd(self, name, params=None):
        self.next_id += 1
        msg = json.dumps([0, self.next_id, name, params or {}]).encode()
        self.sock.sendall(str(len(msg)).encode() + b":" + msg)
        while True:
            reply = self._recv()
            if reply[0] == 1 and reply[1] == self.next_id:
                if reply[2]:
                    raise RuntimeError(reply[2].get("message", reply[2]))
                return reply[3]

    def run(self, script):
        return self.cmd("WebDriver:ExecuteScript", {"script": script, "args": []})["value"]


def accept_chooser(stop):
    """Answers the certificate chooser with its default button.

    Firefox draws the chooser inside the browser window, so there is no
    dialog window to find: the browser window is brought to the front
    and Return is pressed through XTEST, which reaches the dialog while
    it has the focus and does nothing to a page that has none.
    """
    while not stop.is_set():
        time.sleep(1.5)
        try:
            found = subprocess.run(
                ["xdotool", "search", "--onlyvisible", "--class", "firefox"],
                capture_output=True, text=True, check=False,
            ).stdout.split()
            for wid in found[:1]:
                subprocess.run(["xdotool", "windowactivate", "--sync", wid], check=False)
                time.sleep(0.2)
                subprocess.run(["xdotool", "key", "--clearmodifiers", "Return"], check=False)
                print(f"[{time.strftime('%H:%M:%S')}] pressed Return in the browser window")
        except OSError:
            pass


def click_first(m, selectors, label):
    script = (
        "const sels = %s; for (const s of sels) { const el = document.querySelector(s);"
        " if (el) { el.click(); return s; } } return null;" % json.dumps(selectors)
    )
    hit = m.run(script)
    print(f"[*] {label}: {hit or 'nothing matched'}")
    return hit


def main():
    start = sys.argv[1] if len(sys.argv) > 1 else START_URL
    subprocess.run(["pkill", "-x", "firefox"], check=False)
    time.sleep(3)
    proc = subprocess.Popen(
        ["firefox", "--marionette"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    stop = threading.Event()
    m = None
    try:
        m = Marionette()
        m.cmd("WebDriver:NewSession", {"capabilities": {}})
        m.cmd("WebDriver:SetTimeouts", {"pageLoad": 90000})
        print(f"[*] {time.strftime('%H:%M:%S')} start {start}")
        m.cmd("WebDriver:Navigate", {"url": start})
        time.sleep(3)
        click_first(m, [".login-container a", ".login-container button", "a[href*='tunnistaudu']",
                        "a[href*='login']", "button[data-testid*='login']"], "Tunnistaudu")
        time.sleep(4)
        click_first(m, ["#varmennekortti", "a[href*='VARMENNEKORTTI']", "a[href*='varmennekortti']",
                        "button[id*='varmennekortti']", "a[href*='HST']"], "Varmennekortti")
        for _ in range(20):
            time.sleep(1)
            if "hst-prompt" in m.cmd("WebDriver:GetCurrentURL")["value"]:
                break
        time.sleep(1)
        print("[*] card prompt:", m.run(
            "const f = document.querySelector('#login-form'); if (f) { f.submit(); return 'submitted'; } return null;"))
        stop = threading.Event()
        threading.Thread(target=accept_chooser, args=(stop,), daemon=True).start()
        started = time.time()
        while time.time() - started < 120:
            time.sleep(2)
            url = m.cmd("WebDriver:GetCurrentURL")["value"]
            title = m.cmd("WebDriver:GetTitle")["value"]
            print(f"    [{time.time()-started:4.0f}s] {url[:90]} | {title[:50]}")
            if "kortti." not in url:
                stop.set()
            if "/idp/profile/SAML2" in url:
                # The card authenticated; the identity provider asks once
                # whether to carry the identity to the service.
                hit = m.run("const b = document.querySelector('#continue-button');"
                            " if (b) { b.click(); return 'continued'; } return null;")
                if hit:
                    print(f"[*] {hit}")
                continue
            if url.startswith("https://www.suomi.fi/") and "/etusivu" not in url.split("?")[0]:
                text = re.sub(r"<[^>]+>", " ", m.cmd("WebDriver:GetPageSource")["value"])
                text = re.sub(r"\s+", " ", text)
                print(f"[+] logged in at {url}")
                print("    page says:", text[:200])
                return 0
            if "Problem loading" in title:
                print("[-] the browser reports a load problem")
                return 1
        print("[-] no landing within 120 s")
        return 1
    finally:
        stop.set()
        if m:
            try:
                m.cmd("WebDriver:DeleteSession")
            except (OSError, RuntimeError):
                pass
        # Firefox stays for the person; the automation only drove it.
        proc.poll()


if __name__ == "__main__":
    sys.exit(main())
