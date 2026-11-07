"""One observation or action on Firefox's accessibility tree, in a fresh process.

  cert-ok     press OK on the certificate prompt; exit 0 when done, 3 when absent
  pin-focus   give the password field focus; exit 0 when it reports focus, 3 when absent
  pin-ok      press OK on the dialog that holds the password field
  page TITLE  exit 0 when a web document whose title contains TITLE is shown
"""
import pyatspi, sys
CERT = ("Käyttäjän todentamispyyntö", "User Identification Request")
def firefox():
    for app in pyatspi.Registry.getDesktop(0):
        try:
            if "irefox" in (app.name or ""): yield app
        except Exception: pass
def walk(node, depth=0, maxdepth=16):
    if depth > maxdepth: return
    yield node
    try: count = node.childCount
    except Exception: return
    for i in range(count):
        try: ch = node.getChildAtIndex(i)
        except Exception: continue
        if ch is not None: yield from walk(ch, depth+1, maxdepth)
def role(n):
    try: return n.getRoleName()
    except Exception: return ""
def name(n):
    try: return n.name or ""
    except Exception: return ""
def press(b):
    a = b.queryAction()
    for i in range(a.nActions):
        if a.getName(i) in ("press","click","activate"): a.doAction(i); return True
    return False
def first(pred):
    for app in firefox():
        for n in walk(app):
            try:
                if pred(n): return n
            except Exception: pass
    return None
cmd = sys.argv[1]
if cmd == "cert-ok":
    d = first(lambda n: role(n)=="dialog" and any(s in name(n) for s in CERT))
    if d is None: sys.exit(3)
    ok = next((n for n in walk(d) if role(n) in ("button","push button") and name(n)=="OK"), None)
    sys.exit(0 if ok is not None and press(ok) else 4)
elif cmd == "pin-focus":
    pw = first(lambda n: role(n)=="password text")
    if pw is None: sys.exit(3)
    pw.queryComponent().grabFocus()
    import time; time.sleep(0.3)
    sys.exit(0 if pw.getState().contains(pyatspi.STATE_FOCUSED) else 4)
elif cmd == "pin-ok":
    pw = first(lambda n: role(n)=="password text")
    if pw is None: sys.exit(3)
    p = pw
    for _ in range(12):
        p = p.parent
        if p is None: sys.exit(4)
        if role(p) in ("dialog", "alert"): break
    ok = next((n for n in walk(p) if role(n) in ("button","push button") and name(n) in ("OK", "Kirjaudu sisään", "Sign in", "Log in")), None)
    sys.exit(0 if ok is not None and press(ok) else 4)
elif cmd == "page":
    d = first(lambda n: role(n)=="document web" and sys.argv[2] in name(n))
    sys.exit(0 if d is not None else 3)
