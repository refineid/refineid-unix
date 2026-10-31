# Installing RefineID on OpenBSD

Verified on OpenBSD 8.0/amd64 under KVM, October 2026: the CLI, the
PKCS#11 module and the FLTK GUI build from packages alone, and the GUI
starts from the CDE Application Manager. With multicast enabled (section
5), the GUI pairs with an iPhone and Firefox logs in to card.refineid.fi
through it. Firefox and Chromium log in with a card in a USB reader
(HID OMNIKEY 3x21) and through the phone.

## 1. Packages

```sh
pkg_add git rust cmake ninja pcsc-lite ccid
```

`cmake` and `ninja` build the FLTK library bundled by `fltk-sys`.

## 2. Build

The GTK4 GUI is the default; OpenBSD builds the FLTK one:

```sh
cargo build --release -p refineid-client -p refineid-unix-pkcs11 \
  -p refineid-gui --no-default-features --features refineid-gui/fltk
```

The linker warns about `strcpy`, `strcat` and `rand` inside the bundled
FLTK; the warnings do not concern RefineID code.

## 3. CDE

For a CDE desktop, install it before RefineID:

```sh
pkg_add cde
```

Configure CDE as `/usr/local/share/doc/pkg-readmes/cde` describes. With
CDE present, `script/install-desktop.sh` adds RefineID to the System group
of the Application Manager. A running session shows it after the next
login, or after Desktop_Tools > Reload Applications.

## 4. Install

As root:

```sh
install -m 755 target/release/refineid /usr/local/bin/refineid
install -d /usr/local/man/man1
install -m 444 crates/refineid-client/man/refineid.1 /usr/local/man/man1/refineid.1
install -d /usr/local/lib/refineid
install -m 755 target/release/librefineid_pkcs11.so /usr/local/lib/refineid/
BIN=target/release/refineid-gui script/install-desktop.sh --prefix /usr/local
rcctl enable pcscd
rcctl start pcscd
```

## 5. Multicast for phone pairing

Pairing finds the phone through multicast DNS. Unless `multicast=YES` is
set, netstart(8) routes `224.0.0.0/4` to a reject route on `lo0`, so the
queries never leave the host and no phone is found. As root:

```sh
rcctl enable multicast
route -qn delete 224.0.0.0/4
```

`rcctl enable multicast` takes effect at the next boot; deleting the
reject route applies it now.

## 6. Browsers

Both browsers on OpenBSD are confined with unveil(2), and the module they
load reads the phone pairings under `~/.config/refineid`.
`script/install-desktop.sh` adds that directory to
`/etc/firefox/unveil.main` and `/etc/chromium/unveil.main` when they exist.

Firefox loads the module through its policy. Chromium reads the user's NSS
database, which the browser-token script fills at each desktop login; in
CDE, `/etc/dt/config/Xsession.d/0100.refineid` runs it. Restart the
browsers afterwards; they read all of this only at startup.

## 7. Remote desktop

The VM has no display of its own. Two X paths work from a Mac.

**VNC.** TigerVNC runs CDE in its own X server. As root, `pkg_add
tigervnc`; then as the desktop user:

```sh
vncpasswd
printf 'geometry=1920x1080\ndepth=24\nSecurityTypes=VncAuth\n' > ~/.vnc/config
printf '#!/bin/sh\nunset SESSION_MANAGER DBUS_SESSION_BUS_ADDRESS\nexec /usr/local/dt/bin/Xsession\n' > ~/.vnc/xstartup
chmod 755 ~/.vnc/xstartup
vncserver :0
```

A crontab line `@reboot /usr/local/bin/vncserver :0` starts it at boot.
macOS Screen Sharing connects to `vnc://<host>.local:5900` once the host
announces itself (section 8).

**XDMCP.** With `dtlogin` enabled and every `:0 Local` line removed from
`/etc/dt/config/Xservers` (the pkg-readme copies the templates there),
dtlogin serves XDMCP queries only. XQuartz on the Mac, with its
`nolisten_tcp` and `rootless` preferences both off, runs

```sh
/opt/X11/bin/X :1 -listen tcp -query <host>.local -from <mac-ip-address>
```

dtlogin resolves the querying host's name before it answers, so the Mac
needs an entry in the OpenBSD `/etc/hosts` when the network has no
reverse DNS, and `-from` names the Mac's own address on that network,
the one dtlogin connects back to, so it does not pick a link-local one.
The CDE pkg-readme's inetd lines (`dtspc`, `cmsd`), with `inetd` and
`portmap` enabled through rcctl, complete the session.

## 8. Host name on the network

OpenBSD ships no multicast DNS responder, so `<host>.local` answers
nothing until one is installed. The openmdns package does that with the
first label of `/etc/myname`; it needs the multicast route from section 5.
As root:

```sh
pkg_add openmdns
rcctl enable mdnsd
rcctl set mdnsd flags vio0
rcctl start mdnsd
```

`rcctl set` refuses flags for a service that is not yet enabled, and the
default flags name `em0`, so the order matters. A service is announced
with `mdnsctl publish`, which must stay running for the announcement to
last and takes a TXT argument even when empty. This line in
`/etc/rc.local` announces the VNC desktop, so the host appears under
Network in the Finder with a Share Screen button:

```sh
/usr/local/bin/mdnsctl publish "$(hostname -s)" rfb tcp 5900 "" >/dev/null 2>&1 &
```

macOS resolves a `.local` name through mDNS only when the name is typed
with the suffix. A `local` search domain does not help: the Mac appends it
and then sends the result over unicast DNS, where nothing answers. For
ssh, let ssh add the suffix itself in `~/.ssh/config`:

```
CanonicalizeHostname yes
CanonicalDomains local
CanonicalizeFallbackLocal yes
```

`ssh <host>` then resolves live, with no address written anywhere. The
price is one mDNS lookup before every unqualified name that is not on
the local link.

## 9. Card readers

A reader connected to a running system was found after restarting
`pcscd`; whether a running `pcscd` notices it unaided is not verified.

```sh
rcctl restart pcscd
```
