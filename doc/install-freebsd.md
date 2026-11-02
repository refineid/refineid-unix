# Installing RefineID on FreeBSD

This is the from-source installation. The `refineid` package
([packages.md](packages.md)) installs the same files and enables pcscd;
the ACS reader note in section 2 and section 3 apply to it as well.

Verified on FreeBSD 15.1-RELEASE amd64 with an ACS ACR39U USB reader and
an xfce desktop. Everything below runs as root unless the prompt says
otherwise.

## 1. Packages

```sh
pkg install pcsc-lite acsccid libccid pcsc-tools \
    avahi-app nss_mdns \
    rust git pkgconf cmake ninja evdev-proto \
    p11-kit nss firefox chromium
```

For a desktop: `pkg install xfce xorg lightdm lightdm-gtk-greeter dbus
xdg-desktop-portal-gtk` and the `drm-*-kmod` package for the GPU; enable `dbus` and `lightdm` in
`/etc/rc.conf`, set `greeter-session=lightdm-gtk-greeter` and
`user-session=xfce` under `[Seat:*]` in `/usr/local/etc/lightdm/lightdm.conf`,
and add the user to the `video` group. Without `xdg-desktop-portal-gtk`
the desktop portal has no file chooser and the GUI's file dialogs do not
open.

For KDE Plasma 6 or GNOME 47, install `plasma6-plasma` or `gnome` (along
with `gnome-terminal`), and ensure `procfs` and `fdescfs` are mounted in
`/etc/fstab` (`proc /proc procfs rw 0 0` and `fdesc /dev/fd fdescfs rw 0 0`).
Leave `user-session` unset in `/usr/local/etc/lightdm/lightdm.conf` so the
login greeter allows selecting the session.

## 2. Smart-card daemon

```sh
sysrc pcscd_enable=YES
sysrc pcscd_flags="--disable-polkit"
service pcscd start
```

With polkit enabled, a client outside a logind seat gets "Service not
available"; FreeBSD has no logind, so polkit is disabled.

An ACS reader needs the ACS driver (`acsccid`). With the generic CCID bundle
in place, `pcscd` binds the ACR39U to `libccid` and the reader never finishes
initialising. However, moving `ifd-ccid.bundle` aside breaks all non-ACS card
readers (e.g. Alcor Micro, Realtek, generic EMV chips).

To make both ACS readers and generic CCID readers work simultaneously, keep
both bundles active in `/usr/local/lib/pcsc/drivers/` and remove the
conflicting ACS vendor entries (`0x072F`) from `ifd-ccid.bundle`'s `Info.plist`:

```sh
python3 -c '
import plistlib
p = "/usr/local/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist"
with open(p, "rb") as f:
    d = plistlib.load(f)
keep = [(v, pr, n) for v, pr, n in zip(d["ifdVendorID"], d["ifdProductID"], d["ifdFriendlyName"]) if v.lower() != "0x072f"]
d["ifdVendorID"], d["ifdProductID"], d["ifdFriendlyName"] = [list(x) for x in zip(*keep)]
with open(p, "wb") as f:
    plistlib.dump(d, f)
'
service pcscd restart
```

`ifd-acsccid.bundle` then serves ACS readers while `ifd-ccid.bundle` serves all
other CCID readers.

`pcsc_scan -r` lists the reader. If `service pcscd restart` answers
"already running?" after a crash, stop it, remove `/var/run/pcscd.pid`,
and start it again.

## 3. Name resolution and mDNS

The phone's RAPP service is found over DNS-SD:

```sh
sysrc avahi_daemon_enable=YES
service avahi-daemon start
```

and in `/etc/nsswitch.conf`: `hosts: files mdns dns`. A phone advertises
`_refineid-stream._tcp` only while its remote access is on;
`avahi-browse -t -r _refineid-stream._tcp` shows it.

RefineID sends its own mDNS query and does not depend on Avahi for the
phone. A wireless network delivers multicast to a phone unreliably, so
the query also goes directly to the addresses the phone last answered
from, kept beside the pairing record in `~/.config/refineid/rapp-pairs`.

If local unbound forwards to a router that drops DNSSEC data, every
lookup answers SERVFAIL and pkg cannot resolve its mirrors; a file
`/var/unbound/conf.d/no-dnssec.conf` with `module-config: "iterator"`
and `service local_unbound restart` fixes it.

For automatic network link failover between wired Ethernet and Wi-Fi on
laptops or workstations, see [freebsd-network-failover.md](freebsd-network-failover.md).

## 4. Build

The sources need no change. FLTK's CMake has to find `linux/input.h`
from `evdev-proto`, so the build takes the environment below; the
libraries FLTK links on FreeBSD come from `crates/refineid-gui-fltk/build.rs`
and reach only binaries that link FLTK. As the user:

```sh
git clone https://github.com/refineid/refineid-unix.git
cd refineid-unix
export CFLAGS=-I/usr/local/include CXXFLAGS=-I/usr/local/include \
    CMAKE_INCLUDE_PATH=/usr/local/include
cargo build --release --workspace
cargo test --release --workspace
```

The workspace tests and `script/verify-push.sh` pass on FreeBSD. The
binaries are `target/release/refineid`, `target/release/refineid-gui`
and `target/release/librefineid_pkcs11.so`. `refineid card` reports the
card in the reader.

## 5. Desktop integration

`script/install-desktop.sh` installs the GUI binary, the freedesktop
launcher and the icon under the prefix, and refreshes the caches; the
CLI goes beside it:

```sh
sh script/install-desktop.sh --prefix /usr/local
install -m 755 target/release/refineid /usr/local/bin/
install -d /usr/local/share/man/man1 /usr/local/share/zsh/site-functions
install -m 444 crates/refineid-client/man/refineid.1 /usr/local/share/man/man1/
install -m 444 packaging/zsh/_refineid /usr/local/share/zsh/site-functions/
```

RefineID then appears in the xfce application menu. Reinstall after
every rebuild.

## 6. Browsers

### Firefox and Chromium

Neither browser is configured by the user. The module is installed on a
stable path, and `script/install-desktop.sh` (section 5) installs the
two things the browsers need: a Firefox enterprise policy naming the
module, and a desktop autostart entry that gives each signed-in user's
NSS database the module before any browser starts.

Install the module:

```sh
install -d /usr/local/lib/refineid
install -m 0755 target/release/librefineid_pkcs11.so /usr/local/lib/refineid/
```

Then `sh script/install-desktop.sh --prefix /usr/local` as root writes
`/usr/local/lib/firefox/distribution/policies.json`, which every Firefox
profile of every user reads, and
`/usr/local/etc/xdg/autostart/refineid-browser-token.desktop`, which runs
`/usr/local/libexec/refineid/refineid-browser-token` at each desktop
login: the script creates `~/.pki/nssdb` when it is missing and adds the
module to it when it is not there, in under a second, so a new user and
a wiped home directory are handled alike. Chromium and every other NSS
program reading that database then see the card. Reinstall the module
copy after every rebuild; the policy and the autostart entry need no
change.

For Chromium to offer the citizen certificate during TLS authentication,
NSS requires that the issuing CA certificates be present in `~/.pki/nssdb`
with client certificate trust flags (`CT,C,C`):

```sh
certutil -A -d sql:$HOME/.pki/nssdb -n "DVV Gov. Root CA - G3 ECC" \
    -t "CT,C,C" -i /path/to/dvv-gov-root-ca-g3-ecc.der
certutil -A -d sql:$HOME/.pki/nssdb -n "DVV Citizen Certificates - G4E" \
    -t "CT,C,C" -i /path/to/dvvcqc4ec.crt
```

In Firefox the module appears under "RefineID" in Settings > Privacy &
Security > Security Devices, with the reader as one slot and the paired
phone (section 7) as another, "RefineID Remote" with the phone's name.
A card in the reader shows the token "Basic (PIN 1)"; the paired phone
shows "Phone (PIN 1)" while the module holds a session to it and the
phone reports its card. The phone's certificate comes from the pairing
record, read from the card once and cached, so the phone does nothing
for the slot but answer the session's pings; it is asked for one
thing, the signature. A card-login site asks for the certificate; PIN 1
is asked by the browser for the reader's card and by the phone for the
phone's card. Without a card nothing is offered and nothing is asked.
One program on the computer holds the phone session at a time: while a
browser holds it, `refineid card` and the desktop application report
the phone as in use.

### Konqueror (KDE Plasma / WebEnginePart)

Konqueror uses KDE's `webenginepart`, backed by QtWebEngine. On FreeBSD,
QtWebEngine is built without NSS client certificate support (`use_nss_certs=false`),
and its internal `QWebEngineClientCertificateStore` mandates that client
private keys be exported to PEM (`QSslKey::toPem()`). Because hardware smart cards
strictly prohibit private key extraction, QtWebEngine cannot natively complete
mTLS handshakes with PKCS#11 tokens.

To support Konqueror on FreeBSD without upstream QtWebEngine architectural changes,
RefineID provides a local loopback mTLS proxy bridge (`refineid-mtls-proxy`):

1. **Proxy Daemon (`refineid-mtls-proxy`)**:
   Runs as a user daemon listening on `127.0.0.1:18443`. It intercepts HTTPS `CONNECT`
   tunnels for card authentication domains (`card.refineid.fi`, `*.suomi.fi`,
   `*.dvv.fi`, etc.), while transparently forwarding other traffic.
2. **Upstream Smart Card Authentication**:
   The proxy terminates upstream TLS using OpenSSL 3 and `openssl-pkcs11provider`
   via `/usr/local/lib/p11-kit-proxy.so` (backed by `librefineid_pkcs11.so`). When the
   card's authentication private key is accessed, the proxy prompts for PIN 1
   via `refineid-ask-pin` (a native Qt modal dialog that displays over the desktop
   session without logging or leaking the PIN).
3. **Local Bridge CA**:
   Downstream connections to Konqueror are secured using a locally generated CA
   installed into FreeBSD system trust (`/usr/local/share/certs/refineid-ca.pem`
   with `certctl rehash`).
4. **Konqueror Integration**:
   Konqueror's `webenginepart` is patched (`packaging/konqueror/webenginepart-mtls-bridge.patch`)
   to probe `127.0.0.1:18443` on startup, automatically routing requests through
   the proxy, and trusting the local bridge CA.
5. **Autostart**:
   `packaging/konqueror/refineid-mtls-proxy.desktop` installed to `~/.config/autostart/`
   starts the proxy bridge on KDE login.

Build and install the bridge components:

```sh
cd packaging/konqueror
make
make install
```

OpenSSH and OpenSSL reach the module through p11-kit when it is
registered there, which the browsers no longer need:

```sh
cat > /usr/local/etc/pkcs11/modules/refineid.module <<'MODULE'
module: /usr/local/lib/refineid/librefineid_pkcs11.so
critical: no
MODULE
```

`ssh -I /usr/local/lib/p11-kit-proxy.so host` then uses the card.
`p11tool --provider p11-kit-proxy.so` answers "PKCS #11 initialization
error" because p11tool is itself a p11-kit client; `p11tool --list-tokens`
without a provider, or `p11-kit list-modules`, is the check.

The Debian package and the NixOS module install the same policy and
autostart entry under `/etc`.

## 7. Pairing a phone

Each pairing is one owner-only file (mode `0600` in a `0700` directory)
under `~/.config/refineid/rapp-pairs`, holding the pairing's private key
with its record, as `~/.ssh` holds a private key.

With remote access on in the phone's RefineID and the phone on the same
network:

```sh
./target/release/refineid phone pair
```

The command browses for the phone, the phone shows a six-character
code, and the code is typed at the prompt. `refineid phone` shows the
pairing and `refineid phone auth` uses the phone's card.
