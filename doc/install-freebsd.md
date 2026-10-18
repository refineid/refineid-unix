# Installing RefineID on FreeBSD

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

For a desktop: `pkg install xfce xorg lightdm lightdm-gtk-greeter dbus`
and the `drm-*-kmod` package for the GPU; enable `dbus` and `lightdm` in
`/etc/rc.conf`, set `greeter-session=lightdm-gtk-greeter` and
`user-session=xfce` under `[Seat:*]` in `/usr/local/etc/lightdm/lightdm.conf`,
and add the user to the `video` group.

## 2. Smart-card daemon

```sh
sysrc pcscd_enable=YES
sysrc pcscd_flags="--disable-polkit"
service pcscd start
```

With polkit enabled, a client outside a logind seat gets "Service not
available"; FreeBSD has no logind, so polkit is disabled.

An ACS reader needs the ACS driver. With the generic CCID bundle in
place pcscd binds the ACR39U to libccid and the reader never finishes
initialising, so move the bundle aside; other CCID readers need it back:

```sh
mkdir -p /usr/local/lib/pcsc/drivers-disabled
mv /usr/local/lib/pcsc/drivers/ifd-ccid.bundle /usr/local/lib/pcsc/drivers-disabled/
service pcscd restart
```

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

If local unbound forwards to a router that drops DNSSEC data, every
lookup answers SERVFAIL and pkg cannot resolve its mirrors; a file
`/var/unbound/conf.d/no-dnssec.conf` with `module-config: "iterator"`
and `service local_unbound restart` fixes it.

## 4. Build

The sources need no change. The FLTK crate builds FLTK with its Wayland
backend on FreeBSD but links the Wayland and GTK libraries only under
its `use-wayland` feature, and its CMake has to find `linux/input.h`
from `evdev-proto`, so the build takes the environment below. As the
user:

```sh
git clone https://github.com/refineid/refineid-unix.git
cd refineid-unix
export CFLAGS=-I/usr/local/include CXXFLAGS=-I/usr/local/include \
    CMAKE_INCLUDE_PATH=/usr/local/include
export RUSTFLAGS="-L native=/usr/local/lib \
    -l dylib=wayland-client -l dylib=wayland-cursor -l dylib=wayland-egl \
    -l dylib=xkbcommon -l dylib=dbus-1 -l dylib=EGL -l dylib=GL \
    -l dylib=gtk-3 -l dylib=gdk-3 -l dylib=gobject-2.0 -l dylib=glib-2.0 \
    -l dylib=gio-2.0 -l dylib=pango-1.0 -l dylib=pangocairo-1.0 -l dylib=cairo"
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
```

RefineID then appears in the xfce application menu. Reinstall after
every rebuild.

## 6. Browsers

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
./target/release/refineid pair
```

The command browses for the phone, the phone shows a six-character
code, and the code is typed at the prompt. `refineid pairs` lists the
pairing and `refineid auth` uses the phone's card.
