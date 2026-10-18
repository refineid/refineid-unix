# Installing RefineID on FreeBSD

Verified on FreeBSD 15.1-RELEASE amd64 with an ACS ACR39U USB reader and
an xfce desktop. Everything below runs as root unless the prompt says
otherwise.

## 1. Packages

```sh
pkg install pcsc-lite acsccid libccid pcsc-tools \
    avahi-app nss_mdns libsecret gnome-keyring \
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

## 6. PKCS#11 through p11-kit

Nothing names the RefineID module in any browser. The module is
registered with p11-kit, and NSS loads p11-kit's proxy module, through
which every p11-kit module appears.

Install the module on a stable path and register it:

```sh
install -d /usr/local/lib/refineid
install -m 0755 target/release/librefineid_pkcs11.so /usr/local/lib/refineid/
cat > /usr/local/etc/pkcs11/modules/refineid.module <<'MODULE'
module: /usr/local/lib/refineid/librefineid_pkcs11.so
critical: no
MODULE
```

`p11-kit list-modules` lists `refineid` and, with a card in the reader,
its token "Basic (PIN 1)". Reinstall the copy after every rebuild.

Firefox loads the proxy through its enterprise policy, which names only
the proxy; the file is
`/usr/local/lib/firefox/distribution/policies.json`:

```json
{ "policies": { "SecurityDevices": { "p11-kit-proxy": "/usr/local/lib/p11-kit-proxy.so" } } }
```

Chromium reads the user's NSS database; as the user:

```sh
certutil -N -d sql:$HOME/.pki/nssdb --empty-password
modutil -dbdir sql:$HOME/.pki/nssdb -add p11-kit-proxy -libfile /usr/local/lib/p11-kit-proxy.so
modutil -dbdir sql:$HOME/.pki/nssdb -list
```

The listing shows the proxy with the reader as its slot and the token
"Basic (PIN 1)" while a card is inserted. In Firefox the token appears
under "p11-kit-proxy" in Settings > Privacy & Security > Security
Devices. A card-login site then asks for the certificate and for PIN 1.
Without a card nothing is offered and nothing is asked.

OpenSSH reaches the same module through the proxy:
`ssh -I /usr/local/lib/p11-kit-proxy.so host`.

`p11tool --provider p11-kit-proxy.so` answers "PKCS #11 initialization
error" because p11tool is itself a p11-kit client; `p11tool --list-tokens`
without a provider, or `p11-kit list-modules`, is the check.

The Debian package and the NixOS module register the module with
p11-kit the same way but name the module itself in Firefox's policy;
FreeBSD names only the proxy.

## 7. Pairing a phone

Each pairing's private key is kept in the desktop's Secret Service
(`secret-tool` from `libsecret`), so a provider must run in the session:
`gnome-keyring` is the one installed above. It starts with the Xfce
session through its autostart entries and keeps its keyring unlocked
when the keyring password is the login password or empty. Pairing
refuses to start when the service does not answer, before the phone's
code is spent.

The RefineID desktop application and `refineid pair` must run inside the
desktop session (with `DBUS_SESSION_BUS_ADDRESS` set), not over a plain
SSH login, for the Secret Service to be reachable.

With remote access on in the phone's RefineID and the phone on the same
network:

```sh
./target/release/refineid pair
```

The command browses for the phone, the phone shows a six-character
code, and the code is typed at the prompt. `refineid pairs` lists the
pairing and `refineid auth` uses the phone's card.
