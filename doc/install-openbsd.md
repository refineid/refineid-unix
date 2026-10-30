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

## 7. Card readers

A reader connected to a running system was found after restarting
`pcscd`; whether a running `pcscd` notices it unaided is not verified.

```sh
rcctl restart pcscd
```
