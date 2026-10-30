# Installing RefineID on OpenBSD

Verified on OpenBSD 8.0/amd64 under KVM, October 2026: the CLI, the
PKCS#11 module and the FLTK GUI build from packages alone, and the GUI
starts from the CDE Application Manager. Card operations through a reader
are not yet verified on OpenBSD.

## 1. Packages

```sh
pkg_add rust cmake ninja pcsc-lite ccid
```

- `cmake` and `ninja` build the FLTK library bundled by `fltk-sys`.
- OpenBSD 8.0 packages carry no `git`. Fetch the source as an archive;
  cargo fetches the refineid-core git dependencies itself.

## 2. Build

The GTK4 GUI is the default; OpenBSD builds the FLTK one:

```sh
cargo build --release -p refineid-client -p refineid-unix-pkcs11 \
  -p refineid-gui --no-default-features --features refineid-gui/fltk
```

The linker warns about `strcpy`, `strcat` and `rand` inside the bundled
FLTK; the warnings do not concern RefineID code.

## 3. Install

As root:

```sh
install -m 755 target/release/refineid /usr/local/bin/refineid
install -d /usr/local/lib/refineid
install -m 755 target/release/librefineid_pkcs11.so /usr/local/lib/refineid/
BIN=target/release/refineid-gui script/install-desktop.sh --prefix /usr/local
rcctl enable pcscd
rcctl start pcscd
```

## 4. CDE

```sh
pkg_add cde
```

Configure CDE as `/usr/local/share/doc/pkg-readmes/cde` describes. With
CDE present, `script/install-desktop.sh` adds RefineID to the System group
of the Application Manager. A running session shows it after the next
login, or after Desktop_Tools > Reload Applications.
