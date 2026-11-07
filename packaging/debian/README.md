# Debian & Ubuntu packaging material

This directory contains the system integration assets packaged into binary
Debian (`.deb`) packages for Debian and Ubuntu systems.

## Packages

Binary `.deb` packages are produced automatically by `script/package-deb.sh`
(or `make package-deb`):

1. **`refineid-pkcs11`** (`Multi-Arch: same`):
   - Multiarch shared library `/usr/lib/${DEB_HOST_MULTIARCH}/librefineid_pkcs11.so`
   - PKCS#11 module symlink `/usr/lib/${DEB_HOST_MULTIARCH}/pkcs11/librefineid_pkcs11.so`
   - Compatibility symlink `/usr/lib/librefineid_pkcs11.so`
   - System p11-kit module `/usr/share/p11-kit/modules/refineid.module`
   - Polkit access rule `/usr/share/polkit-1/rules.d/50-refineid-pcscd.rules`
   - Firefox enterprise policy `/etc/firefox/policies/policies.json`
   - Desktop autostart entry `/etc/xdg/autostart/refineid-browser-token.desktop` running `/usr/libexec/refineid/refineid-browser-token`, which gives the signed-in user's NSS database the module for Chromium
   - Maintainer scripts (`postinst`, `postrm`, `prerm`) managing `ldconfig`, polkit reload, and `pcscd.socket` activation.
2. **`refineid-cli`** (`Multi-Arch: foreign`):
   - Command-line tool `/usr/bin/refineid`
   - Manual page `/usr/share/man/man1/refineid.1.gz`
   - zsh completion `/usr/share/zsh/vendor-completions/_refineid`
3. **`refineid-gui`**:
   - Desktop application `/usr/bin/refineid-gui`
   - Freedesktop launcher `/usr/share/applications/refineid.desktop`
   - Scalable icon `/usr/share/icons/hicolor/scalable/apps/refineid.svg`
   - Maintainer scripts triggering `update-desktop-database` and `gtk-update-icon-cache`
4. **`refineid`** (`Architecture: all` metapackage):
   - Metapackage pulling in CLI, PKCS#11, and GUI, with `Recommends: pcscd, libccid, pcsc-tools`.

## Firefox policy roots

`policies.json` installs two DVV root certificates system-wide through
the Firefox `Certificates.Install` policy, trusted for every purpose
including TLS server authentication, with no card in any reader. The
policy exists because no Mozilla-derived root store knows the DVV roots:
DVV's roots (DVV Gov. Root CA - G3 ECC and RSA) are in Microsoft's root
program, so Windows and macOS system stores carry them, but DVV has not
applied to Mozilla's root program, so Firefox's built-in store, and the
stores derived from it (Debian `ca-certificates`, NixOS, FreeBSD), do
not. Chrome's own root store covers server authentication only and
Chrome on Linux takes client certificates, and the trust for their
chains, from NSS.

The PKCS#11 module now presents an NSS trust record next to each CA
certificate it reads from the card (see the
[module README](../../crates/refineid-pkcs11/README.md#nss-trust-records)):
the DVV root is trusted for client authentication and email only, and
only while a FINEID card is in the reader, from the card and through
NSS, for Firefox, Thunderbird and Chrome alike. The policy roots remain
in this package until the maintainer has confirmed that behaviour in
Firefox on Linux with a card; then `Certificates.Install` leaves
`policies.json` and the package scripts in one change, and only the
`SecurityDevices` entry that loads the module stays.

What to expect in that test: NSS searches the certificates and trust
records of a login-required token only after the user has logged in
to it, unless the module was registered as friendly (`modutil -add
... -mechanisms FRIENDLY`), and the `SecurityDevices` policy registers
without that flag. So the certificate manager should show the DVV root
as trusted for identifying mail users and clients, and not web sites,
from the session's first PIN login on; before it, the token's
certificates are not listed at all. Whether the token should be made
friendly, by the registration flag in `refineid-browser-token` or by a
public-certificates profile object in the module, is the maintainer's
call after that observation.

## Debian / Ubuntu Policy Compliance

| Component | Policy Rule | Location in Package |
| --- | --- | --- |
| Shared library | Multiarch (§9.1.1) | `/usr/lib/${DEB_HOST_MULTIARCH}/librefineid_pkcs11.so` |
| PKCS#11 module | Default module path | `/usr/lib/${DEB_HOST_MULTIARCH}/pkcs11/librefineid_pkcs11.so` |
| p11-kit registration | Distro modules in `/usr/share` | `/usr/share/p11-kit/modules/refineid.module` |
| Polkit rule | Distro rules in `/usr/share` | `/usr/share/polkit-1/rules.d/50-refineid-pcscd.rules` |
| Firefox policy | Conffile in `/etc` | `/etc/firefox/policies/policies.json` |
| Desktop & icon | Freedesktop / XDG specs | `/usr/share/applications/refineid.desktop`, `/usr/share/icons/...` |
| Package copyright | DEP-5 format (§12.3) | `/usr/share/doc/<pkg>/copyright` |
| Shared library dependencies | Dynamic resolution | Generated via `dpkg-shlibdeps` |

## Building & Installing

Build packages:
```sh
make package-deb
# or: script/package-deb.sh
```

Build and install via package manager:
```sh
make install-deb
# or: script/package-deb.sh --install
```
