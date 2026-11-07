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
   - Polkit access rule `/usr/share/polkit-1/rules.d/50-refineid-pcscd.rules`, granting `org.debian.pcsc-lite.access_pcsc` and `access_card` to every user, active local session or not: remote card use over SSH is a supported use case, and the card in the reader and its PINs are the security perimeter, as in the NixOS module's rule
   - Firefox enterprise policy `/etc/firefox/policies/policies.json`, from `policies.json` here with `@MODULE@` replaced by the multiarch module path
   - Module copy `/var/snap/firefox/common/refineid/librefineid_pkcs11.so` for Ubuntu's Firefox snap, placed by `postinst` (see below)
   - Desktop autostart entry `/etc/xdg/autostart/refineid-browser-token.desktop` running `/usr/libexec/refineid/refineid-browser-token`, which gives the signed-in user's NSS database the module for Chromium
   - Maintainer scripts `postinst`, `postrm` and `prerm` from this directory, managing `ldconfig`, polkit reload, `pcscd.socket` activation and the snap copy.
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

## Firefox from snap

Ubuntu's default Firefox is a snap under strict confinement. Inside it
the host's `/usr/lib` is not at `/usr/lib`, and the dynamic loader is
denied the host filesystem view at `/var/lib/snapd/hostfs`, so neither
the module's host path nor a symlink to it can be loaded; the
`SecurityDevices` entry for the host path does nothing there. The snap
does see `/etc/firefox/policies`, its own common data directory
`/var/snap/firefox/common`, and the `pcscd` socket through its
connected `pcscd` interface.

So `postinst` copies the module to
`/var/snap/firefox/common/refineid/librefineid_pkcs11.so` (directory
0755, file 0644, root-owned) whenever `/var/snap/firefox/common` exists,
on every `configure`, so an upgrade refreshes the copy; `postrm` deletes
the copy on `remove` and `purge`, and the directory when it is empty.
Inside the snap the copy resolves against the snap's own
`libpcsclite.so.1`. `policies.json` names both paths, `FINEID` for the
host path and `FINEID (snap)` for the copy; Firefox silently ignores a
`SecurityDevices` path it cannot load, so a deb-based Firefox sees one
module and the snap sees one module. A Firefox snap installed after the
package gets its copy when the package is next configured
(`apt reinstall refineid-pkcs11`).

The package registers no Thunderbird policy; the same confinement and
the same remedy, a copy under `/var/snap/thunderbird/common`, apply to
Thunderbird's snap if that is ever added.

## Trust from the card, not from installed roots

This package installs no certificate authority files and sets no
`Certificates.Install` policy. The PKCS#11 module presents an NSS trust
record next to each CA certificate it reads from the card (see the
[module README](../../crates/refineid-pkcs11/README.md#nss-trust-records)):
the DVV root is trusted for client authentication and email only, and
only while a FINEID card is in the reader, from the card and through
NSS, for Firefox, Thunderbird and Chrome alike. Verified on Ubuntu 26.10
on 2026-11-07: with no root file installed, the Firefox snap logged a
holder into a card-authenticated site with a production citizen card.

The roots were installed system-wide until then because no
Mozilla-derived root store knows them: DVV's roots (DVV Gov. Root CA -
G3 ECC and RSA) are in Microsoft's root program, so Windows and macOS
system stores carry them, but DVV has not applied to Mozilla's root
program, so Firefox's built-in store, and the stores derived from it
(Debian `ca-certificates`, NixOS, FreeBSD), do not. Chrome's own root
store covers server authentication only, and Chrome on Linux takes
client certificates, and the trust for their chains, from NSS.

## Firefox snap and the card daemon

The Firefox snap reaches `pcscd` through its `pcscd` interface, which
is not connected by default on every Ubuntu release. `postinst` connects
it when the snap is installed (`snap connect firefox:pcscd`); without
the connection the module loads inside the snap but sees no reader.

## Debian / Ubuntu Policy Compliance

| Component | Policy Rule | Location in Package |
| --- | --- | --- |
| Shared library | Multiarch (§9.1.1) | `/usr/lib/${DEB_HOST_MULTIARCH}/librefineid_pkcs11.so` |
| PKCS#11 module | Default module path | `/usr/lib/${DEB_HOST_MULTIARCH}/pkcs11/librefineid_pkcs11.so` |
| p11-kit registration | Distro modules in `/usr/share` | `/usr/share/p11-kit/modules/refineid.module` |
| Polkit rule | Distro rules in `/usr/share` | `/usr/share/polkit-1/rules.d/50-refineid-pcscd.rules` |
| Firefox policy | Conffile in `/etc` | `/etc/firefox/policies/policies.json` |
| Firefox snap module copy | Snap common data (`/var/snap/<snap>/common`) | `/var/snap/firefox/common/refineid/librefineid_pkcs11.so` |
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
