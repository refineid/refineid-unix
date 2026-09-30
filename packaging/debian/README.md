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
   - Maintainer scripts (`postinst`, `postrm`, `prerm`) managing `ldconfig`, polkit reload, and `pcscd.socket` activation.
2. **`refineid-cli`** (`Multi-Arch: foreign`):
   - Command-line tool `/usr/bin/refineid`
3. **`refineid-gui`**:
   - Desktop application `/usr/bin/refineid-gui`
   - Freedesktop launcher `/usr/share/applications/refineid.desktop`
   - Scalable icon `/usr/share/icons/hicolor/scalable/apps/refineid.svg`
   - Maintainer scripts triggering `update-desktop-database` and `gtk-update-icon-cache`
4. **`refineid`** (`Architecture: all` metapackage):
   - Metapackage pulling in CLI, PKCS#11, and GUI, with `Recommends: pcscd, libccid, pcsc-tools`.

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
