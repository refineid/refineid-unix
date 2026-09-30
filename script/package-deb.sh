#!/bin/sh
# Copyright 2026 Petri Koistinen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

# Build binary Debian (.deb) packages for RefineID conforming to
# Debian / Ubuntu Packaging Policy guidelines.
#
# Packages generated:
#   1. refineid-pkcs11: PKCS#11 module (multiarch), p11-kit config,
#                       polkit pcscd rule, Firefox enterprise policy
#   2. refineid-cli:    Command-line tool (/usr/bin/refineid)
#   3. refineid-gui:    Desktop GUI tool (/usr/bin/refineid-gui), launcher, icons
#   4. refineid:        Architecture-independent metapackage pulling in all components
#
# Usage:
#   script/package-deb.sh [--skip-build] [--install]

set -eu
cd "$(dirname "$0")/.."

DO_BUILD=1
DO_INSTALL=0

for arg in "$@"; do
    case "$arg" in
        --skip-build)
            DO_BUILD=0
            ;;
        --install)
            DO_INSTALL=1
            ;;
        -h|--help)
            echo "Usage: $0 [--skip-build] [--install]"
            exit 0
            ;;
        *)
            echo "error: unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "error: dpkg-deb not found. Please install dpkg (sudo apt install dpkg)" >&2
    exit 1
fi

VERSION="$(tr -d '\r\n ' < VERSION)"
if [ -z "$VERSION" ]; then
    echo "error: VERSION file is empty" >&2
    exit 1
fi

ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)"
if [ -z "$MULTIARCH" ]; then
    case "$ARCH" in
        amd64) MULTIARCH="x86_64-linux-gnu" ;;
        arm64) MULTIARCH="aarch64-linux-gnu" ;;
        armhf) MULTIARCH="arm-linux-gnueabihf" ;;
        i386)  MULTIARCH="i386-linux-gnu" ;;
        *)     MULTIARCH="" ;;
    esac
fi

if [ "$DO_BUILD" -eq 1 ]; then
    echo "Building release binaries with cargo..."
    cargo build --release --workspace
fi

DEB_DIR="target/deb"
mkdir -p "$DEB_DIR"

calc_shlibdeps() {
    binary="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
    fallback="$2"
    if command -v dpkg-shlibdeps >/dev/null 2>&1; then
        tmp_ctrl_dir="$(mktemp -d)"
        mkdir -p "$tmp_ctrl_dir/debian"
        touch "$tmp_ctrl_dir/debian/control"
        deps="$( (cd "$tmp_ctrl_dir" && dpkg-shlibdeps -O "$binary" 2>/dev/null) | sed -n 's/^shlibs:Depends=//p' || true)"
        rm -rf "$tmp_ctrl_dir"
        if [ -n "$deps" ]; then
            echo "$deps"
            return 0
        fi
    fi
    echo "$fallback"
}

write_copyright() {
    target="$1"
    pkg_name="$2"
    mkdir -p "$(dirname "$target")"
    cat > "$target" << COPYRIGHTEOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: $pkg_name
Upstream-Contact: Petri Koistinen <petri.koistinen@refineid.fi>
Source: https://github.com/refineid/refineid-unix

Files: *
Copyright: 2026 Petri Koistinen
License: Apache-2.0
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 .
     https://www.apache.org/licenses/LICENSE-2.0
 .
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 .
 On Debian systems, the complete text of the Apache version 2.0 license
 can be found in '/usr/share/common-licenses/Apache-2.0'.
COPYRIGHTEOF
    chmod 644 "$target"
}

# ==============================================================================
# Package 1: refineid-pkcs11
# ==============================================================================
PKG_PKCS11="refineid-pkcs11_${VERSION}_${ARCH}"
STAGING_PKCS11="$DEB_DIR/$PKG_PKCS11"
echo "Packaging $PKG_PKCS11..."
rm -rf "$STAGING_PKCS11" "$DEB_DIR/${PKG_PKCS11}.deb"

if [ -n "$MULTIARCH" ]; then
    PKCS11_LIB_DIR="usr/lib/$MULTIARCH"
    PKCS11_MODULE_DIR="usr/lib/$MULTIARCH/pkcs11"
    FIREFOX_LIB_PATH="/usr/lib/$MULTIARCH/pkcs11/librefineid_pkcs11.so"
else
    PKCS11_LIB_DIR="usr/lib"
    PKCS11_MODULE_DIR="usr/lib/pkcs11"
    FIREFOX_LIB_PATH="/usr/lib/pkcs11/librefineid_pkcs11.so"
fi

mkdir -p \
    "$STAGING_PKCS11/DEBIAN" \
    "$STAGING_PKCS11/$PKCS11_LIB_DIR" \
    "$STAGING_PKCS11/$PKCS11_MODULE_DIR" \
    "$STAGING_PKCS11/usr/share/p11-kit/modules" \
    "$STAGING_PKCS11/usr/share/polkit-1/rules.d" \
    "$STAGING_PKCS11/etc/firefox/policies"

install -m 755 target/release/librefineid_pkcs11.so "$STAGING_PKCS11/$PKCS11_LIB_DIR/librefineid_pkcs11.so"
(cd "$STAGING_PKCS11/$PKCS11_MODULE_DIR" && ln -sf "../librefineid_pkcs11.so" "librefineid_pkcs11.so")

if [ -n "$MULTIARCH" ]; then
    mkdir -p "$STAGING_PKCS11/usr/lib"
    (cd "$STAGING_PKCS11/usr/lib" && ln -sf "$MULTIARCH/librefineid_pkcs11.so" "librefineid_pkcs11.so")
fi

cat > "$STAGING_PKCS11/usr/share/p11-kit/modules/refineid.module" << 'P11EOF'
# RefineID FINEID PKCS#11 module
module: librefineid_pkcs11.so
trust-policy: no
critical: no
P11EOF
chmod 644 "$STAGING_PKCS11/usr/share/p11-kit/modules/refineid.module"

install -m 644 packaging/debian/50-refineid-pcscd.rules \
    "$STAGING_PKCS11/usr/share/polkit-1/rules.d/50-refineid-pcscd.rules"

cat > "$STAGING_PKCS11/etc/firefox/policies/policies.json" << POLICIESEOF
{
  "policies": {
    "SecurityDevices": {
      "FINEID": "$FIREFOX_LIB_PATH"
    }
  }
}
POLICIESEOF
chmod 644 "$STAGING_PKCS11/etc/firefox/policies/policies.json"

cat > "$STAGING_PKCS11/DEBIAN/conffiles" << 'CONFFILESEOF'
/etc/firefox/policies/policies.json
CONFFILESEOF
chmod 644 "$STAGING_PKCS11/DEBIAN/conffiles"

write_copyright "$STAGING_PKCS11/usr/share/doc/refineid-pkcs11/copyright" "refineid-pkcs11"

PKCS11_SHLIBS="$(calc_shlibdeps target/release/librefineid_pkcs11.so "libc6, libpcsclite1")"

cat > "$STAGING_PKCS11/DEBIAN/control" << CONTROLEOF
Package: refineid-pkcs11
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Multi-Arch: same
Maintainer: Petri Koistinen <petri.koistinen@refineid.fi>
Depends: ${PKCS11_SHLIBS}, p11-kit
Recommends: pcscd, libccid
Homepage: https://github.com/refineid/refineid-unix
Description: Open-source FINEID PKCS#11 module for Finnish identity cards
 RefineID PKCS#11 module enabling authentication, document signing, and
 card cryptography across web browsers (Firefox, Chrome), OpenSC, and
 NSS applications.
CONTROLEOF
chmod 644 "$STAGING_PKCS11/DEBIAN/control"

cat > "$STAGING_PKCS11/DEBIAN/postinst" << 'POSTINSTEOF'
#!/bin/sh
set -e

case "$1" in
    configure)
        if command -v ldconfig >/dev/null 2>&1; then
            ldconfig
        fi
        if [ -d /run/systemd/system ]; then
            if systemctl is-active --quiet polkit 2>/dev/null; then
                systemctl reload polkit 2>/dev/null || true
            fi
            systemctl enable --now pcscd.socket 2>/dev/null \
                || systemctl enable --now pcscd 2>/dev/null \
                || true
        fi
        ;;
    abort-upgrade|abort-remove|abort-deconfigure)
        ;;
    *)
        echo "postinst called with unknown argument \`$1'" >&2
        exit 1
        ;;
esac

exit 0
POSTINSTEOF
chmod 755 "$STAGING_PKCS11/DEBIAN/postinst"

cat > "$STAGING_PKCS11/DEBIAN/postrm" << 'POSTRMEOF'
#!/bin/sh
set -e

case "$1" in
    purge|remove|upgrade|disappear|abort-install|abort-upgrade|failed-upgrade)
        if command -v ldconfig >/dev/null 2>&1; then
            ldconfig
        fi
        if [ -d /run/systemd/system ]; then
            if systemctl is-active --quiet polkit 2>/dev/null; then
                systemctl reload polkit 2>/dev/null || true
            fi
        fi
        ;;
    *)
        echo "postrm called with unknown argument \`$1'" >&2
        exit 1
        ;;
esac

exit 0
POSTRMEOF
chmod 755 "$STAGING_PKCS11/DEBIAN/postrm"

cat > "$STAGING_PKCS11/DEBIAN/prerm" << 'PRERMEOF'
#!/bin/sh
set -e

case "$1" in
    remove|upgrade|deconfigure|failed-upgrade)
        ;;
    *)
        echo "prerm called with unknown argument \`$1'" >&2
        exit 1
        ;;
esac

exit 0
PRERMEOF
chmod 755 "$STAGING_PKCS11/DEBIAN/prerm"

dpkg-deb --build --root-owner-group "$STAGING_PKCS11" "$DEB_DIR/${PKG_PKCS11}.deb"
rm -rf "$STAGING_PKCS11"

# ==============================================================================
# Package 2: refineid-cli
# ==============================================================================
PKG_CLI="refineid-cli_${VERSION}_${ARCH}"
STAGING_CLI="$DEB_DIR/$PKG_CLI"
echo "Packaging $PKG_CLI..."
rm -rf "$STAGING_CLI" "$DEB_DIR/${PKG_CLI}.deb"
mkdir -p \
    "$STAGING_CLI/DEBIAN" \
    "$STAGING_CLI/usr/bin"

install -m 755 target/release/refineid "$STAGING_CLI/usr/bin/refineid"
write_copyright "$STAGING_CLI/usr/share/doc/refineid-cli/copyright" "refineid-cli"

CLI_SHLIBS="$(calc_shlibdeps target/release/refineid "libc6, libpcsclite1")"

cat > "$STAGING_CLI/DEBIAN/control" << CONTROLEOF
Package: refineid-cli
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Multi-Arch: foreign
Maintainer: Petri Koistinen <petri.koistinen@refineid.fi>
Depends: ${CLI_SHLIBS}
Recommends: pcscd, libccid, refineid-pkcs11
Homepage: https://github.com/refineid/refineid-unix
Description: Open-source FINEID command-line tool for Finnish identity cards
 RefineID command-line interface for smart card status inspection, PIN verification
 and change, remote card pairing (RAPP), and authentication testing.
CONTROLEOF
chmod 644 "$STAGING_CLI/DEBIAN/control"

dpkg-deb --build --root-owner-group "$STAGING_CLI" "$DEB_DIR/${PKG_CLI}.deb"
rm -rf "$STAGING_CLI"

# ==============================================================================
# Package 3: refineid-gui
# ==============================================================================
PKG_GUI="refineid-gui_${VERSION}_${ARCH}"
STAGING_GUI="$DEB_DIR/$PKG_GUI"
echo "Packaging $PKG_GUI..."
rm -rf "$STAGING_GUI" "$DEB_DIR/${PKG_GUI}.deb"
mkdir -p \
    "$STAGING_GUI/DEBIAN" \
    "$STAGING_GUI/usr/bin" \
    "$STAGING_GUI/usr/share/applications" \
    "$STAGING_GUI/usr/share/icons/hicolor/scalable/apps"

install -m 755 target/release/refineid-gui "$STAGING_GUI/usr/bin/refineid-gui"

install -m 644 packaging/refineid.desktop \
    "$STAGING_GUI/usr/share/applications/refineid.desktop"

install -m 644 crates/refineid-gui/assets/app-icon.svg \
    "$STAGING_GUI/usr/share/icons/hicolor/scalable/apps/refineid.svg"

write_copyright "$STAGING_GUI/usr/share/doc/refineid-gui/copyright" "refineid-gui"

GUI_SHLIBS="$(calc_shlibdeps target/release/refineid-gui "libc6, libpcsclite1, libx11-6, libxcursor1, libxi6, libxrandr2, libfontconfig1")"

cat > "$STAGING_GUI/DEBIAN/control" << CONTROLEOF
Package: refineid-gui
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: Petri Koistinen <petri.koistinen@refineid.fi>
Depends: ${GUI_SHLIBS}, refineid-cli (= ${VERSION})
Recommends: refineid-pkcs11 (= ${VERSION})
Homepage: https://github.com/refineid/refineid-unix
Description: Graphical user interface for Finnish identity cards
 RefineID graphical desktop application for PIN management, card portrait and
 signature inspection, document signing, and pairing management.
CONTROLEOF
chmod 644 "$STAGING_GUI/DEBIAN/control"

cat > "$STAGING_GUI/DEBIAN/postinst" << 'POSTINSTEOF'
#!/bin/sh
set -e

case "$1" in
    configure)
        if command -v update-desktop-database >/dev/null 2>&1; then
            update-desktop-database -q /usr/share/applications || true
        fi
        if command -v gtk-update-icon-cache >/dev/null 2>&1; then
            gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
        fi
        ;;
    abort-upgrade|abort-remove|abort-deconfigure)
        ;;
    *)
        echo "postinst called with unknown argument \`$1'" >&2
        exit 1
        ;;
esac

exit 0
POSTINSTEOF
chmod 755 "$STAGING_GUI/DEBIAN/postinst"

cat > "$STAGING_GUI/DEBIAN/postrm" << 'POSTRMEOF'
#!/bin/sh
set -e

case "$1" in
    purge|remove|upgrade|disappear|abort-install|abort-upgrade|failed-upgrade)
        if command -v update-desktop-database >/dev/null 2>&1; then
            update-desktop-database -q /usr/share/applications || true
        fi
        if command -v gtk-update-icon-cache >/dev/null 2>&1; then
            gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
        fi
        ;;
    *)
        echo "postrm called with unknown argument \`$1'" >&2
        exit 1
        ;;
esac

exit 0
POSTRMEOF
chmod 755 "$STAGING_GUI/DEBIAN/postrm"

dpkg-deb --build --root-owner-group "$STAGING_GUI" "$DEB_DIR/${PKG_GUI}.deb"
rm -rf "$STAGING_GUI"

# ==============================================================================
# Package 4: refineid (Metapackage)
# ==============================================================================
PKG_META="refineid_${VERSION}_all"
STAGING_META="$DEB_DIR/$PKG_META"
echo "Packaging $PKG_META (metapackage)..."
rm -rf "$STAGING_META" "$DEB_DIR/${PKG_META}.deb"
mkdir -p "$STAGING_META/DEBIAN"

write_copyright "$STAGING_META/usr/share/doc/refineid/copyright" "refineid"

cat > "$STAGING_META/DEBIAN/control" << CONTROLEOF
Package: refineid
Version: ${VERSION}
Section: metapackages
Priority: optional
Architecture: all
Maintainer: Petri Koistinen <petri.koistinen@refineid.fi>
Depends: refineid-cli (>= ${VERSION}), refineid-pkcs11 (>= ${VERSION}), refineid-gui (>= ${VERSION})
Recommends: pcscd, libccid, pcsc-tools
Homepage: https://github.com/refineid/refineid-unix
Description: Open-source FINEID middleware for Finnish identity cards (metapackage)
 RefineID is an open-source FINEID smart-card middleware for Finnish identity
 cards on Linux. This metapackage installs the command-line tool, PKCS#11 module,
 and desktop GUI.
CONTROLEOF
chmod 644 "$STAGING_META/DEBIAN/control"

cat > "$STAGING_META/DEBIAN/postinst" << 'POSTINSTEOF'
#!/bin/sh
set -e

case "$1" in
    configure)
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload || true
            systemctl enable --now pcscd.socket 2>/dev/null \
                || systemctl enable --now pcscd 2>/dev/null \
                || true
        fi
        ;;
    abort-upgrade|abort-remove|abort-deconfigure)
        ;;
    *)
        echo "postinst called with unknown argument \`$1'" >&2
        exit 1
        ;;
esac

exit 0
POSTINSTEOF
chmod 755 "$STAGING_META/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "$STAGING_META" "$DEB_DIR/${PKG_META}.deb"
rm -rf "$STAGING_META"

echo ""
echo "Successfully built Debian packages in $DEB_DIR:"
ls -lh "$DEB_DIR"/*.deb

if [ "$DO_INSTALL" -eq 1 ]; then
    echo ""
    echo "Installing Debian packages with package manager..."
    DEB_FILES="$(ls -1 "$PWD/$DEB_DIR"/refineid-pkcs11_${VERSION}_*.deb \
                       "$PWD/$DEB_DIR"/refineid-cli_${VERSION}_*.deb \
                       "$PWD/$DEB_DIR"/refineid-gui_${VERSION}_*.deb \
                       "$PWD/$DEB_DIR"/refineid_${VERSION}_all.deb)"
    SUDO=""
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
        else
            echo "error: root privileges required to install packages" >&2
            exit 1
        fi
    fi
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get install -y --reinstall $DEB_FILES
    else
        $SUDO dpkg -i $DEB_FILES
    fi
    echo ""
    echo "Installed RefineID packages:"
    dpkg -l 'refineid*'
fi
