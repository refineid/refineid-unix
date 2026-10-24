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

# Build a signed package repository from every package in a directory.
#
#   ubuntu:  <site>/ubuntu with pool/main/r/refineid, dists/<suite>/main/
#            binary-<arch>/Packages{,.gz,.xz}, Release signed into InRelease
#            and Release.gpg, and the public key <site>/ubuntu/refineid.asc.
#            Runs on Debian or Ubuntu (apt-ftparchive, gpg, gpgv).
#   freebsd: <site>/freebsd/<ABI>/All/*.pkg indexed by `pkg repo` and signed
#            with the RSA key, and the public key <site>/freebsd/refineid.pub.
#            Runs on FreeBSD.
#
# Each repository is checked against its exported public key before the
# script returns.
#
# Usage:
#   script/package-repo.sh ubuntu  <secret-key.asc> <package-dir> <site-dir>
#   script/package-repo.sh freebsd <rsa-key.pem>    <package-dir> <site-dir>

set -eu

UBUNTU_SUITE="resolute"
APT_COMPONENT="main"
APT_ARCHITECTURES="amd64 arm64"
APT_POOL="pool/main/r/refineid"
REPO_LABEL="RefineID"

usage() {
    echo "usage: $0 ubuntu|freebsd <key> <package-dir> <site-dir>" >&2
    exit 2
}

[ "$#" -eq 4 ] || usage
KIND="$1"
KEY="$2"
INCOMING="$3"
SITE="$4"
[ -f "$KEY" ] || { echo "error: no key file $KEY" >&2; exit 1; }
[ -d "$INCOMING" ] || { echo "error: no package directory $INCOMING" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

ubuntu_repo() {
    root="$SITE/ubuntu"
    rm -rf "$root"
    mkdir -p "$root/$APT_POOL"
    found=0
    for deb in "$INCOMING"/*.deb; do
        [ -f "$deb" ] || continue
        cp "$deb" "$root/$APT_POOL/"
        found=1
    done
    [ "$found" -eq 1 ] || { echo "error: no .deb in $INCOMING" >&2; exit 1; }

    GNUPGHOME="$WORK/gnupg"
    export GNUPGHOME
    install -d -m 700 "$GNUPGHOME"
    gpg --batch --quiet --import "$KEY"
    fingerprint="$(gpg --batch --with-colons --list-secret-keys \
        | awk -F: '$1 == "fpr" { print $10; exit }')"
    [ -n "$fingerprint" ] || { echo "error: $KEY holds no secret key" >&2; exit 1; }

    dists="dists/$UBUNTU_SUITE"
    for arch in $APT_ARCHITECTURES; do
        dir="$dists/$APT_COMPONENT/binary-$arch"
        mkdir -p "$root/$dir"
        (cd "$root" && apt-ftparchive --arch "$arch" packages "$APT_POOL") \
            > "$root/$dir/Packages"
        gzip -9nk "$root/$dir/Packages"
        xz -9k "$root/$dir/Packages"
    done

    (cd "$root" && apt-ftparchive \
        -o APT::FTPArchive::Release::Origin="$REPO_LABEL" \
        -o APT::FTPArchive::Release::Label="$REPO_LABEL" \
        -o APT::FTPArchive::Release::Suite="$UBUNTU_SUITE" \
        -o APT::FTPArchive::Release::Codename="$UBUNTU_SUITE" \
        -o APT::FTPArchive::Release::Architectures="$APT_ARCHITECTURES" \
        -o APT::FTPArchive::Release::Components="$APT_COMPONENT" \
        release "$dists") > "$WORK/Release"
    mv "$WORK/Release" "$root/$dists/Release"
    gpg --batch --yes --local-user "$fingerprint" --clearsign \
        --output "$root/$dists/InRelease" "$root/$dists/Release"
    gpg --batch --yes --local-user "$fingerprint" --detach-sign --armor \
        --output "$root/$dists/Release.gpg" "$root/$dists/Release"
    gpg --batch --export --armor "$fingerprint" > "$root/refineid.asc"

    gpg --batch --dearmor < "$root/refineid.asc" > "$WORK/public.gpg"
    gpgv --keyring "$WORK/public.gpg" "$root/$dists/InRelease"
    gpgv --keyring "$WORK/public.gpg" "$root/$dists/Release.gpg" "$root/$dists/Release"
    echo "Ubuntu repository: $root (signing key $fingerprint)"
}

freebsd_repo() {
    root="$SITE/freebsd"
    rm -rf "$root"
    mkdir -p "$root"
    found=0
    for package in "$INCOMING"/*.pkg; do
        [ -f "$package" ] || continue
        abi="$(pkg query -F "$package" '%q')"
        mkdir -p "$root/$abi/All"
        cp "$package" "$root/$abi/All/"
        found=1
    done
    [ "$found" -eq 1 ] || { echo "error: no .pkg in $INCOMING" >&2; exit 1; }

    openssl rsa -in "$KEY" -pubout -out "$root/refineid.pub" 2>/dev/null

    for dir in "$root"/*/; do
        pkg repo -q "${dir%/}" "$KEY"
    done

    # pkg update drops a repository whose signature fails and still exits
    # zero, so the check is that the signed catalogue lists packages.
    abi="$(pkg config ABI)"
    [ -d "$root/$abi" ] || { echo "error: no $abi packages to check" >&2; exit 1; }
    mkdir -p "$WORK/repos" "$WORK/db" "$WORK/cache"
    printf '%s: { url: "file://%s", signature_type: "pubkey", pubkey: "%s", enabled: yes }\n' \
        "$REPO_LABEL" "$(cd "$root/$abi" && pwd)" "$(cd "$root" && pwd)/refineid.pub" \
        > "$WORK/repos/refineid.conf"
    pkg -o PKG_DBDIR="$WORK/db" -o PKG_CACHEDIR="$WORK/cache" \
        -o REPOS_DIR="$WORK/repos" update -q -f
    listed="$(pkg -o PKG_DBDIR="$WORK/db" -o PKG_CACHEDIR="$WORK/cache" \
        -o REPOS_DIR="$WORK/repos" rquery -r "$REPO_LABEL" '%n-%v' || true)"
    [ -n "$listed" ] || { echo "error: $root/$abi does not verify with refineid.pub" >&2; exit 1; }
    printf '%s\n' "$listed"
    echo "FreeBSD repository: $root"
}

case "$KIND" in
    ubuntu) ubuntu_repo ;;
    freebsd) freebsd_repo ;;
    *) usage ;;
esac
