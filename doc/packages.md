# Packages

RefineID publishes signed package repositories at `https://pkg.refineid.fi`,
one path per distribution: `/ubuntu` for Ubuntu 26.04 LTS (amd64, arm64)
and `/freebsd` for FreeBSD 15 (amd64). `/debian` is reserved for Debian.
A new release arrives through `apt upgrade` and `pkg upgrade`.

## Install

### Ubuntu 26.04

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/refineid.asc https://pkg.refineid.fi/ubuntu/refineid.asc
sudo tee /etc/apt/sources.list.d/refineid.sources >/dev/null <<'EOF'
Types: deb
URIs: https://pkg.refineid.fi/ubuntu
Suites: resolute
Components: main
Signed-By: /etc/apt/keyrings/refineid.asc
EOF
sudo apt update
sudo apt install refineid
```

The same source as one line, in `/etc/apt/sources.list.d/refineid.list`
instead of `refineid.sources`:

```
deb [signed-by=/etc/apt/keyrings/refineid.asc] https://pkg.refineid.fi/ubuntu resolute main
```

`curl` is `sudo apt install curl` where it is missing. `refineid` installs
the CLI, the desktop application and the PKCS#11 module, with pcscd and
the CCID driver.

#### Firefox

Ubuntu's Firefox is a snap, and a snap cannot load a PKCS#11 module from
the host ([#74](https://github.com/refineid/refineid-unix/issues/74)).
Install Firefox from Mozilla's APT repository instead, with the steps
[Mozilla documents](https://support.mozilla.org/en-US/kb/install-firefox-linux#w_install-firefox-deb-package-for-debian-based-and-ubuntu-based-distributions-recommended):

```sh
sudo install -d -m 0755 /etc/apt/keyrings
wget -q https://packages.mozilla.org/apt/repo-signing-key.gpg -O- | sudo tee /etc/apt/keyrings/packages.mozilla.org.asc > /dev/null
gpg -n -q --import --import-options import-show /etc/apt/keyrings/packages.mozilla.org.asc | awk '/pub/{getline; gsub(/^ +| +$/,""); if($0 == "35BAA0B33E9EB396F59CA838C0BA5CE6DC6315A3") print "\nThe key fingerprint matches ("$0").\n"; else print "\nVerification failed: the fingerprint ("$0") does not match the expected one.\n"}'
sudo tee /etc/apt/sources.list.d/mozilla.sources > /dev/null << EOF
Types: deb
URIs: https://packages.mozilla.org/apt
Suites: mozilla
Components: main
Signed-By: /etc/apt/keyrings/packages.mozilla.org.asc
EOF
sudo tee /etc/apt/preferences.d/mozilla > /dev/null << EOF
Package: *
Pin: origin packages.mozilla.org
Pin-Priority: 1000
EOF
sudo apt-get update
sudo apt-get install firefox
```

The third command must report that the fingerprint matches. The pin
makes Mozilla's `firefox` deb win over Ubuntu's `firefox` package, which
only installs the snap. Mozilla's page also describes moving the snap
profile (Data migration); after that, `sudo snap remove firefox` removes
the snap. The Firefox policy in the `refineid` package loads the module
into the deb Firefox.

### FreeBSD 15

As root:

```sh
mkdir -p /usr/local/etc/pkg/keys /usr/local/etc/pkg/repos
fetch -o /usr/local/etc/pkg/keys/refineid.pub https://pkg.refineid.fi/freebsd/refineid.pub
cat > /usr/local/etc/pkg/repos/refineid.conf <<'EOF'
refineid: {
  url: "https://pkg.refineid.fi/freebsd/${ABI}",
  signature_type: "pubkey",
  pubkey: "/usr/local/etc/pkg/keys/refineid.pub",
  enabled: yes
}
EOF
pkg update
pkg install refineid
```

The package depends on pcsc-lite, libccid, p11-kit and nss. Installing it
enables pcscd with `--disable-polkit` in `/etc/rc.conf` and starts it;
removing the package leaves `/etc/rc.conf` as it is. An ACS reader needs
the ACS driver as [install-freebsd.md](install-freebsd.md) section 2
describes; the package does not move the CCID driver aside.

### Known limits

- Ubuntu's Chromium is a snap and cannot load the module
  ([#74](https://github.com/refineid/refineid-unix/issues/74)). The
  NSS autostart entry the package installs reaches a Chromium installed
  as a deb.

## Pipeline

`.github/workflows/packages.yml` runs on a pushed `v<VERSION>` tag, where
`<VERSION>` is the content of `VERSION`, and on a manual run.

| Job | Runs on | Does |
| --- | --- | --- |
| `prepare` | Ubuntu runner | checks that the tag names `VERSION`; resolves refineid-core `main` to one commit |
| `deb` | `ubuntu:26.04` container on an amd64 and an arm64 runner | builds with that core commit, `script/package-deb.sh` |
| `freebsd` | FreeBSD 15.1 amd64 VM ([vmactions/freebsd-vm](https://github.com/vmactions/freebsd-vm)) | builds with that core commit, `script/package-freebsd.sh` |
| `release` | Ubuntu runner, tag only | creates the GitHub Release for the tag with every `.deb` and `.pkg`; the notes name the core commit |
| `repository` | Ubuntu runner and the FreeBSD VM, environment `packages` | collects this run's packages and those of every release, builds the signed repositories with `script/package-repo.sh` and uploads them as the Pages artifact |
| `deploy` | Ubuntu runner, tag only, environment `github-pages` | deploys the artifact to GitHub Pages |

A manual run is the dry run: it builds and signs everything and keeps the
packages and the site as workflow artifacts, without a release or a
deployment.

The build tracks refineid-core `main` at the moment of the run, never
the revision in `Cargo.lock`; both builds use the same commit, and the
release notes record it.

Repository layout:

```
ubuntu/refineid.asc                    public key (OpenPGP, armored)
ubuntu/dists/resolute/{InRelease,Release,Release.gpg}
ubuntu/dists/resolute/main/binary-{amd64,arm64}/Packages{,.gz,.xz}
ubuntu/pool/main/r/refineid/*.deb
freebsd/refineid.pub                   public key (RSA, PEM)
freebsd/FreeBSD:15:amd64/{meta.conf,packagesite.pkg,data.pkg,...}
freebsd/FreeBSD:15:amd64/All/*.pkg
```

Every package of every release stays in the index. The site is rebuilt
from the GitHub Releases on each tag, so the Releases are the archive and
the site can be regenerated from them at any time. GitHub Pages limits a
published site to 1 GB.

`script/package-repo.sh` checks each repository against the public key
it exports before the job continues: `gpgv` on `InRelease` and
`Release.gpg`, and `pkg update` plus `pkg rquery` from the signed
FreeBSD repository.

## Secrets

Both secrets are environment secrets of the `packages` environment, so
only the `repository` job sees them.

| Secret | Content |
| --- | --- |
| `APT_SIGNING_KEY` | armored OpenPGP secret key, Ed25519, no passphrase |
| `PKG_SIGNING_KEY` | PEM RSA 4096 private key |

## One-time setup

1. Create the apt signing key on an offline machine:

   ```sh
   export GNUPGHOME="$(mktemp -d)"
   gpg --batch --passphrase '' --quick-gen-key "RefineID packages" ed25519 sign never
   gpg --armor --export-secret-keys "RefineID packages" > apt-signing-key.asc
   gpg --fingerprint "RefineID packages"
   ```

2. Create the pkg signing key:

   ```sh
   openssl genrsa -out pkg-signing-key.pem 4096
   openssl rsa -in pkg-signing-key.pem -pubout | openssl dgst -sha256
   ```

3. Create the `packages` environment (Settings > Environments) with
   deployment branches and tags limited to the tag pattern `v*` and the
   branch `main`, and store the keys in it:

   ```sh
   gh secret set APT_SIGNING_KEY --env packages --repo refineid/refineid-unix < apt-signing-key.asc
   gh secret set PKG_SIGNING_KEY --env packages --repo refineid/refineid-unix < pkg-signing-key.pem
   ```

   Keep an offline copy of both files, then delete them from the machine.

4. Settings > Pages: source "GitHub Actions", custom domain
   `pkg.refineid.fi`, "Enforce HTTPS" once the certificate is issued.
   In Settings > Environments > `github-pages`, add the tag pattern `v*`
   to the deployment branches and tags: Pages deploys from the tag.

5. DNS: a `CNAME` record `pkg.refineid.fi` pointing at
   `refineid.github.io`. Verifying `pkg.refineid.fi` for the organization
   (organization Settings > Pages > Verified domains, a `TXT` record)
   keeps any other repository from claiming the name.

6. Publish the two fingerprints from steps 1 and 2 on the beta page next
   to the install snippets.

7. Run the workflow manually from `main` (Actions > packages > Run
   workflow) as the dry run, then push the first tag.

## Rotating a key

1. Create the new key as in the one-time setup and replace the secret
   with `gh secret set`.
2. Push a tag, or re-run the `repository` job of the last tag's run: the
   repository is re-signed with the new key, and the new public key replaces
   `ubuntu/refineid.asc` or `freebsd/refineid.pub`.
3. Every user repeats the key download line of the install snippet;
   until then `apt update` and `pkg update` reject the repository.
   Announce the new fingerprint on the beta page.

A key that leaked is rotated the same way, at once.
