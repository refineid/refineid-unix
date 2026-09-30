# RefineID for Unix

**Refined Electronic Identification.**

Open Source reimplementation of FINEID middleware for Finnish identity
card users, built from
[public specifications](https://dvv.fi/en/fineid-specifications) --
never from guesswork or from reverse-engineering the incumbent. The
specifications this tree implements are indexed, with what each one
governs, in [`doc/references.md`](doc/references.md).

This repository is the Unix (Linux and BSD) tree. It ships three
things:

- **`refineid`** -- command-line tool: card readout, PIN management,
  qualified document signing (PAdES / CAdES / ASiC-E with RFC 3161
  timestamps and eIDAS trusted-list validation), revocation checks.
- **`librefineid_pkcs11.so`** -- PKCS#11 v2.40 module (read-only,
  sign-only) for Firefox/NSS card login, and for OpenSSL / GnuTLS /
  OpenSSH through p11-kit.
- **`refineid-gui`** -- desktop GUI: PIN activation, PIN
  change, PUK unblock, viewing the card's portrait and signature
  images, and PDF document signing. (See [GUI Architecture](doc/gui-architecture.md)).

Project stage: beta. The CLI, the PKCS#11 Firefox/NSS card login, and
the reproducible NixOS install are proven against real FINEID
hardware; breadth of card-model coverage is still growing, and
PIN-change stays off by default until validated on a 2026 ECC card.
The macOS/iPadOS app lives in
[RefineID-Apple](https://github.com/refineid/refineid-apple).

## Install

See [INSTALL](INSTALL) for full installation and uninstallation instructions.

- **Debian / Ubuntu (.deb package)**:
  ```sh
  script/package-deb.sh
  sudo apt install ./target/deb/refineid_*.deb
  ```

- **NixOS**:
  See [doc/install-nixos.md](doc/install-nixos.md) for declarative system installation.

- **Generic source build**:
  ```sh
  cargo build --release --workspace
  ```

## Development checks

Install the repository's mandatory Git hooks once per clone:

```sh
script/install-githook.sh
```

The pre-commit hook checks formatting and the workspace; the pre-push hook
runs the complete build, test, Clippy, and rustdoc floor. Keep the hooks
enabled for every commit and push. GitHub's Nix workflow is an optional
manual run plus a weekly build for both x86_64 and arm64; it complements the
native local gates without repeating them on every push and pull request.

### Managing build cache

During development, Cargo build artifacts and `rustc` incremental compilation caches can grow significantly.

```sh
# Sweep unused build artifacts older than 14 days
cargo sweep -t 14

# Clean incremental compilation cache if disk space is needed
find target -type d -name "incremental" -prune -exec rm -rf {} +
```

## Workspace layout

| Crate | Purpose |
| --- | --- |
| [refineid-lib-core](crates/refineid-lib-core/) | FINEID smartcard protocol core: APDUs, PACE, secure messaging, eMRTD, X.509/CRL/OCSP/CMS parsing and verification. No I/O, no platform code. |
| [refineid-lib-pcsc](crates/refineid-lib-pcsc/) | PC/SC adapter implementing the core's reader/transport ports. |
| [refineid-lib-tls](crates/refineid-lib-tls/) | Server-authenticated HTTPS client (rustls) for timestamp authorities and EU trusted lists. |
| [refineid-client](crates/refineid-client/) | Client library and the `refineid` CLI. |
| [refineid-pkcs11](crates/refineid-pkcs11/) | PKCS#11 v2.40 cdylib for Firefox/NSS card login. |
| [refineid-gui](crates/refineid-gui/) | Desktop GUI (Slint): PIN management, portrait/signature, document signing. |

## Maintainer

Petri Koistinen <petri.koistinen@refineid.fi>. Issues and discussion:
<https://github.com/refineid/refineid-unix>.

## License

Apache-2.0. See [LICENSE](LICENSE).
