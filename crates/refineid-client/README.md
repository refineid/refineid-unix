# refineid-client

Client library and the `refineid` command-line tool.

## Subcommand groups

- **Card readout** (no PIN): `card` walks every FINEID-responding reader and prints a full report
  -- identity, certificate chain with CRL/OCSP revocation, PIN counters,
  optionally the eMRTD layer when a CAN is supplied.
  `card pubkey` and `card emrtd` are the read-only siblings.
- **PIN-gated crypto**: `card sign-auth`, `card sign-qualified`,
  `document sign` (PAdES / CAdES / ASiC-E), `card decrypt-auth`.
- **PIN management**: `pin activate`, `pin change 1|2`, `pin unblock 1|2`.
- **Offline tools**: `verify`, `cert show`, `cert chain`.

## Contents

- `cli/` + `cli.rs` -- hand-rolled typed argv parsing (no clap; typed `ArgParseError`, per-subcommand parsers)
  and the verb dispatcher.
- `card_check.rs` -- the full card report:
  chain building, CRL/OCSP verification, and the eMRTD section.
- `card_sign.rs` / `card_decrypt.rs` / `card_pin.rs` / `card_pubkey.rs` / `card_emrtd.rs` / `card_export.rs`
  -- per-command card operations.
- `signed_name.rs` -- the default name of a signed document, shared with the GUI.
- `http.rs` -- a deliberately minimal plain-HTTP client for CRL/OCSP fetches
  (payloads are CA-signed; bounded bodies, no redirects).
- `trust_roots.rs`, `verify.rs`, `cert_show.rs`, `cert_chain.rs`, `exit_status.rs` (sysexits-style codes),
  `events.rs`, `apdu_trace.rs`.
- `bin/refineid.rs` -- the thin CLI entry point.
