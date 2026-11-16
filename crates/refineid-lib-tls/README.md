# refineid-lib-tls

Address-pinned, server-authenticated HTTPS client (`simple_https`, backed
by rustls behind the `tls-rustls` feature) for public-infrastructure
fetches: RFC 3161 timestamp authorities, EU trusted lists, validator APIs.

## Contents

- `simple_https.rs` -- address-pinned HTTPS GET/POST (`get_to`, `post_to`,
  `post_to_authorized`) with bounded response size; the caller resolves and
  vets destination addresses and enforces redirect policy.
- `http.rs` / `framing.rs` -- TLS-agnostic HTTP/1.1 response-head parsing
  and bounded response framing.
- `client_auth.rs` -- RAPP-backed client-authenticated TLS diagnostic probe
  (behind `tls-rustls`).

Used by `refineid-client` for its HTTPS needs.
