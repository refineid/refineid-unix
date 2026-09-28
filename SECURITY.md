# Security Policy

**Open a public issue.** Full technical detail is expected and wanted, including
the attack path, the reachable code, and why the control that should prevent it
does not. A fix needs the mechanism, not a summary. A public record also means
the next reviewer can see what was considered, what was rejected, and why,
instead of rediscovering it.

Report what is broken, with `file:line`, the quoted code, and a concrete
scenario. Do not soften the finding and do not file it as a question. Label it
`security` plus the severity you judge, and say plainly what you could not
establish.

There is no embargo and no private channel. RefineID is pre-release and
single-maintainer; coordinated disclosure buys nothing that a public issue does
not, and the delay costs the project the other fixes in the queue.

## Never in a report, public or otherwise

A real PIN, PUK, CAN, candidate PIN length, private key, full personal
certificate, personal identity code, or unredacted event log. Those values
identify a real person, and nothing published on the internet can be
unpublished.

Sanitized status words, `0x` status values, and APDU shapes carry all the
information a fix needs. Never commit test PINs or card secrets.

RefineID handles card credentials and retry-limited operations, so a card
lockout caused by a bad report is a real harm to a real citizen. Name the card
generation and reader, not a card identity.

## Inviolable Rule #1: PIN codes NEVER travel over any network

PIN codes (PIN1 and PIN2) NEVER leave the mobile device when accessed via RAPP.
RAPP must absolutely deny and preclude all attempts to transport PIN codes
anywhere:

- The protocol wire format has no field or message for PIN codes.
- PIN1 remains in protected on-device cache on the phone.
- PIN2 prompts appear exclusively on the mobile device screen.
- The host computer operates via a protected authentication path
  (`CKF_PROTECTED_AUTHENTICATION_PATH`) without any PIN prompts or transport.

## Inviolable Rule #2: Zero PIN data and candidate PIN-length logging across all environments

Never log, trace, display, or format PIN bytes, character offsets, supplied or
candidate PIN lengths, or development PIN role identifiers in log sinks, audit
records, or error strings. Only static specification policy bounds may be
reported. Never commit test PINs or card secrets.
