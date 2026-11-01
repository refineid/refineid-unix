# RefineID GUI

Native desktop application for managing supported FINEID cards through PC/SC readers.

## User interface principles

The interface follows **simple as possible, but no simpler**:

- Do not add redundant headings, explanatory success text, nested intention levels, decorative indentation, or layout-only whitespace.
- One window, laid out as [doc/gui-architecture.md](../../doc/gui-architecture.md) section 4.4 describes; the PIN codes have a window of their own.
- Align related controls using stable columns.

## Status messages

Show feedback only when it helps the user act:

- Show concise success/failure feedback for PIN activation, PIN changes, and PIN reactivation, on every supported card generation (S4-1 v3.1 RSA-3072 and v4.0 ECC P-384).
- Show detailed information for errors and warnings.
- Do not show routine success messages such as card discovery or card selection.

## Numeric secret input and validation

- PIN, PUK, activation-code, and CAN fields accept digits only.
- Secret fields are masked where appropriate and input is length-limited before card commands are sent.
- Reject predictable weak PINs in the GUI, including obvious repeated and consecutive-digit values.
- Validate PIN confirmation live, but avoid premature mismatch feedback until both fields have their minimum relevant length and equal entered length.

## Reactivation and PUK retries

- The PIN codes window lists the PUK's retry count beside the PINs' while
  it is below full.
- Reactivation errors must be user-facing, never Rust debug output.
- `WrongPuk { retries_left: ... }` is rendered as `Wrong PUK. N attempts remaining.`
- The PUK has its own retry counter. A successful reset-retry-counter command
  resets both the target PIN retry counter and the PUK try counter to their
  configured limits; production old- and new-generation cards confirm this.
- Query PUK retries with the credential-free PIN-container `GET DATA` form
  from FINEID S1 v4.2 section 3.15. Never probe by submitting an intentionally
  wrong PUK because that consumes an attempt.
- A locked or invalidated PUK/card is terminal and should clearly tell the user that replacement is required.

## Card status monitoring

- Open the window immediately. Full card inspection runs outside the
  toolkit's UI thread.
- No timed polling. A background monitor parks in `SCardGetStatusChange`
  and requests one inspection per card insertion/removal or reader
  arrival. Peer activity that does not change presence (a browser
  holding the card for a TLS signature) never triggers card traffic.
- Never overlap full inspections. Buttons remain disabled while an inspection
  is in flight, and completed reports are applied on the UI event loop.

## Versioning

The window title shows the project version `YY.M.D.B`
([doc/packages.md](../../doc/packages.md#version)).

## Validation

Run the crate check after UI or behavior changes:

```text
cargo check -p refineid-gui
```

When a visible behavior change is requested, rebuild and launch the application with:

```text
cargo run -p refineid-gui
```
