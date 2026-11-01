# DVV terminology

Code identifiers use universal PKI terms; user-facing strings
(CLI prompts, error messages, audit JSON `human` field, doc copy)
use the DVV vocabulary.

## Codes that protect the card

A FINEID card protects key operations with PIN 1 and PIN 2,
which the holder sets during activation, and the PUK, which
unblocks them. The activation letter carries the activation
PIN.

| Code identifier in repo | English              | suomi                   | svenska         | Length         | Set by   |
|-------------------------|----------------------|-------------------------|-----------------|----------------|----------|
| `Pin1`                  | basic PIN            | perustunnusluku         | grundkod        | 4-12 digits    | holder   |
| `Pin2`                  | signature PIN        | allekirjoitustunnusluku | signaturkod     | 6-12 digits    | holder   |
| `ActivationCode`        | activation PIN       | aktivointitunnusluku    | aktiveringskod  | 8 digits (§4.6.1) / 7 digits (§4.6.2) | DVV (in the activation letter) |
| `Puk`                   | PUK code             | PUK-tunnusluku          | PUK-kod         | 8-12 digits    | DVV      |

UI text writes "PIN 1" and "PIN 2" with a space.

### The two activation schemes

FINEID S4-1 v4.2 §4.6 defines two activation procedures, and the
card decides which one applies:

- **§4.6.1, the activation code is the PUK.** Citizen cards
  issued before 13 January 2026, and every organization card.
  PIN 1 and PIN 2 ship blocked; activation sends RESET RETRY
  COUNTER with the 8-digit code from the letter for each PIN.
  The code stays the card's PUK afterwards.
- **§4.6.2, preset activation PIN.** Citizen cards issued from
  13 January 2026. PIN 1 and PIN 2 ship set to one 7-digit
  activation PIN; activation sends CHANGE REFERENCE DATA from
  that PIN for each PIN. The PUK is a separate code.

The organization reference numbering (FINEID S4-2 v4.0 §4.2)
decides §4.6.1; under the citizen numbering the authentication
certificate's validity start decides. Neither the ATR nor the
issuer name does. The card's issuance date is also printed on
its surface.

In refineid the two activation entries are *two distinct
types*:

- `ActivationPinEight` -- the §4.6.1 activation code
  (`ActivationScheme::ActivationCodeIsPuk`).
- `ActivationPinSeven` -- the §4.6.2 preset activation PIN
  (`ActivationScheme::PresetActivationPin`).
- `Puk` -- the unblock code, 8 to 12 digits under either scheme.

The CLI and the GUI read the scheme from the card before
prompting and build the matching type; `activate_first` refuses
a variant that does not match the card's scheme before any
modify APDU goes out.

refineid uses the activation PIN only for activation and the PUK
for `pin unblock 1` / `pin unblock 2`. FINEID S4-1 v4.2 §4.6
requires both PINs to be initialized, but there is no combined
two-PIN card command: refineid sends one per-PIN command for
PIN 1 and then one for PIN 2. Later recovery targets only the
selected blocked PIN.

The terms above are DVV's own -- see the activation letter that
ships with every new card and the public DVV pages.

Canonical DVV sources:

- <https://dvv.fi/en/personal-identity-code>
- <https://dvv.fi/henkilotunnus>
- <https://dvv.fi/sv/personbeteckning>
- <https://dvv.fi/citizen-certificate>

## Operational rules for each code

### `Pin1` / `Pin2`

- Set during card activation (citizen chooses).
- Card-side try counter; 5 wrong tries blocks the PIN.
- A blocked PIN is recoverable only via the PUK
  (`pin unblock 1` / `pin unblock 2`).

### Activation PIN (`aktivointitunnusluku` / `aktiveringskod`)

- §4.6.1: the 8-digit activation code, which is the PUK; each
  wrong try spends one of the PUK's tries.
- §4.6.2: the 7-digit preset activation PIN, the factory value
  of PIN 1 and PIN 2; each wrong try spends one of that PIN's
  tries.
- Used during activation to set the initial `Pin1` and `Pin2`.
- Distributed inside the DVV activation letter that ships with
  the card. The letter explicitly warns to keep it separate
  from the card.

### PUK (`PUK-tunnusluku` / `PUK-kod`)

- 8 to 12 digits (FINEID S4-1 v4.2 §8.1.5, EF.AOD: minLength 8,
  storedLength 12).
- Under §4.6.1 the activation letter's code is the PUK; under
  §4.6.2 the PUK is separately ordered from DVV, a *paid
  service*.
- Used to unblock `Pin1` / `Pin2` after lockout.
- PUK has its own try counter. Exhausting it permanently
  bricks the card -- DVV reissue is the only recovery.
- FINEID S4-1 v4.2 section 4.1 sets the PUK try limit to 5,
  its usage counter to `No limit`, and both PIN unblocking counters
  to `No limit`. A successful unblock resets the PUK retry counter.
- refineid's `pin unblock 1 / pin unblock 2` drive
  this code via the PKCS#15 `RESET RETRY COUNTER` APDU.

### CAN (Card Access Number)

- suomi: *kortin pääsykoodi*; svenska: *kortets åtkomstkod*. An
  access code, which is what a Card Access Number is - not a
  "käyttönumero"/"användningsnummer", which would name usage.
- 6 digits, **printed on the card front**, **not secret**.
- Used to set up the PACE secure channel before reading the
  eMRTD application. The CAN is the bearer of the operator's
  intent to physically possess the card; an attacker who can
  see the card front can read it too.
- refineid surfaces the CAN as a normal argv option
  (`--can NNNNNN`) -- not subject to the no-PIN-in-argv rule,
  precisely because it isn't secret.

## Naming rules

### Personal Identity Code (PIC)

PIC is the DVV-published English term. **Never "SSN"** -- that's
American social-security terminology and wrong for Finnish
identifiers. The suomi term is *henkilötunnus* (abbreviated
HETU); the svenska term is *personbeteckning*. Either of those
is acceptable inside suomi or svenska user-facing strings
respectively; in English prose, code, and committed docs use
PIC.

### Activation PIN vs PUK -- code-side discipline

Name the code by the scheme it belongs to. Under §4.6.1 the
activation code *is* the PUK; under §4.6.2 the preset activation
PIN is not a PUK. Prose that equates the two without naming the
scheme, or that gives the activation PIN one length for every
card, is wrong.

### Project name forms

**RefineID / refineid / REFINEID / `librefineid_*`** -- four
written forms; not interchangeable.

- `RefineID` for prose
- `refineid` for command and crate names
- `REFINEID` for environment variables
- `librefineid_*` for FFI symbols

The name layers deliberately: **Re** = reimplementation (not Rust),
**Fin** = Finn(ish citizen), **e** = electronic, **ID** = identity.
The lowercase `refineid` contains the Swedish `finne` (= Finn), and
the library name `librefineid_pkcs11` reads as "Libre Finn e-ID";
spoken aloud, `RefineID` is approximately "refine". Every layer is a
deliberate decision, not a typo -- do not "correct" the spelling,
the capitalisation, or the `lib` prefix.
