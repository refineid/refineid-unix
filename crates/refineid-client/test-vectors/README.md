# Test vectors

Fixtures used only by `#[cfg(test)]` code in this crate.
They are **not** trust anchors and must never be loaded by production code:
RefineID ships no root (`AGENTS.md`, "Certificates and trust"); a chain is judged against the EU trusted lists at runtime.

## `fineid-intermediate-01-citizen-g4e.der`

The DVV *Citizen Certificates - G4E* intermediate CA,
byte-for-byte identical to `platform/apple/RefineID/Resources/fineid-intermediate-01-citizen-g4e.der`
(verify with `shasum -a 256`).
Copied here so the `cert_chain` tests can build a real two-link chain without reaching outside the crate directory:

- leaf  = this intermediate (`ecdsa-with-SHA384`, EC P-384)
- issuer = `dvv-gov-root-ca-g3-ecc.der` (the self-signed root below)

The intermediate's `issuer` DN is byte-identical to the ECC root's `subject` DN,
and the root's key verifies the intermediate's signature,
so `walk_chain` resolves the issuer from the pool and exercises the real ECDSA-P384/SHA-384 chain-verify path.

## `dvv-gov-root-ca-g3-rsa.der`, `dvv-gov-root-ca-g3-ecc.der`

The public self-signed *DVV Gov. Root CA - G3* certificates, RSA 4096 and EC P-384 (FINEID S2 section 8.2 lists their fingerprints).
Fixtures only: public CA certificates that verify under their own keys, so tests of the chain walk, the CA-certificate cache, certificate display and signature verification need no private key.

## `icao-pkd-un-csca-2.pem`

The self-signed *United Nations CSCA* root certificate (RSA, `sha256WithRSAEncryption`) from the ICAO PKD.
Tests use it as a public self-signed RSA certificate:
its signature verifies under its own key over its own TBS bytes, so no private key is needed.
