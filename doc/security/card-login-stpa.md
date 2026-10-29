# STPA of card login

Card login (`programs.refineid.cardLogin`, [install-nixos.md](../install-nixos.md#card-login))
puts pam_pkcs11 over the RefineID PKCS#11 module into the PAM stacks of
console login, SDDM, GDM, sudo and the KDE lock screen. The method and
the losses L-2 and L-3 are those of the RAPP record,
[stpa-rapp.md](https://github.com/refineid/refineid-core/blob/main/doc/security/stpa-rapp.md).

## Losses

| Id | Loss |
| --- | --- |
| CL-L1 | A person other than an account's holder gets a session or root rights as that account. |
| L-2 | The card's PIN retry budget is consumed, or the card is blocked, by operations the cardholder did not intend. |
| L-3 | The cardholder cannot authenticate when they legitimately want to, and cannot tell why. |

CL-L1 is new: no loss of the RAPP record covers an account on the
computer itself.

## Hazards

| Id | Hazard | Losses |
| --- | --- | --- |
| CL-H1 | An account accepts a certificate the administrator did not map to it. | CL-L1 |
| CL-H2 | A mapped card that is no longer its holder's still logs in. | CL-L1 |
| CL-H3 | An account has no working way in: the card path fails and the password path is gone. | L-3 |
| CL-H4 | A login attempt verifies PIN 1 with a card whose holder did not mean to log in with it. | L-2 |
| CL-H5 | A login process changes the files of a user's phone pairing. | L-3 |

## Control structure

- The administrator writes `cardLogin.users`; the feedback is the
  evaluation's assertions (64 hex digits, a login name, at least one
  login) and the generated `/etc/pam_pkcs11/digest_mapping`.
- The PAM stack (pam_pkcs11) asks the PKCS#11 module for a token, logs
  in with the PIN the user typed, has the card sign a random challenge,
  verifies it against the certificate and looks the certificate's
  SHA-256 digest up in the map. Its feedback is the module's return
  codes, the token label and the certificates.
- The cardholder inserts the card and types PIN 1; the feedback is the
  prompt, which pam_pkcs11 shows only when a token is present.
- GDM starts its smartcard flow on a token-insertion event. The module
  reports no reader slot before a card is present, so GDM gets no such
  event: missing feedback, and the flow is reached only once a card is
  in (CL-H3 for GDM users relying on it; a separate change).

## Unsafe control actions

| Id | Unsafe control action | Hazard |
| --- | --- | --- |
| CL-UCA1 | pam_pkcs11 accepts a certificate whose digest matches a map line written from a mistyped or truncated fingerprint. | CL-H1 |
| CL-UCA2 | pam_pkcs11 accepts a card that was lost, replaced or revoked, because no chain, validity or revocation check runs. | CL-H2 |
| CL-UCA3 | The card rule ends the stack on failure, or is ordered after a password rule that prompts first. | CL-H3 |
| CL-UCA4 | pam_pkcs11 asks for and verifies PIN 1 before it reads the map, so a card in the reader that is mapped to nobody, or to another account, is asked for its PIN. | CL-H4 |
| CL-UCA5 | The PKCS#11 module, loaded by a login process with no per-user directory or another user's environment, creates or rewrites pairing files. | CL-H5 |
| CL-UCA6 | On a failed card login the PIN stays in `PAM_AUTHTOK`, and a later rule with `try_first_pass` tries it as the password. | CL-H4 |

## Controller constraints

| Id | Constraint | Against |
| --- | --- | --- |
| CL-CC1 | A fingerprint is SHA-256 over the whole DER certificate; the evaluation refuses anything but 64 hex digits and renders the colon form itself. No subject or name mapper is configured. | CL-UCA1 |
| CL-CC2 | The map line is the authorization, by decision. Possession of the card and PIN 1 is proved by a signature over a fresh challenge; withdrawal is removing the line and rebuilding. | CL-UCA2 |
| CL-CC3 | The card rule is `sufficient` and sits in the token slot of each stack, before every password rule; the password rules are unchanged. `gdm-smartcard` is a service of its own. | CL-UCA3 |
| CL-CC4 | The PKCS#11 module serves PIN 1 only while enough attempts are left; a card in the reader is the cardholder's choice to offer it. | CL-UCA4 |
| CL-CC5 | Opening the pairing store for reading never creates a directory. The phone source is installed only when an absolute per-user configuration directory resolves and the store directory is owned by the process's effective uid; a missing directory counts as the process's own unless it runs as root. A login process as root, `sudo` with the invoking user's `HOME` included, leaves the user's store alone. | CL-UCA5 |
| CL-CC6 | No network authentication rule follows the card rule in these stacks. | CL-UCA4, CL-UCA6 |

CL-UCA4 and CL-UCA6 are inherent to pam_pkcs11, which asks for the PIN
before it reads the map and stores what it read as the authentication
token; they stay recorded hazards. In the stacks this module configures
the PIN reaches only the local pam_unix, as one failed password attempt.
