# RefineID Remote Card Proxy & 6-Character Pairing Architecture Vision

- **Document Version**: `26.10.3`
- **Protocol Versions**: `26.9.28`, `26.10.1`
- **Status**: Normative Architecture & Design Vision
- **Applies To**: `RefineID-Unix` (Linux, FreeBSD, NetBSD, NixOS), `RefineID-Apple`, `RefineID-Android`
- **Companion Specification**: [RAPP Transport and Discovery Hierarchy Specification](../../refineid-core/doc/protocols/rapp-transport-and-discovery-hierarchy.md)

---

## 1. Executive Summary

The **RefineID Remote Card Proxy** enables Linux and BSD workstations to perform high-assurance smartcard authentication (e.g. FINEID Citizen Identity, Suomi.fi, eIDAS services) using a smartphone (iPhone, Android) as a wireless NFC card reader proxy.

### Core Tenets

1. **Linux and BSD as First-Class Platforms**: Full parity with macOS and Windows. Firefox, Chromium, OpenSC, and desktop environments authenticate seamlessly through standard PKCS#11 (`librefineid_pkcs11.so`) and desktop GUI frontends.
2. **Phone as Sovereign Custodian (Root of Trust)**: The mobile phone holds physical custody of the identity card over NFC, hosts biometric verification gates, and operates as the authoritative security anchor. The phone ONLY opens a listening socket or advertises if "Allow Remote Card Reader" is explicitly toggled ON in mobile settings.
3. **Zero Inbound Ports on Unix Requesters**: Desktop workstations act strictly as **outbound clients**. Workstations **MUST NOT** bind incoming network listeners, open TCP ports, or require firewall modifications (`iptables`, `nftables`, `firewalld`, `pf`).
4. **Workstation UX Hygiene: Local Card Reader First**: By default, RefineID Unix operates strictly as a **Local Smart Card Reader** (interfacing with local CCID hardware via `pcscd`). Background radio scanning and network mDNS discovery run ONLY when the user explicitly enables "Remote Phone Reader" in settings.
5. **Normative 3-Tier Discovery & Transport Hierarchy**:
   * **Tier 1: Apple Native (Direct P2P)**: Exclusively Apple-to-Apple; not applicable on Unix.
   * **Tier 2: Bluetooth / BLE Proximity Transport (`fi.refineid.rapp.ble`)**: BlueZ BLE GATT / L2CAP Credit-Based Channels (CoC) with physical RSSI proximity gating ($\ge -55\text{ dBm}$). Works completely offline with zero IP infrastructure.
   * **Tier 3: Local IP Stream via mDNS / DNS-SD Fallback (`fi.refineid.stream`)**: Universal cross-platform fallback when Bluetooth is absent, disabled, or in VMs. Discovered via RFC 6762 / 6763 (Avahi / `systemd-resolved`), connecting outbound to the phone.
6. **Noise Cryptography Over Untrusted Transports**: End-to-end authenticated encryption (`Noise_XXpsk3` for pairing, `Noise_KK` for sessions) using Curve25519, ChaCha20-Poly1305, and SHA-256 over BLE L2CAP or Local TCP streams. The underlay is treated as an untrusted wire.
7. **Strict PIN Custody Rules**:
   * **Rule #1**: PIN codes (PIN1 and PIN2) NEVER leave the phone. PIN2 prompts appear exclusively on the phone's protected display.
   * **Rule #2**: Zero PIN and candidate PIN-length logging across all environments.

---

## 2. System Architecture & Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        UNIX WORKSTATION (REQUESTER)                     │
│                       (Linux, FreeBSD, NetBSD, NixOS)                   │
│                                                                         │
│  ┌───────────────────────────────┐     ┌─────────────────────────────┐  │
│  │   RefineID App / CLI          │     │    Web Browser (Firefox)    │  │
│  │   Default: Local pcscd reader │     │    Loads librefineid_pkcs11 │  │
│  │   Opt-in: [x] Remote Reader   │     │    Virtual card slots       │  │
│  └──────────────┬────────────────┘     └──────────────┬──────────────┘  │
│                 │ One-time Pairing                    │ C_Sign / Login  │
│                 ▼                                     ▼                 │
│         ┌───────────────┐                     ┌───────────────┐         │
│         │  Local Vault  │ ◄───────────────────│ PKCS#11 State │         │
│         │  (CBOR / OS)  │    Reads pairings   │ (Virtual Slot)│         │
│         └───────────────┘                     └───────┬───────┘         │
└───────────────────────────────────────────────────────┼─────────────────┘
                                                        │
                      Outbound Channel                  │
                 • Tier 2: BlueZ BLE / L2CAP CoC        │ (Zero inbound ports)
                 • Tier 3: Outbound TCP via Avahi mDNS  │ (Zero firewall rules)
                                                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    SOVEREIGN CUSTODIAN (PHONE)                          │
│                         (iOS / Android)                                 │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │   RefineID Mobile App (Sovereign Custodian)                       │  │
│  │   • Gated by "Allow Remote Card Reader" user toggle               │  │
│  │   • Tier 2: BLE Peripheral (RAPP Service UUID)                    │  │
│  │   • Tier 3: Ephemeral TCP listener + mDNS (_refineid-stream._tcp) │  │
│  │   1. Receives `BrowserAuthenticate` request                       │  │
│  │   2. Displays prompt: "Authenticate to Suomi.fi? [Confirm]"       │  │
│  │   3. Drives NFC session: prompts user to tap physical card        │  │
│  │   4. Transmits APDUs (SELECT -> VERIFY PIN1 -> PSO COMPUTE SIG)  │  │
│  │   5. Returns card signature over Noise channel                   │  │
│  └───────────────────────────────────┬───────────────────────────────┘  │
│                                      │ Contactless ISO 7816 APDUs       │
│                                      ▼                                  │
│                          ┌───────────────────────┐                      │
│                          │  Physical FINEID Card │                      │
│                          └───────────────────────┘                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. One-Time 6-Character Pairing Ceremony

Pairing establishes cryptographic association between the Unix workstation and the mobile phone without exposing identity secrets or candidate PIN lengths.

### 3.1 Pairing Flow

1. **Activation on Custodian**:
   * User enables "Allow Remote Card Reader" in RefineID mobile settings and taps "Pair New Workstation".
   * Phone generates a 6-character Crockford Base32 human factor code (e.g. `7K X4 M9`) and begins advertising (via BLE and/or mDNS).
2. **Initiation on Requester**:
   * In `refineid-gui` (or CLI `refineid pair`), the user turns on "Remote Phone Reader" and selects the discovered phone.
   * Desktop prompts for the 6-character code displayed on the phone.
3. **Mutual Authentication (`CPaceRistretto255` KC2 + `Noise_XXpsk3`)**:
   * The 6-character code is upper-cased; the letters `I`, `L`, `O` and `U` are not in the alphabet and a code carrying one is refused (RAPP v26.10.22 section 3.1).
   * PAKE exchange (`CPaceRistretto255`) mutually authenticates both endpoints and derives a 256-bit PSK.
   * `Noise_XXpsk3` performs authenticated key exchange, binding the handshake to canonical offer hashes.
   * Both devices exchange and authenticate static Curve25519 public keys.
4. **Initial Certificate Sync & Vault Storage**:
   * Mobile prompts the user to tap their ID card once.
   * Desktop retrieves and stores:
     * Phone's static public key and device metadata.
     * Card's authentication certificate (`EF.4331`) and on-card CA certificates (`EF.4334`..`EF.4336`).
   * The pair record is committed to the local encrypted vault (`RappDeviceVault`).

---

## 4. Routine Web Login (PKCS#11 Integration)

Once paired, routine authentication requires zero re-pairing:

1. **One slot for the paired phone**:
   * `librefineid_pkcs11.so` reads the pairing record the desktop application or the CLI keeps, without sweeping it, and raises one slot, "RefineID Remote" with the phone's name, for the one phone paired with this computer.
   * A thread inside the module holds the session: it dials while the record is usable and the phone is in sight, and keeps the session open while it is, answering pings and reading the phone's card reports. The pairing's lock file keeps the module, the desktop application and the CLI from two sessions under one static key; the loser reports the phone as in use.
2. **The token is the card on the phone**:
   * The token "Phone (PIN 1)" carries the authentication certificate the pairing record caches, which a session confirmed by the fingerprint the phone reports for its card, and which is read from the card afresh when no program has cached it or the phone reports another card. It stands on that certificate before and between sessions (RAPP v26.10.22 section 8.4 item 3): a browser given no certificate at its first handshake keeps resuming that handshake and never asks again, so the identity is offered from the record, and a signature asked before the session is open wakes the dial and waits for the phone within the browser's deadline. The token goes when, for 120 seconds, no session has reported the card present; at once when the pairing is forgotten or revoked, or a session reports another card. A report of absence starts the 120 seconds and is never taken for another card, and an operation the card did not answer is a failed operation, not absence. The phone does nothing for the slot but answer pings.
   * NSS reads `CKA_VALUE`, `CKA_ISSUER`, `CKA_SUBJECT` and the CA certificates from the module's memory; enumeration never dials.
   * `C_Login` reads no PIN: the token declares a protected authentication path, and succeeds only while the token is present.
3. **Sign request dispatch**:
   * `C_Sign` becomes one `browser_authenticate` on the held session: the key profile from the certificate, the algorithm from the mechanism (RSA PKCS#1 v1.5 by the DigestInfo's hash, ECDSA by the digest's length), the digest, and a context naming this computer. PKCS#11 carries no relying party, so no origin is claimed.
   * The request is bounded by one deadline, sent to the phone as the operation's lifetime; the module never repeats a request whose outcome it could not classify.
4. **The phone verifies PIN 1 and signs**:
   * The phone asks for PIN 1 on its own screen, verifies it on the card, signs, and returns the signature. PIN 1 is never on the wire (Rule #1).
5. **TLS completion**:
   * The module hands the signature to NSS and the browser completes the login.

---

## 5. Security, Privacy & Hygiene Guarantees

* **Zero Open Ports on Unix**: No listening daemons or inbound firewall holes on Linux/BSD workstations.
* **Workstation Hygiene**: RefineID is a pure local smart card tool out-of-the-box; remote discovery is strictly opt-in.
* **Encrypted Wire**: All transport payloads are authenticated and encrypted via ChaCha20-Poly1305 with monotonic nonces.
* **Zero PII Over Broadcasts**: RFC 8882 compliant. No citizen names, card serials, or persistent identifiers travel in BLE beacons or mDNS announcements.
* **Strict Hardware Bound**: Physical presence (NFC tap) and phone biometric confirmation are required for each signing operation.
