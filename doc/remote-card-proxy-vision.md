# RefineID Remote Card Proxy & 6-Character Pairing Architecture Vision

- **Document Version**: `26.10.3`
- **Protocol Versions**: `26.9.28`, `26.10.1`
- **Status**: Normative Architecture & Design Vision
- **Applies To**: `RefineID-Unix` (Linux, FreeBSD, NetBSD, NixOS), `RefineID-Apple`, `RefineID-Android`
- **Companion Specification**: [RAPP Transport and Discovery Hierarchy Specification](../../refineid-core/docs/protocols/rapp-transport-and-discovery-hierarchy.md)

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
   * **Tier 2: Bluetooth / BLE Proximity Transport (`fi.refineid.rapp.ble.v1`)**: BlueZ BLE GATT / L2CAP Credit-Based Channels (CoC) with physical RSSI proximity gating ($\ge -55\text{ dBm}$). Works completely offline with zero IP infrastructure.
   * **Tier 3: Local IP Stream via mDNS / DNS-SD Fallback (`fi.refineid.stream.v1`)**: Universal cross-platform fallback when Bluetooth is absent, disabled, or in VMs. Discovered via RFC 6762 / 6763 (Avahi / `systemd-resolved`), connecting outbound to the phone.
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
   * The 6-character code is normalized via canonical NFKC and Crockford aliasing (mapping `I`/`L` to `1`, `O` to `0`, rejecting `U`).
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

1. **Slot Enumeration**:
   * When Firefox or Chromium opens, `librefineid_pkcs11.so` checks `RappDeviceVault`.
   * Each active paired phone is exposed as a virtual PKCS#11 slot (e.g. `Slot 1: Mobile Reader (RefineID)`).
2. **Zero-Latency Attribute Lookups**:
   * NSS queries `CKA_VALUE`, `CKA_ISSUER`, `CKA_SUBJECT`, and CA trust anchors.
   * The PKCS#11 module answers directly from in-memory cache without waking up the phone or card.
3. **Sign Request Dispatch**:
   * When TLS client authentication reaches the CertificateVerify step:
   * PKCS#11 module establishes an outbound connection to the phone over `Noise_KK`.
   * Module sends a `CardOperation::BrowserAuthenticate` message containing:
     * Request Origin (`"https://www.suomi.fi"`)
     * Key Profile (`"eccP384"` / `"rsa3072"`)
     * SHA-384 / SHA-256 Digest
4. **Mobile Authorization & Card Execution**:
   * Phone displays authentication prompt with origin and certificate details.
   * User confirms and presents physical ID card to the phone's NFC reader.
   * Phone verifies PIN1 locally, executes APDUs on the card, and returns the signature over the encrypted Noise channel.
5. **TLS Completion**:
   * PKCS#11 module delivers the signature to NSS; the browser completes login seamlessly.

---

## 5. Security, Privacy & Hygiene Guarantees

* **Zero Open Ports on Unix**: No listening daemons or inbound firewall holes on Linux/BSD workstations.
* **Workstation Hygiene**: RefineID is a pure local smart card tool out-of-the-box; remote discovery is strictly opt-in.
* **Encrypted Wire**: All transport payloads are authenticated and encrypted via ChaCha20-Poly1305 with monotonic nonces.
* **Zero PII Over Broadcasts**: RFC 8882 compliant. No citizen names, card serials, or persistent identifiers travel in BLE beacons or mDNS announcements.
* **Strict Hardware Bound**: Physical presence (NFC tap) and phone biometric confirmation are required for each signing operation.
