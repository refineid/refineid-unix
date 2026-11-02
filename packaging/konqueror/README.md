# RefineID mTLS Bridge for Konqueror and QtWebEngine on FreeBSD

This directory provides the RefineID mTLS Loopback Bridge, enabling Finnish
Citizen Smart Cards (FINEID v4.0 / EC) to authenticate seamlessly in
**Konqueror** and QtWebEngine applications on FreeBSD.

## Background & Architecture

### The Problem in QtWebEngine
On FreeBSD, QtWebEngine is built with `use_nss_certs=false`, bypassing NSS's
native hardware token support. Furthermore, QtWebEngine's internal client
certificate store implementation (`QWebEngineClientCertificateStore::add`)
requires client private keys to be exported to PEM format:

```cpp
// Disassembled from libQt6WebEngineCore.so:
QSslKey key = cert.privateKey();
QByteArray pem = key.toPem(); // Returns empty for hardware tokens!
if (pem.isEmpty()) {
    // Fails: client certificate rejected
}
```

Because cryptographic smart cards enforce `CKA_NEVER_EXTRACTABLE` and `CKA_SENSITIVE`,
private keys cannot be converted to PEM format. As a result, Konqueror cannot natively
perform PKCS#11 hardware mTLS.

### The Solution: Transparent Loopback Bridge
Rather than maintaining an intrusive fork of Chromium/QtWebEngine, RefineID
uses a lightweight, transparent local loopback bridge:

```
+-------------------------------------------------------------+
| Konqueror (WebEnginePart)                                    |
+-------------------------------------------------------------+
             |
             | HTTPS CONNECT (127.0.0.1:18443)
             v
+-------------------------------------------------------------+
| refineid-mtls-proxy (FreeBSD daemon on 127.0.0.1:18443)     |
|                                                             |
|  - Downstream TLS: local CA (/usr/local/etc/refineid/ca/)   |
|  - Upstream TLS: OpenSSL 3 + ossl-modules/pkcs11.so         |
|  - Token Session: p11-kit-proxy.so -> librefineid_pkcs11.so  |
|  - PIN Prompt: refineid-ask-pin (native Qt modal dialog)    |
+-------------------------------------------------------------+
             |
             | Upstream mTLS (Citizen Certificate + EC P-384)
             v
+-------------------------------------------------------------+
| card.refineid.fi / tunnistus.suomi.fi / dvv.fi              |
+-------------------------------------------------------------+
```

1. **Selective Interception**: Only Finnish eID domains (`card.refineid.fi`,
   `*.suomi.fi`, `*.dvv.fi`, `*.vrk.fi`, `fineid.fi`) are intercepted. All other
   traffic is forwarded transparently as standard TCP tunnels.
2. **Zero PIN Exposure**: When OpenSSL's PKCS#11 provider requires card PIN 1,
   it calls an OpenSSL UI reader method which runs `/usr/local/bin/refineid-ask-pin`.
   The PIN is entered into a modal Qt password dialog, passed securely via pipe,
   and immediately cleansed from memory with `OPENSSL_cleanse`. No PIN is ever
   logged or stored.
3. **Origin Preservation**: Because Konqueror issues standard `CONNECT` requests,
   all URLs, cookies, SameSite policies, and CORS boundaries remain genuine
   `https://card.refineid.fi/` or `https://tunnistus.suomi.fi/`.

## Files

- `refineid_mtls_proxy.cpp`: The loopback proxy daemon.
- `refineid_ask_pin.cpp`: Secure Qt modal PIN entry dialog for desktop sessions.
- `openssl_pkcs11.cnf`: OpenSSL 3 configuration registering the PKCS#11 provider.
- `cert.cnf`: OpenSSL SAN configuration for the local bridge server certificate.
- `webenginepart-mtls-bridge.patch`: Patch for KDE's `webenginepart` to auto-detect
  the local proxy and trust the local bridge CA.
- `refineid-mtls-proxy.desktop`: XDG autostart file to launch the proxy on login.
- `Makefile`: Build and installation automation.

## Quick Start

### 1. Prerequisites

```sh
pkg install qt6-base openssl-pkcs11provider p11-kit
```

Ensure the RefineID PKCS#11 module is installed to `/usr/local/lib/refineid/`
and registered with p11-kit:

```sh
cat > /usr/local/etc/pkcs11/modules/refineid.module <<'MODULE'
module: /usr/local/lib/refineid/librefineid_pkcs11.so
critical: no
MODULE
```

### 2. Generate Local Bridge CA & Server Certificate

```sh
make ca
```

This creates `/usr/local/etc/refineid/ca/`, generates a dedicated local Root CA,
creates the server certificate with all required Subject Alternative Names, and
installs the CA into FreeBSD system trust (`/usr/local/share/certs/refineid-ca.pem`
via `certctl rehash`).

### 3. Build & Install Bridge Binaries

```sh
make
make install
```

### 4. Patch & Rebuild WebEnginePart

Apply `webenginepart-mtls-bridge.patch` to Konqueror's `webenginepart`:

```sh
cd /path/to/konqueror-source/webenginepart
patch -p0 < /path/to/packaging/konqueror/webenginepart-mtls-bridge.patch
cmake -B build -S .
cmake --build build
cmake --install build
```

### 5. Verification

Launch Konqueror:

```sh
konqueror https://card.refineid.fi/
```

When connecting, the `RefineID Smart Card` dialog will appear prompting for
PIN 1 (Authentication). Once entered, the authenticated page will render.
Navigate to `https://tunnistus.suomi.fi/` or `https://suomi.fi/` to verify
governmental authentication.
