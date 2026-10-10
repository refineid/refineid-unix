# GUI Architecture & Modernization: Modular Driver Framework

- **Document Version**: `26.9.28.1`
- **Protocol Wire Version**: `26.10.9`
- **Status**: Approved Architecture & Implementation Plan
- **Date**: 2026-09-28
- **Applies To**: `RefineID-Unix` (Linux, NetBSD, FreeBSD, OpenBSD)

---

## 1. Executive Summary & Assessment of Current GUI (Slint)

The desktop graphical interface in `refineid-unix` (`crates/refineid-gui`) currently relies on Slint. While Slint provides a declarative domain-specific language (DSL) for small embedded screens, it has proven to be a poor architectural fit for a security-critical Unix smartcard middleware utility.

### 1.1 Excessive Dependency Footprint & Attack Surface

In `refineid-unix`, Slint introduces a massive dependency cone (expanding `Cargo.lock` to 696 crates). It vendors an entire bespoke stack into Rust user-space:
- **Windowing engine**: `winit`
- **Font stack**: `fontique`, `skrifa`, `swash`, `ttf-parser`
- **Software rasterizer**: `resvg`, `tiny-skia`

Ironically, despite vendoring this extensive rendering stack, runtime file dialogs still require linking GTK 3 through `rfd`.

### 1.2 Concrete Friction in Production & Packaging

1. **Supply-Chain Risk**: Introduces unmaintained or stale transitive dependencies into audit scans (such as `bincode` and `ttf-parser`).
2. **Lint & Code Integrity Pollution**: Forces `#![allow(clippy::all, clippy::unwrap_used)]` in `crates/refineid-gui/src/main.rs` because code emitted by the `slint-build` code generator violates RefineID's strict zero-warning policy.
3. **BSD & Platform Breakage**:
   - On NetBSD, Slint's custom font parser fails font discovery, requiring explicit runtime workarounds (`SLINT_DEFAULT_FONT`).
   - Slint's compiler memory footprint during release builds has wedged 4-vCPU build guests.
4. **Nix Packaging Gymnastics**: `nix/package.nix` is forced to invoke `patchelf --add-rpath` across six dynamic X11/Wayland libraries (`libxkbcommon`, `wayland`, `libx11`, `libxcursor`, `libxi`, `libxrandr`) to satisfy internal dlopen calls from `winit`.

---

## 2. Evaluation and Comparison of Toolkit Alternatives

The following matrix compares Slint against the primary toolkit alternatives for Unix:

| Feature / Metric | Slint (Current) | GTK 3 / 4 (`gtk-rs` / `gtk4-rs`) | FLTK (`fltk-rs`) | egui (`eframe`) |
| :--- | :--- | :--- | :--- | :--- |
| **Rust Crate Dependencies** | ~550+ GUI crates (696 total) | ~35 crates (~120 total) | < 10 crates (~80 total) | ~150 crates |
| **Windowing & Display** | `winit` + dlopen hacks | System GDK (native Wayland / X11) | Native X11 / Wayland (FLTK 1.4+) | `winit` |
| **Font & Text Engine** | Bundled `fontique` / `ttf-parser` | System Pango / Cairo / HarfBuzz | System Xft / FreeType | Bundled `cosmic-text` / `ab_glyph` |
| **System Theme & Dark Mode**| Non-native / custom CSS | 100% Native (Adwaita, Breeze, etc.) | Basic / Utilitarian | Custom OpenGL/CPU skin |
| **Accessibility (a11y)** | Incomplete accesskit | Native AT-SPI out of the box | None / Minimal | Incomplete |
| **File Dialogs & Clipboard** | Requires `rfd` + `arboard` | Built-in (`GtkFileChooserNative` / `GtkFileDialog`, `GdkClipboard`) | Built-in (`NativeFileChooser`, system clipboard) | Requires plugins |
| **Memory / CPU Usage** | Medium | Low (shares cached system dynamic libraries) | Extremely Low (< 10 MB RAM) | High (continuous redrawing / immediate mode) |
| **BSD Portability** | Broken font fallback, high build RAM | Flawless (available in `pkgsrc` / ports) | Flawless (builds cleanly everywhere) | Requires `winit` / Wayland workarounds |

### 2.1 The Modern Desktop Choice: GTK 4 (Tier 1)

GTK is the native foundation of Linux desktop environments. Because RefineID packaging is already configured to link `libgtk-3-dev` on Debian/Ubuntu and `gtk3+` in NetBSD pkgsrc (via `rfd` and `wrapGAppsHook3`), adopting `gtk-rs` or `gtk4-rs` adds zero new foreign dependencies.

- **Supply-Chain Reduction**: Drops over 500 crates from `Cargo.lock`. Completely removes `slint`, `slint-build`, `winit`, `sctk-adwaita`, `ab_glyph`, `ttf-parser`, `bincode`, `resvg`, and `fontique`.
- **Integrated OS Facilities**: Replaces `rfd` with native `gtk::FileDialog` and `arboard` with `gdk::Clipboard`.
- **Security & PIN Hygiene**: Native `gtk::PasswordEntry` provides standard masking, input event protection, and explicit buffer clearing without leaking character sequences.
- **Clean Toolchain**: Pure, strongly-typed Rust without custom DSLs, build-time code generators, or Clippy suppressions.
- **Packaging Simplicity**: Removes manual `patchelf` rpath gymnastics.

### 2.2 The Minimalist / Purist Choice: FLTK (Tier 2)

For minimal environments, system rescue media, NetBSD, OpenBSD, FreeBSD, headless servers via Xvnc, or users who reject large desktop toolkit stacks:

- **Radical Simplicity**: Adds fewer than 10 Rust crates; compiles from source in 5 to 10 seconds.
- **Tiny Runtime Footprint**: Operates in under 10 MB of RAM.
- **Bulletproof Portability**: Runs identically on X11, Wayland (FLTK 1.4+), BSDs, and minimal window managers without GSettings schemas or font configuration quirks.
- **Self-Contained**: Can be statically linked into a standalone Unix binary without runtime dlopen dependencies.

### 2.3 Frameworks Explicitly Rejected

- **egui / iced**: Rely on `winit`, preserving the exact font-rasterization and Wayland/X11 dependency baggage that causes supply-chain audit friction. Immediate-mode rendering continuously repaints or demands complex frame throttling, wasting CPU cycles on background card monitoring.
- **Tauri / WebKitGTK**: Pulls in an entire browser engine (> 100 MB RAM), introducing a massive multi-process web rendering attack surface for a cryptographic security tool.

---

## 3. Core Architectural Principles

### 3.1 "One Core to Rule Them All" (Root of All Good)

RefineID maintains a unified core repository (`refineid-core`) providing authoritative cryptographic and protocol implementations. Historically, `refineid-unix` duplicated protocol code in an in-tree `crates/refineid-lib-core`.

Under this modernization:
1. **Elimination of In-Tree Duplication**: Deprecate `crates/refineid-lib-core` in `refineid-unix` in favor of consuming canonical modular crates from `refineid-core`:
   - `refineid-auth`
   - `refineid-rapp` (CPace KC2 over Ristretto255, `Noise_XXpsk3` pairing and `Noise_KK` sessions with SHA-512, wire format v26.10.9), driven by the in-workspace `crates/refineid-rapp-core` requester
   - `refineid-sign` (PAdES, CAdES, ASiC-E)
   - `refineid-emrtd` (ICAO Doc 9303 LDS1 portrait and signature parsing)
   - `refineid-pcsc` and `refineid-pkcs11`
2. **Zero Internal Version Shims**: All platform trees track the latest authoritative core protocol without backwards compatibility layers or stale protocol versions.

### 3.2 Separation of Dialogue Meaning vs. Presentation Rendering

Drawing directly from HCI User Interface Management System (UIMS) literature (Hartson & Hix 1989; Dix et al., HCI ch. 16; W3C SCXML) and earlier research in `refineid-client/dialogue`:
- **Dialogue Layer**: Defines ceremonies, state transitions, security rules, and PIN validation constraints independently of any visual widget toolkit.
- **Presentation Layer (Drivers)**: Pure renderers that display state snapshots and dispatch raw user intentions back to the controller.
- **Strict Separation Rule**: UI drivers must contain **zero** cryptography, zero APDU encoding, zero Noise handshakes, and zero card-reader management.
- **Zero PIN Exposure**: In accordance with project security policy, PIN codes never travel over external networks, candidate PIN lengths are never logged, and all memory buffers holding secret credentials implement explicit zeroization on drop.

---

## 4. Component Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                refineid-core (Root of All Good)             │
│  • refineid-auth   • refineid-rapp (CPace)  • refineid-sign │
│  • refineid-emrtd  • refineid-pcsc          • refineid-pkcs11│
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 crates/refineid-gui-core                    │
│                 (Headless Dialogue Engine)                  │
│                                                             │
│   RefineIdController:                                       │
│   • Background PC/SC SCardGetStatusChange listener thread   │
│   • Weak PIN validation & policy constraints (4-12 digits)  │
│   • Secret zeroization (ZeroizeOnDrop)                      │
│   • RAPP CPace pairing controller (wire v26.10.9)           │
│   • Async signing dispatch queue                            │
└───────────────┬─────────────────────────────▲───────────────┘
                │                             │
        UiState │                             │ UserIntent
    (Immutable) │                             │ (Typed Actions)
                ▼                             │
┌─────────────────────────────────────────────┴───────────────┐
│                     Presentation Drivers                    │
│                                                             │
│  ┌───────────────────────────┐ ┌──────────────────────────┐ │
│  │ crates/refineid-gui-fltk  │ │ crates/refineid-gui-gtk4 │ │
│  │ (Tier 2: Purist / Minimal)│ │ (Tier 1: Modern Desktop) │ │
│  │ • fltk-rs v1.5            │ │ • gtk4-rs                │ │
│  │ • <10 crates, <10 MB RAM  │ │ • Adwaita, AT-SPI a11y   │ │
│  └─────────────┬─────────────┘ └────────────┬─────────────┘ │
└────────────────┼────────────────────────────┼───────────────┘
                 │                            │
                 ▼                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   crates/refineid-gui                       │
│                   (Dispatcher Binary)                       │
│                                                             │
│   Cargo features: default = ["gtk4"] on Linux desktop       │
│                   default = ["fltk"] on BSD / minimalist    │
└─────────────────────────────────────────────────────────────┘
```

### 4.1 The Driver Interface (`UiDriver`)

The bridge between `refineid-gui-core` and visual presentation frontends is defined by a clean, unidirectional state-push and action-pull contract:

```rust
pub trait UiDriver: Send + 'static {
    /// Initialize the visual toolkit, main window, and styling.
    fn init(&mut self) -> Result<(), GuiError>;

    /// Render an immutable snapshot of the application state.
    fn render(&mut self, state: &UiState);

    /// Enter the event loop, forwarding user actions to the controller.
    fn run(self, tx: std::sync::mpsc::Sender<UserIntent>) -> Result<(), GuiError>;
}
```

### 4.2 State & Intent Data Contracts

#### State Pushed to Driver (`UiState`)
- `cards: Vec<CardSummary>` and `selected_card: Option<usize>`
- `pin_status: BTreeMap<PinManageSlot, PinStatus>` (retry counters, blocked flags)
- `portrait: Option<Arc<DocumentImage>>` and `signature: Option<Arc<DocumentImage>>`
- `signing_queue: Vec<PathBuf>`
- `remote_reader_enabled: bool` (default: `false` — local PC/SC smart card reader only)
- `rapp_pairing: Option<RappPairingState>` (PAKE state, 6-character Crockford Base32 code)
- `busy_message: Option<String>`
- `status_banner: Option<StatusBanner>`

#### Intent Emitted by Driver (`UserIntent`)
- `SelectCard(usize)`
- `ToggleRemoteReader(bool)` (explicit opt-in to discover announced phone readers)
- `ChangePin { slot: PinManageSlot, old_pin: PinBytes, new_pin: PinBytes }`
- `ReactivatePin { puk: PukBytes, new_pin1: PinBytes, new_pin2: PinBytes }`
- `LoadPortrait { can: PinBytes }`
- `QueueDocuments(Vec<PathBuf>)` and `ClearDocuments`
- `ExecuteSign { pin2: PinBytes, format: SignFormat, timestamp_config: TimestampConfig }`
- `StartRappPairing` and `CancelRappPairing`

### 4.3 Workstation UX Hygiene Contract

In accordance with [RAPP Transport and Discovery Hierarchy Specification](../../refineid-core/docs/protocols/rapp-transport-and-discovery-hierarchy.md):
1. **Local Card Reader Default**: Out of the box, `remote_reader_enabled` is strictly `false`. The controller interfaces exclusively with local smart cards via `pcscd`. No background radio polling, mDNS queries, or network sockets are active.
2. **Explicit User Opt-In**: The GUI provides a clean toggle:
   ```text
   [ ] Enable Remote Phone Reader
       Allow discovering and using your phone as a wireless card reader.
   ```
3. **Outbound Discovery Activation**:
   * Enabling the toggle activates Tier 2 (BlueZ BLE scanning) and/or Tier 3 (Avahi/`systemd-resolved` mDNS browsing) to detect phones advertising `_refineid-stream._tcp.local.`.
   * Disabling the toggle immediately shuts down discovery scanners, closes any idle outbound sockets, and purges transient device cache.
4. **Zero Open Ports on Unix**: The desktop application operates exclusively as an outbound client. It binds zero network listening sockets and requires zero `iptables`, `nftables`, `firewalld`, or `pf` firewall rules.

---

## 5. Phased Implementation Plan

### Phase 1: Unify with Core & Bring in RAPP with CPace PAKE
- Update `Cargo.toml` to depend on modular `refineid-core` components (`refineid-rapp`, `refineid-sign`, `refineid-emrtd`, `refineid-pcsc`).
- Replace in-tree `crates/refineid-lib-core/src/rapp` with `refineid-rapp` through `crates/refineid-rapp-core` (done).
- Standardize on CPace KC2, `Noise_XXpsk3_25519_ChaChaPoly_SHA512`, `Noise_KK_25519_ChaChaPoly_SHA512`, and wire protocol v26.10.9: the phone shows the pairing code, serves its random offer after the pairing preamble, and the workstation types the code.
- Verify interoperability tests pass against canonical vectors.

### Phase 2: Design `refineid-gui-core` (Headless Dialogue Layer)
- Create `crates/refineid-gui-core`.
- Implement `RefineIdController` with background PC/SC thread (`SCardGetStatusChange`).
- Enforce strict PIN length and weak PIN denylists.
- Enforce zeroization of all sensitive memory buffers on drop.
- Establish the `UiDriver` trait, `UiState`, and `UserIntent` structures.
- Ensure 100% headless unit-testability in CI without display servers.

### Phase 3: Implement `refineid-gui-fltk` (Tier 2 / Purist)
- Create `crates/refineid-gui-fltk` using `fltk` 1.5.
- Implement tab navigation via `fltk::group::Wizard`.
- Implement masked PIN input via `fltk::input::SecretInput` with numeric filtering callbacks.
- Render eMRTD JPEG2000 portraits using `fltk::image::RgbImage`.
- Render RAPP pairing QR codes directly with `qrcodegen` onto an FLTK drawing canvas.
- Replace `rfd` with `fltk::dialog::NativeFileChooser`.
- Run `cargo audit` to confirm complete elimination of `bincode`, `ttf-parser`, and Slint transitives.

### Phase 4: Implement `refineid-gui-gtk4` (Tier 1 / Modern Desktop)
- Create `crates/refineid-gui-gtk4` using `gtk4` 0.9.
- Implement native window shell using `AdwApplicationWindow` / `gtk::ApplicationWindow`.
- Leverage native `gtk::PasswordEntry` for masked credential entry.
- Implement modern async file dialogs via `gtk::FileDialog`.
- Provide native AT-SPI screen reader accessibility and automatic light/dark mode adaptation.

### Phase 5: Umbrella Dispatcher Binary & Packaging Cleanup
- Configure `crates/refineid-gui` as an umbrella executable selecting the backend via Cargo features:
  - `--features fltk` (default for BSD, minimal X11, recovery environments).
  - `--features gtk4` (default for standard Linux desktop distributions).
- Support explicit runtime driver selection via CLI flag (`refineid-gui --driver fltk|gtk4`).
- Remove `patchelf --add-rpath` across X11/Wayland libraries in `nix/package.nix`.
- Remove NetBSD `SLINT_DEFAULT_FONT` workarounds from `doc/install-netbsd.md`.
- Remove redundant X11 development dependencies from `script/package-deb.sh`.
