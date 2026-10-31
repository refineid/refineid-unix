# RefineID package: the refineid CLI, the RefineID GUI, and the
# PKCS#11 module, built from this source tree with the pinned Rust
# toolchain supplied through craneLib by both entry points.
#
# Built with crane so the dependency graph compiles as its own
# derivation: editing RefineID source rebuilds only the workspace
# crates, while the dependency build is reused from the local store
# until Cargo.lock (or the toolchain) changes.
{
  lib,
  craneLib,
  pkg-config,
  cmake,
  # GTK apps abort without the GSettings machinery in their
  # environment (the file chooser reads org.gtk.Settings.FileChooser).
  wrapGAppsHook4,
  gsettings-desktop-schemas,
  pcsclite,
  fontconfig,
  # GTK 4 is the GUI toolkit (refineid-gui-gtk4); linked at build time.
  gtk4,
  # GTK 3: the FLTK driver's native file chooser dlopens it.
  gtk3,
  pango,
  cairo,
  # Windowing stack and libraries for the GUI.
  libxkbcommon,
  wayland,
  libx11,
  libxext,
  libxinerama,
  libxcursor,
  libxrender,
  libxfixes,
  libxft,
  libxi,
  libxrandr,
}:

let
  commonArgs = {
    pname = "refineid";
    # The workspace version YY.M.D; build.rs appends the build number
    # from the sandbox clock.
    version = (lib.importTOML ../Cargo.toml).workspace.package.version;

    src = lib.cleanSourceWith {
      src = ../.;
      # Documentation is excluded so a doc-only commit does not
      # recompile the workspace.
      filter =
        path: type:
        let
          base = baseNameOf path;
        in
        base != "target"
        && base != "result"
        && base != ".git"
        && base != "nix"
        && base != "doc"
        && !lib.hasSuffix ".md" base;
    };

    strictDeps = true;
    # Identical for the dependency build and the final build: any
    # difference in the environment invalidates cargo's fingerprints
    # and recompiles cached dependencies for nothing.
    nativeBuildInputs = [
      pkg-config
      cmake
      wrapGAppsHook4
    ];
    dontUseCmakeConfigure = true;
    # Only the GUI needs the GTK wrap; leave the CLI and the PKCS#11
    # module unwrapped (wrapGApp runs in postFixup).
    dontWrapGApps = true;
    buildInputs = [
      pcsclite
      fontconfig
      gtk4
      gtk3
      pango
      cairo
      gsettings-desktop-schemas
      libx11
      libxext
      libxinerama
      libxcursor
      libxrender
      libxfixes
      libxft
      libxi
      libxrandr
      libxkbcommon
      wayland
    ];
  };

  # Dependencies only: crane builds this from the manifests and
  # Cargo.lock with dummied-out workspace sources, so its hash -- and
  # therefore the cached artifact -- survives RefineID source edits.
  # The version is pinned so a version stamp does not rotate the
  # cached derivation by name alone.
  cargoArtifacts = craneLib.buildDepsOnly (commonArgs // { version = "0"; });
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;

    # The GUI dlopens its windowing stack at runtime.
    runtimeLibs = lib.makeLibraryPath [
      libxkbcommon
      wayland
      libx11
      libxext
      libxinerama
      libxcursor
      libxrender
      libxfixes
      libxft
      libxi
      libxrandr
      pango
      cairo
      fontconfig
    ];

    postFixup = ''
      patchelf --add-rpath "$runtimeLibs" $out/bin/refineid-gui
      wrapGApp $out/bin/refineid-gui
    '';

    postInstall = ''
      # The PKCS#11 cdylib (installed from the cargo build log; copy
      # by hand if the crane hook missed it, and assert so a hook
      # change cannot ship a package silently missing the module).
      if [ ! -f $out/lib/librefineid_pkcs11.so ]; then
        mkdir -p $out/lib
        cp target/release/librefineid_pkcs11.so $out/lib/
      fi
      test -f $out/lib/librefineid_pkcs11.so

      # p11-kit module config: every p11-kit-aware consumer (Firefox
      # via p11-kit-proxy, OpenSSL via pkcs11-provider, GnuTLS,
      # OpenSSH) loads the module with no per-user configuration.
      mkdir -p $out/share/p11-kit/modules
      cat > $out/share/p11-kit/modules/refineid.module <<EOF
      module: $out/lib/librefineid_pkcs11.so
      # Citizen client-auth keys, not CA trust anchors.
      trust-policy: no
      # A load failure must not take down every crypto consumer.
      critical: no
      EOF

      # Desktop entry + icon for the GUI. The visible name is "RefineID";
      # the binary is refineid-gui so it does not collide with the
      # `refineid` CLI on PATH. Exec=refineid-gui resolves through PATH
      # so running desktop sessions launch the current system generation.
      mkdir -p $out/share/applications $out/share/icons/hicolor/scalable/apps
      cp crates/refineid-gui/assets/app-icon.svg \
        $out/share/icons/hicolor/scalable/apps/refineid.svg
      cp packaging/refineid.desktop $out/share/applications/refineid.desktop

      # The CLI's manual page; the fixup phase compresses it.
      install -Dm644 crates/refineid-client/man/refineid.1 $out/share/man/man1/refineid.1
      install -Dm644 packaging/zsh/_refineid $out/share/zsh/site-functions/_refineid
    '';

    meta = {
      description = "Open-source FINEID middleware: CLI, PKCS#11 module, and desktop GUI";
      homepage = "https://github.com/refineid/refineid-unix";
      license = lib.licenses.asl20;
      platforms = lib.platforms.linux;
      mainProgram = "refineid";
    };
  }
)
