# Non-flake development shell: nix-shell gives a toolchain and every
# build/runtime dependency for `cargo build` in this tree.
{
  pkgs ? import <nixpkgs> { },
  rustToolchain ? import ./nix/rust-toolchain.nix { inherit pkgs; },
  refineidPackage ? import ./default.nix { inherit pkgs; },
}:
pkgs.mkShell {
  inputsFrom = [ refineidPackage ];
  packages = with pkgs; [
    rustToolchain
    pcsc-tools # pcsc_scan for reader debugging
    opensc # pkcs11-tool for module debugging
    nss.tools # tstclnt/certutil/modutil for the hardware cert-auth rig
  ];
  # The GUI dlopens the windowing/GL stack; a dev build has no
  # baked rpath, so provide the libraries via the environment.
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (
    with pkgs;
    [
      libGL
      libxkbcommon
      wayland
      gtk3
      libx11
      libxcursor
      libxi
      libxrandr
    ]
  );
}
