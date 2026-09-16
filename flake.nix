{
  description = "RefineID -- open-source FINEID middleware for Finnish identity cards";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    # Splits the cargo build so dependencies compile as their own
    # locally cached derivation; source edits rebuild only our crates.
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      rust-overlay,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      toolchainFor = pkgs: import ./nix/rust-toolchain.nix {
        inherit pkgs;
        rustOverlay = rust-overlay.overlays.default;
      };
      packageFor = pkgs: pkgs.callPackage ./nix/package.nix {
        craneLib = (crane.mkLib pkgs).overrideToolchain (toolchainFor pkgs);
      };
    in
    {
      packages = forAllSystems (pkgs: rec {
        refineid = packageFor pkgs;
        default = refineid;
      });

      nixosModules = {
        refineid = import ./nix/module.nix { refineidPackage = packageFor; };
        default = self.nixosModules.refineid;
      };

      overlays.default = final: prev: { refineid = packageFor final; };

      devShells = forAllSystems (pkgs: {
        default = import ./shell.nix {
          inherit pkgs;
          rustToolchain = toolchainFor pkgs;
          refineidPackage = packageFor pkgs;
        };
      });

      checks = forAllSystems (pkgs: {
        toolchain =
          let
            toolchain = toolchainFor pkgs;
            classicToolchain = import ./nix/rust-toolchain.nix { inherit pkgs; };
            version = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain.channel;
          in
          assert toolchain.drvPath == classicToolchain.drvPath;
          pkgs.runCommand "refineid-rust-toolchain" { nativeBuildInputs = [ toolchain ]; } ''
            rustc --version
            cargo --version
            cargo clippy --version
            cargo fmt --version
            test "$(rustc --version | cut -d ' ' -f 2)" = ${pkgs.lib.escapeShellArg version}
            touch "$out"
          '';
      });
    };
}
