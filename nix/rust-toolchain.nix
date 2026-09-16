# Both Nix entry points use the Rust version and components selected
# by rust-toolchain.toml, independently of the host nixpkgs compiler.
{
  pkgs,
  rustOverlay ? import (
    let
      lock = builtins.fromJSON (builtins.readFile ../flake.lock);
      source = lock.nodes.rust-overlay.locked;
    in
    builtins.fetchTarball {
      url = "https://github.com/oxalica/rust-overlay/archive/${source.rev}.tar.gz";
      sha256 = source.narHash;
    }
  ),
}:
(pkgs.extend rustOverlay).rust-bin.fromRustupToolchainFile ../rust-toolchain.toml
