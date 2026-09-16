# Non-flake entry point: nix-build builds the RefineID package with
# the nixpkgs on NIX_PATH. Both entry points use the Crane and Rust
# overlay revisions pinned in flake.lock and the workspace toolchain.
{
  pkgs ? import <nixpkgs> { },
}:
let
  lock = builtins.fromJSON (builtins.readFile ./flake.lock);
  crane = fetchTarball {
    url = "https://github.com/ipetkov/crane/archive/${lock.nodes.crane.locked.rev}.tar.gz";
    sha256 = lock.nodes.crane.locked.narHash;
  };
  rustToolchain = import ./nix/rust-toolchain.nix { inherit pkgs; };
  craneLib = (import crane { inherit pkgs; }).overrideToolchain rustToolchain;
in
pkgs.callPackage ./nix/package.nix { inherit craneLib; }
