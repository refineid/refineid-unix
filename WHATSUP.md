Purpose: Use rust-toolchain.toml for all Nix builds and development shells.
Status: implemented; integration tracked by pull request checks

The NixOS dependency build inherits nixpkgs Rust instead of the workspace
toolchain. Pin rust-overlay and override Crane for both dependency and
application builds; share that toolchain with the development shells.

Validation: all local commit and push gates passed. Linux flake checks
passed on x86-64 and ARM64; formatting passed in the Nix development shell.
Full Linux package build results are recorded in the pull request checks.
The overlay archive hash was computed with a NAR serializer verified
against the existing Crane lock hash and accepted by Nix CI.
