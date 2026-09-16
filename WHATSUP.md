Purpose: Use rust-toolchain.toml for all Nix builds and development shells.
Status: in-progress

The NixOS dependency build inherits nixpkgs Rust instead of the workspace
toolchain. Pin rust-overlay and override Crane for both dependency and
application builds; share that toolchain with the development shells.

Validation: pre-commit format and workspace checks passed. Full pre-push
checks and Linux Nix CI are pending. The overlay archive hash was computed
with a NAR serializer verified against the existing Crane lock hash.
