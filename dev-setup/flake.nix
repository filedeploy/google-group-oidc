# Source: https://fasterthanli.me/series/building-a-rust-service-with-nix/part-10#setting-up-direnv-and-nix-direnv
{
  inputs = {
    # Repo where all packages are stored
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Cross-platform utils
    flake-utils.url = "github:numtide/flake-utils";

    # Programmable alternative to Rustup
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };
  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    # calling a function from `flake-utils` that takes a lambda
    # that takes the system we're targetting
    flake-utils.lib.eachDefaultSystem(
      system:
        let
          overlays = [ (import rust-overlay) ];

          pkgs = import nixpkgs {
            inherit system overlays;
          };

          # Create the toolchain
          rustToolchain = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchain {
            channel = "1.81";
            profile = "default";
            targets = [
              # Cloudflare Worker target
              "wasm32-unknown-unknown"
            ];
            # Need these for local develpoment but not CI.
            # rust-analyzer needs rust-src.
            components = [ "rust-analyzer" "rust-src" ];
          };

          # These packages are added to the dev environment.
          # Exhaustive list here: https://search.nixos.org/packages.
          buildInputs = with pkgs; [
            # Rust Toolchain
            rustToolchain
            # For `npx wrangler`
            nodejs_22
            # Wasm binary optimizer
            wasm-pack
            # Worker builder
            worker-build
            # Script runner
            just
          ];
        in
          {
            # `eachDefaultSystem` transforms the input, our output set
            # now simply has `packages.default` which gets turned into
            # `packages.${system}.default` (for each system)
            devShells.default = pkgs.mkShell {
              inherit buildInputs;
            };
          }
    );
}
