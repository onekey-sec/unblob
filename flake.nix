{
  description = "Extract files from any kind of container formats";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.filter.url = "github:numtide/nix-filter";
  inputs.unblob-native = {
    url = "github:onekey-sec/unblob-native";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.pyperscan = {
    url = "github:vlaci/pyperscan";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.sasquatch = {
    url = "github:onekey-sec/sasquatch";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.flake-compat = {
    url = "github:edolstra/flake-compat";
    flake = false;
  };

  nixConfig = {
    extra-substituters = [ "https://unblob.cachix.org" ];
    extra-trusted-public-keys = [
      "unblob.cachix.org-1:5kWA6DwOg176rSqU8TOTBXWxsDB4LoCMfGfTgL5qCAE="
    ];
  };

  outputs = { self, nixpkgs, filter, unblob-native, pyperscan, sasquatch, ... }:
    let
      # System types to support.
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (system: import nixpkgs {
        inherit system;
        overlays = [
          self.overlays.default
        ];
      });
    in
    {
      overlays.default = nixpkgs.lib.composeManyExtensions [
        filter.overlays.default
        sasquatch.overlays.default
        unblob-native.overlays.default
        pyperscan.overlays.default
        (import ./overlay.nix)
      ];
      packages = forAllSystems (system: rec {
        inherit (nixpkgsFor.${system}) unblob;
        default = unblob;
      });

      checks = forAllSystems (system: nixpkgsFor.${system}.unblob.tests);

      devShells = forAllSystems
        (system:
          with nixpkgsFor.${system}; {
            default = mkShell {
              packages = [
                unblob.runtimeDeps
                ruff
                pyright
                python3Packages.pytest
                python3Packages.pytest-cov
                poetry

                nvfetcher
              ];

              env.LD_LIBRARY_PATH = lib.makeLibraryPath [ file ];
            };
          });

      legacyPackages = forAllSystems (system: nixpkgsFor.${system});
    };
}
