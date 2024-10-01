{
  description = "Extract files from any kind of container formats";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.filter.url = "github:numtide/nix-filter";
  inputs.unblob-native = {
    url = "github:onekey-sec/unblob-native";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.lzallright = {
    url = "github:vlaci/lzallright";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.pyperscan = {
    url = "github:vlaci/pyperscan";
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

  outputs = { self, nixpkgs, filter, unblob-native, lzallright, pyperscan, ... }:
    let
      # System types to support.
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

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
        unblob-native.overlays.default
        lzallright.overlays.default
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
              venvDir = "./.venv";
              buildInputs = [
                # A Python interpreter including the 'venv' module is required to bootstrap
                # the environment.
                python3Packages.python

                # This executes some shell code to initialize a venv in $venvDir before
                # dropping into the shell
                python3Packages.venvShellHook

                # This hook is used to patch downloaded binaries in venv to use libraries
                # from the nix store.
                autoPatchelfHook

                unblob.runtimeDeps
                pyright
                python3Packages.pytest
                python3Packages.pytest-cov
                poetry

                nvfetcher
              ];

              postVenvCreation =
                let
                  apply_patches = lib.concatMapStringsSep
                    "\n"
                    (patch: "patch -f -p1 -d $VIRTUAL_ENV/lib/python3*/site-packages < ${patch}")
                    pkgs.python3Packages.python-magic.patches;
                in
                ''
                  poetry install --all-extras --sync --with dev
                  autoPatchelf "$VIRTUAL_ENV/"
                  ${apply_patches}
                '';
            };
          });

      legacyPackages = forAllSystems (system: nixpkgsFor.${system});
    };
}
