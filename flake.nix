{
  description = "Extract files from any kind of container formats";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.filter.url = "github:numtide/nix-filter";
  inputs.unblob-native = {
    url = "github:onekey-sec/unblob-native";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.flake-compat = {
    url = "github:edolstra/flake-compat";
    flake = false;
  };
  inputs.devenv = {
    url = "github:vlaci/devenv/python-wrapper";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  nixConfig = {
    extra-substituters = [ "https://unblob.cachix.org" ];
    extra-trusted-public-keys = [
      "unblob.cachix.org-1:5kWA6DwOg176rSqU8TOTBXWxsDB4LoCMfGfTgL5qCAE="
    ];
  };

  outputs =
    {
      self,
      nixpkgs,
      devenv,
      filter,
      unblob-native,
      ...
    }@inputs:
    let
      # System types to support.
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (
        system:
        import nixpkgs {
          inherit system;
          overlays = [
            self.overlays.default
          ];
        }
      );
    in
    {
      overlays.default = nixpkgs.lib.composeManyExtensions [
        filter.overlays.default
        unblob-native.overlays.default
        (import ./overlay.nix)
      ];
      packages = forAllSystems (
        system:
        let
          inherit (nixpkgsFor.${system}) unblob;
        in
        {
          inherit unblob;
          default = unblob;
          devenv = devenv.packages.${system}.devenv.overrideAttrs (_: {
            checkFlags = [
              "--skip=test::test_nonexistent_script"
            ];
          });
        }
      );

      checks = forAllSystems (
        system:
        {
          inherit (nixpkgsFor.${system}) unblob;
        }
        // self.devShells.${system}
      );

      devShells = forAllSystems (system: {
        default = devenv.lib.mkShell {
          inherit inputs;
          pkgs = nixpkgsFor.${system};
          modules = [
            ./devenv.nix
          ];
        };
      });

      legacyPackages = forAllSystems (system: nixpkgsFor.${system});

      formatter = forAllSystems (system: nixpkgsFor.${system}.nixfmt-rfc-style);
    };
}
