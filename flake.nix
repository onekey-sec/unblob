{
  description = "Extract files from any kind of container formats";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.filter.url = "github:numtide/nix-filter";
  inputs.flake-compat = {
    url = "github:edolstra/flake-compat";
    flake = false;
  };

  inputs.shell-hooks.url = "github:vlaci/nix-shell-hooks";

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
      shell-hooks,
      filter,
      ...
    }:
    let
      # System types to support.
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      # Temporary patches for nixpkgs required for current unblob
      nixpkgsPatches = [
        # ubi_reader: 0.8.9 -> 0.8.10
        {
          url = "https://github.com/NixOS/nixpkgs/commit/a3b3188908f87f3c2bafd6b66ab2c0df2c059fa9.patch";
          hash = "sha256-MYP5q7KwbGzx01GYxvb4YwkLPV/aSzbI4Cbp+olw9a0=";
        }
      ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (
        system:
        let
          importPkgs =
            nixpkgs:
            import nixpkgs {
              inherit system;
              overlays = [
                self.overlays.default
                shell-hooks.overlays.default
              ];
            };

          bootstrapPkgs = importPkgs nixpkgs;

          patchedNixpkgs = bootstrapPkgs.applyPatches {
            name = "nixpkgs-patched";
            src = nixpkgs;
            patches = map bootstrapPkgs.fetchpatch nixpkgsPatches;
          };

          finalPkgs = importPkgs patchedNixpkgs;
        in
        if builtins.length nixpkgsPatches != 0 then finalPkgs else bootstrapPkgs
      );
    in
    {
      overlays.default = nixpkgs.lib.composeManyExtensions [
        filter.overlays.default
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
        default =
          let
            pkgs = nixpkgsFor.${system};
          in
          with pkgs;
          mkShell {
            packages = [
              python3Packages.uvVenvShellHook
              python3Packages.patchVenvShellHook
              python3Packages.autoPatchelfVenvShellHook

              cargo
              rustc

              nodejs # for pyright
            ] ++ unblob.runtimeDeps;

            venvPatches = [
              (
                # https://github.com/NixOS/nixpkgs/blob/70f6d2ad78eee1617f0871878e509b6d78a8b13b/pkgs/development/python-modules/python-magic/default.nix#L25-L27
                replaceVars "${path}/pkgs/development/python-modules/python-magic/libmagic-path.patch" {
                  libmagic = "${file}/lib/libmagic${stdenv.hostPlatform.extensions.sharedLibrary}";
                }
              )
            ];
          };

      });

      legacyPackages = forAllSystems (system: nixpkgsFor.${system});

      formatter = forAllSystems (system: nixpkgsFor.${system}.nixfmt-rfc-style);
    };
}
