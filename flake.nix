{
  description = "Extract files from any kind of container formats";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  # nixpkgs 26.11 no longer has an x86_64-darwin stdenv. Keep this input
  # only while that platform remains in unblob's CI matrix.
  inputs.nixpkgs-x86_64-darwin.url = "github:NixOS/nixpkgs/nixos-26.05";
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
      nixpkgs-x86_64-darwin,
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
        ./nix/patches/fs-python-3.14.patch
      ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (
        system:
        let
          nixpkgsSource = if system == "x86_64-darwin" then nixpkgs-x86_64-darwin else nixpkgs;
          systemNixpkgsPatches = if system == "x86_64-darwin" then [ ] else nixpkgsPatches;

          importPkgs =
            nixpkgsSource: extraOverlays:
            import nixpkgsSource {
              inherit system;
              overlays = [
                self.overlays.default
                shell-hooks.overlays.default
              ]
              ++ extraOverlays;
            };

          bootstrapPkgs = importPkgs nixpkgsSource [ ];

          patchedNixpkgs = bootstrapPkgs.applyPatches {
            name = "nixpkgs-patched";
            src = nixpkgsSource;
            patches = map (
              patch: if builtins.isPath patch then patch else bootstrapPkgs.fetchpatch patch
            ) systemNixpkgsPatches;
          };

          finalPkgs = importPkgs patchedNixpkgs [
            (final: prev: {
              # Preserve the derivation context so consumers of `pkgs.path`
              # retain the patched nixpkgs source as a build dependency.
              path = "${patchedNixpkgs}";

              # nix-shell-hooks currently references the former nixpkgs source
              # location of auto-patchelf.sh. Use the packaged setup hook until
              # it switches to a stable package path.
              pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [
                (_pythonFinal: pythonPrev: {
                  autoPatchelfVenvShellHook = pythonPrev.autoPatchelfVenvShellHook.overrideAttrs (_old: {
                    autoPatchelfHook = "${final.autoPatchelfHook}/nix-support/setup-hook";
                  });
                })
              ];
            })
          ];
        in
        if builtins.length systemNixpkgsPatches != 0 then finalPkgs else bootstrapPkgs
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

              deadnix
              statix
              libz
              cargo
              cargo-deny
              clippy
              pinact
              rustc
              just

              nodejs # for pyright
            ]
            ++ unblob.runtimeDeps;

            uvExtraArgs = [
              "--group"
              "docs"
            ];

            venvPatches = [
              (
                # https://github.com/NixOS/nixpkgs/blob/70f6d2ad78eee1617f0871878e509b6d78a8b13b/pkgs/development/python-modules/python-magic/default.nix#L25-L27
                replaceVars "${path}/pkgs/development/python-modules/python-magic/libmagic-path.patch" {
                  libmagic = "${file}/lib/libmagic${stdenv.hostPlatform.extensions.sharedLibrary}";
                }
              )
              (replaceVars "${path}/pkgs/development/python-modules/cairocffi/dlopen-paths.patch" {
                ext = stdenv.hostPlatform.extensions.sharedLibrary;
                cairo = cairo.out;
                glib = glib.out;
                gdk_pixbuf = gdk-pixbuf.out;
              })
            ];
          };

      });

      legacyPackages = forAllSystems (system: nixpkgsFor.${system});

      formatter = forAllSystems (system: nixpkgsFor.${system}.nixfmt);
    };
}
