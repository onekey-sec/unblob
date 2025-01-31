{
  description = "Performance sensitive parts of Unblob";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    nix-filter.url = "github:numtide/nix-filter";

    crane.url = "github:ipetkov/crane";

    flake-utils.url = "github:numtide/flake-utils";

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nix-filter,
      crane,
      flake-utils,
      advisory-db,
      ...
    }:
    {
      overlays.default =
        final: prev:
        let
          craneLib = crane.mkLib final;
          nixFilter = nix-filter.lib;
        in
        {
          pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [
            (python-final: python-prev: {
              unblob-native = python-final.callPackage ./. { inherit craneLib nixFilter; };
            })
          ];
        };
    }
    // flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ self.overlays.default ];
        };

        inherit (pkgs.python3Packages) unblob-native;
      in
      {

        checks =
          unblob-native.tests
          // (
            let
              inherit (unblob-native)
                cargoArtifacts
                commonArgs
                craneLib
                libunblob-native
                src
                ;
            in
            {
              # Build the crate as part of `nix flake check` for convenience
              inherit libunblob-native;

              # Run clippy (and deny all warnings) on the crate source,
              # again, reusing the dependency artifacts from above.
              #
              # Note that this is done as a separate derivation so that
              # we can block the CI if there are issues here, but not
              # prevent downstream consumers from building our crate by itself.
              libunblob-native-clippy = craneLib.cargoClippy (
                commonArgs
                // {
                  inherit cargoArtifacts;
                  cargoClippyExtraArgs = "--all-targets -- --deny warnings";
                }
              );

              libunblob-native-doc = craneLib.cargoDoc (
                commonArgs
                // {
                  inherit cargoArtifacts;
                }
              );

              # Check formatting
              libunblob-native-fmt = craneLib.cargoFmt {
                inherit src;
              };

              # Audit dependencies
              libunblob-native-audit = craneLib.cargoAudit {
                inherit src advisory-db;
              };

            }
          );

        packages = {
          default = unblob-native;
          inherit unblob-native;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = builtins.attrValues self.checks.${system};

          nativeBuildInputs = with pkgs; [
            black
            maturin
            pdm
            ruff
            rustc
            cargo
          ];
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
