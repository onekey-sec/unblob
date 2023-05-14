{
  description = "Performance sensitive parts of Unblob";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    nix-filter.url = "github:numtide/nix-filter";

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, nix-filter, crane, rust-overlay, flake-utils, advisory-db, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        filter = nix-filter.lib;

        inherit (pkgs) lib makeRustPlatform python3Packages;

        rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        craneLib = crane.lib.${system}.overrideToolchain rust-toolchain;
        src = craneLib.cleanCargoSource (craneLib.path ./.);

        # Common arguments can be set here to avoid repeating them later
        commonArgs = {
          inherit src;

          buildInputs = [
            # Add additional build inputs here
            pkgs.python3
          ] ++ lib.optionals pkgs.stdenv.isDarwin [
            # Additional darwin specific inputs can be set here
            pkgs.libiconv
          ];

          # Additional environment variables can be set directly
          # MY_CUSTOM_VAR = "some value";
        };

        craneLibLLvmTools = craneLib.overrideToolchain
          (rust-toolchain.override {
            extensions = [
              "cargo"
              "llvm-tools-preview"
              "rustc"
            ];
          });

        # Build *just* the cargo dependencies, so we can reuse
        # all of that work (e.g. via cachix) when running in CI
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the actual crate itself, reusing the dependency
        # artifacts from above.
        libunblob-native = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });

        rustPlatform = makeRustPlatform {
          rustc = rust-toolchain;
          cargo = rust-toolchain;
        };

        unblob-native = python3Packages.buildPythonPackage
          {
            inherit (libunblob-native) pname version;
            format = "pyproject";

            src = filter {
              root = ./.;
              include = [
                "Cargo.toml"
                "Cargo.lock"
                "pyproject.toml"
                "python"
                "benches"
                "src"
                "README.md"
                "LICENSE"
              ];
            };

            buildInputs = commonArgs.buildInputs ++ [ pkgs.maturin ];

            strictDeps = true;
            doCheck = false;
            cargoDeps = rustPlatform.importCargoLock {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs =
              (with rustPlatform; [
                cargoSetupHook
                maturinBuildHook
              ]);

            passthru = {
              tests = {
                pytest =
                  with python3Packages; buildPythonPackage
                    {
                      inherit (libunblob-native) pname version;
                      format = "other";

                      src = filter
                        {
                          root = ./.;
                          include = [
                            "pyproject.toml"
                            "tests"
                          ];
                        };

                      dontBuild = true;
                      dontInstall = true;

                      nativeCheckInputs = [
                        unblob-native
                        pytestCheckHook
                      ];
                    };
              };
            };
          };
      in
      {
        checks = unblob-native.tests // {
          # Build the crate as part of `nix flake check` for convenience
          inherit libunblob-native;

          # Run clippy (and deny all warnings) on the crate source,
          # again, reusing the dependency artifacts from above.
          #
          # Note that this is done as a separate derivation so that
          # we can block the CI if there are issues here, but not
          # prevent downstream consumers from building our crate by itself.
          libunblob-native-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          libunblob-native-doc = craneLib.cargoDoc (commonArgs // {
            inherit cargoArtifacts;
          });

          # Check formatting
          libunblob-native-fmt = craneLib.cargoFmt {
            inherit src;
          };

          # Audit dependencies
          libunblob-native-audit = craneLib.cargoAudit {
            inherit src advisory-db;
          };

        } // lib.optionalAttrs (system == "x86_64-linux") {
          # NB: cargo-tarpaulin only supports x86_64 systems
          # Check code coverage (note: this will not upload coverage anywhere)
          libunblob-native-coverage = craneLib.cargoTarpaulin (commonArgs // {
            inherit cargoArtifacts;
          });
        };

        packages = {
          default = unblob-native;
          inherit libunblob-native;
          libunblob-native-llvm-coverage = craneLibLLvmTools.cargoLlvmCov (commonArgs // {
            inherit cargoArtifacts;
          });
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = builtins.attrValues self.checks.${system};

          # Additional dev-shell environment variables can be set directly
          # MY_CUSTOM_DEVELOPMENT_VAR = "something else";

          # Extra inputs can be added here
          nativeBuildInputs = with pkgs; [
            black
            maturin
            pdm
            ruff
          ];
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
