{ lib
, stdenv
, craneLib
, nixFilter
, maturin
, rustPlatform
, libiconv
, python3
}:

let
  src = craneLib.cleanCargoSource (craneLib.path ./.);

  # Common arguments can be set here to avoid repeating them later
  commonArgs = {
    inherit src;

    # python package  build will recompile PyO3 when built with maturin
    # as there are different build features are used for the extension module
    # and the standalone dylib which is used for tests and benchmarks
    doNotLinkInheritedArtifacts = true;

    buildInputs = [
      python3
    ] ++ lib.optionals stdenv.isDarwin [
      # Additional darwin specific inputs can be set here
      libiconv
    ];
  };

  # Build *just* the cargo dependencies, so we can reuse
  # all of that work (e.g. via cachix) when running in CI
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;

  # Build the actual crate itself, reusing the dependency
  # artifacts from above.
  libunblob-native = craneLib.buildPackage (commonArgs // {
    inherit cargoArtifacts;
  });
  self = python3.pkgs.buildPythonPackage {

    inherit (libunblob-native) pname version;
    format = "pyproject";

    src = nixFilter {
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

    buildInputs = commonArgs.buildInputs ++ [ maturin ];

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
      inherit cargoArtifacts craneLib commonArgs libunblob-native;
      tests = {
        pytest =
          with python3.pkgs; buildPythonPackage
            {
              inherit (libunblob-native) pname version;
              format = "other";

              src = nixFilter
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
                self
                pytestCheckHook
              ];
            };
      };
    };
  };
in
self
