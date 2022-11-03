{ lib
, makeWrapper
, mkPoetryApp
, poetry2nix
, glibc
, python3
, rustPlatform
, e2fsprogs
, lz4
, lziprecover
, lzo
, lzop
, p7zip
, pkg-config
, sasquatch
, simg2img
, unar
, file
, hyperscan
, zstd
}:

let
  # These dependencies are only added to PATH
  runtimeDeps = [
    e2fsprogs
    lz4
    lziprecover
    lzop
    p7zip
    sasquatch
    sasquatch.bigEndian
    simg2img
    unar
    zstd
  ];

  self = mkPoetryApp {
    projectDir = ./.;

    preferWheels = true;

    # Python dependencies that need special care, like non-python
    # build dependencies
    overrides = poetry2nix.overrides.withoutDefaults (self: super:
      let
        # Inject setuptools to dependencies that is required by many non-wheel distributed packages
        overrideWithSetuptools = drv: overrides: (drv.overridePythonAttrs overrides).overridePythonAttrs (prev: {
          buildInputs = prev.buildInputs or [ ] ++ [
            self.setuptools
          ];
        });
      in
      {
        python-lzo = overrideWithSetuptools super.python-lzo (_: {
          buildInputs = [
            lzo
          ];
        });

        jefferson = overrideWithSetuptools super.jefferson (_: {
          propagatedBuildInputs = [
            # Use the _same_ version as unblob
            self.cstruct
            self.python-lzo
          ];
        });

        python-magic = overrideWithSetuptools (super.python-magic.override { preferWheel = false; }) (_: {
          patchPhase = ''
            substituteInPlace magic/loader.py --replace "find_library('magic')" "'${file}/lib/libmagic.so'"
          '';
        });

        hyperscan = super.hyperscan.overridePythonAttrs (_: {
          buildInputs = [
            hyperscan
            self.poetry
            self.setuptools
          ];
          nativeBuildInputs = [
            pkg-config
          ];

          installPhase = ''
            ${self.python.pythonForBuild.interpreter} -m pip install --no-build-isolation --no-index --prefix=$out  --ignore-installed --no-dependencies --no-cache .
          '';
        });

        arpy = overrideWithSetuptools super.arpy { };
        yaffshiv = overrideWithSetuptools super.yaffshiv { };
        ubi-reader = overrideWithSetuptools super.ubi-reader { };
      });

    python = python3;

    postFixup = ''
      wrapProgram $out/bin/unblob --prefix PATH : ${lib.makeBinPath runtimeDeps} \
                                  --set LOCALE_ARCHIVE_2_27 ${glibc}/lib/locale/locale-archive \
                                  --set LC_ALL C.UTF-8
    '';

    UNBLOB_BUILD_RUST_EXTENSION = "1";

    cargoDeps = rustPlatform.importCargoLock {
      lockFile = ./Cargo.lock;
    };

    nativeBuildInputs = with rustPlatform; [
      cargoSetupHook
      makeWrapper
      rust.cargo
      rust.rustc
    ];
  };
in
self // {
  inherit runtimeDeps;
  withTests = self.app.overridePythonAttrs (_: {
    checkPhase = ''
      (
        deps_PATH=${lib.makeBinPath runtimeDeps}

        # $program_PATH is set to contain all the script-paths of all
        # Python dependencies
        export PATH=$deps_PATH:$program_PATH:$PATH

        # romfs sample file contains some funky symlinks which get
        # removed when source is copyed to the nix store.
        pytest -vvv -k "not test_all_handlers[filesystem.romfs]" --no-cov
      )
    '';
  });
}
