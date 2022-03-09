{ lib
, makeWrapper
, poetry2nix
, python3
, rustPlatform
, yara
, e2fsprogs
, lz4
, lziprecover
, lzo
, lzop
, p7zip
, sasquatch
, simg2img
, unar
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
  ];

  self = poetry2nix.mkPoetryApplication {
    projectDir = ./.;

    # Python dependencies that need special care, like non-python
    # build dependencies
    overrides = poetry2nix.overrides.withDefaults (self: super: {
      python-lzo = super.python-lzo.overridePythonAttrs (_: {
        buildInputs = [
          lzo
        ];
      });

      jefferson = super.jefferson.overridePythonAttrs (_: {
        propagatedBuildInputs = [
          # Use the _same_ version as unblob
          self.cstruct
          self.python-lzo
        ];
      });

      yara-python = super.yara-python.overridePythonAttrs (_: {
        # Use _our_ patched version of yara
        buildInputs = [ yara ];
        setupPyBuildFlags = [ "--dynamic-linking" ];
      });
    });

    python = python3;

    postFixup = ''
      wrapProgram $out/bin/unblob --prefix PATH : ${lib.makeBinPath runtimeDeps}
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
  withTests = self.overridePythonAttrs (_: {
    checkPhase = ''
      (
        deps_PATH=${lib.makeBinPath runtimeDeps}

        # $program_PATH is set to contain all the script-paths of all
        # Python dependencies
        export PATH=$deps_PATH:$program_PATH:$PATH

        # romfs sample file contains some funky symlinks which get
        # removed when source is copyed to the nix store.
        pytest -k "not test_all_handlers[filesystem.romfs]" --no-cov
      )
    '';
  });
}
