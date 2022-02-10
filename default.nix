{ lib
, runCommand
, poetry2nix
, python3
, rustPlatform
, _7zz
, lz4
, lziprecover
, lzo
, lzop
, simg2img
, squashfsTools
, unar
}:

let
  # These dependencies are only added to PATH
  runtimeDeps = [
    _7z
    lz4
    lziprecover
    lzop
    simg2img
    squashfsTools
    unar
  ];

  _7z = runCommand "7z" { } ''
    mkdir -p $out/bin
    ln -snf ${_7zz}/bin/7zz $out/bin/7z
  '';
in

poetry2nix.mkPoetryApplication {
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
      ];
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
    rust.cargo
    rust.rustc
  ];
}
