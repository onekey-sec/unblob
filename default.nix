{ lib
, pkgs
, nix-filter
, buildPythonApplication
, poetry-core
, setuptools
, setuptools-rust
, arpy
, attrs
, click
, cstruct
, dissect-cstruct
, jefferson
, lark
, lief
, lz4
, plotext
, pluggy
, pyperscan
, python-lzo
, python-magic
, makeWrapper
, pythonRelaxDepsHook
, rustPlatform
, rarfile
, structlog
, ubi-reader
, yaffshiv
, pytest
, pytest-cov
, e2fsprogs
, lziprecover
, lzop
, p7zip
, sasquatch
, simg2img
, unar
, craneLib
, python
}:

let

  pyproject_toml = (builtins.fromTOML (builtins.readFile ./pyproject.toml));
  pname = pyproject_toml.tool.poetry.name;
  version = pyproject_toml.tool.poetry.version;
  # These dependencies are only added to PATH
  runtimeDeps = [
    e2fsprogs
    lziprecover
    lzop
    p7zip
    sasquatch
    sasquatch.bigEndian
    simg2img
    unar
    pkgs.zstd
    pkgs.lz4
  ];

  cargoArtifacts = craneLib.buildDepsOnly {
    inherit pname version;
    src = nix-filter {
      root = ./.;
      include = [
        "Cargo.toml"
        "Cargo.lock"
        "rust"
      ];
    };

    buildInputs = [ python ];
  };

  unblob-rust = craneLib.cargoBuild ({
    inherit cargoArtifacts;
    inherit pname version;
    src = nix-filter {
      root = ./.;
      include = [
        "Cargo.toml"
        "Cargo.lock"
        "rust"
      ];
    };
    buildInputs = [ python ];
  });
in
buildPythonApplication rec {
  inherit pname version;
  format = "pyproject";
  src = nix-filter
    {
      root = ./.;
      include = [
        "build.py"
        "Cargo.toml"
        "Cargo.lock"
        "LICENSE"
        "README.md"
        "pyproject.toml"
        "rust-toolchain.toml"
        "unblob"
        "rust"
        "tests"
      ];
    };
  buildInputs = [ poetry-core setuptools ];

  propagatedBuildInputs = [
    arpy
    attrs
    click
    cstruct
    dissect-cstruct
    jefferson
    lark
    lief.py
    lz4
    plotext
    pluggy
    pyperscan
    python-lzo
    python-magic
    structlog
    yaffshiv
    ubi-reader
    rarfile
  ];

  makeWrapperArgs = [
    "--prefix PATH : ${lib.makeBinPath runtimeDeps}"
  ];


  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = with rustPlatform; [
    cargoSetupHook
    rust.cargo
    rust.rustc
    makeWrapper
    pythonRelaxDepsHook
  ];
  pythonRelaxDeps = true;

  preBuild = ''
    cp -r ${unblob-rust}/target .
    chmod -R u=rwX,o=rwX target
    ls -la target
  '';

  nativeCheckInputs = [
    pytest
    pytest-cov
  ] ++ runtimeDeps ++ propagatedBuildInputs;

  checkPhase = "pytest --no-cov";

}
