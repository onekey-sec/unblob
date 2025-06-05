{
  lib,
  stdenv,
  python3,
  makeWrapper,
  e2fsprogs-nofortify,
  erofs-utils,
  jefferson,
  lz4,
  lziprecover,
  lzop,
  p7zip16,
  partclone,
  nix-filter,
  sasquatch,
  sasquatch-v4be,
  simg2img,
  ubi_reader,
  unar,
  upx,
  zstd,
  versionCheckHook,
  rustPlatform,
}:

let
  # These dependencies are only added to PATH
  runtimeDeps = lib.optional stdenv.isLinux partclone ++ [
    e2fsprogs-nofortify
    erofs-utils
    jefferson
    lziprecover
    lzop
    p7zip16
    sasquatch
    sasquatch-v4be
    ubi_reader
    simg2img
    unar
    upx
    zstd
    lz4
  ];
  pyproject_toml = builtins.fromTOML (builtins.readFile ./pyproject.toml);
  inherit (pyproject_toml.project) version;
in
python3.pkgs.buildPythonApplication {
  pname = "unblob";
  pyproject = true;
  disabled = python3.pkgs.pythonOlder "3.9";
  inherit version;
  src = nix-filter {
    root = ./.;
    include = [
      "Cargo.lock"
      "Cargo.toml"
      "pyproject.toml"
      "python"
      "rust"
      "tests"
      "README.md"
    ];
  };

  strictDeps = true;

  build-system = with python3.pkgs; [ poetry-core ];

  dependencies = with python3.pkgs; [
    arpy
    attrs
    click
    cryptography
    dissect-cstruct
    lark
    lief.py
    python3.pkgs.lz4 # shadowed by pkgs.lz4
    plotext
    pluggy
    pyfatfs
    pyperscan
    python-magic
    pyzstd
    rarfile
    rich
    structlog
    treelib
  ];

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = with rustPlatform; [
    cargoSetupHook
    maturinBuildHook
    makeWrapper
  ];

  # These are runtime-only CLI dependencies, which are used through
  # their CLI interface
  pythonRemoveDeps = [
    "jefferson"
    "ubi-reader"
  ];

  pythonImportsCheck = [ "unblob" ];

  makeWrapperArgs = [
    "--prefix PATH : ${lib.makeBinPath runtimeDeps}"
  ];

  nativeCheckInputs =
    with python3.pkgs;
    [
      pytestCheckHook
      pytest-cov
      versionCheckHook
    ]
    ++ runtimeDeps;

  versionCheckProgramArg = "--version";

  pytestFlagsArray = [
    "--no-cov"
  ];

  passthru = {
    # helpful to easily add these to a nix-shell environment
    inherit runtimeDeps;
  };

}
