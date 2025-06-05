{
  nix-filter,
  lib,
  libiconv,
  python3,
  makeWrapper,
  rustPlatform,
  stdenvNoCC,
  e2fsprogs-nofortify,
  erofs-utils,
  jefferson,
  lz4,
  lziprecover,
  lzop,
  p7zip16,
  partclone,
  sasquatch,
  sasquatch-v4be,
  simg2img,
  ubi_reader,
  unar,
  upx,
  zstd,
  versionCheckHook,
}:

let
  # These dependencies are only added to PATH
  runtimeDeps = [
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
  ] ++ lib.optional stdenvNoCC.isLinux partclone;
  pyproject_toml = builtins.fromTOML (builtins.readFile ./pyproject.toml);
  inherit (pyproject_toml.project) version;
in
python3.pkgs.buildPythonApplication {
  pname = "unblob";
  inherit version;
  pyproject = true;
  disabled = python3.pkgs.pythonOlder "3.9";

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

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ./Cargo.lock;
  };

  strictDeps = true;

  build-system = with python3.pkgs; [ poetry-core ];

  buildInputs = lib.optionals stdenvNoCC.hostPlatform.isDarwin [ libiconv ];

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

  nativeBuildInputs = with rustPlatform; [
    makeWrapper
    maturinBuildHook
    cargoSetupHook
  ];

  # These are runtime-only CLI dependencies, which are used through
  # their CLI interface
  pythonRemoveDeps = [
    "jefferson"
    "ubi-reader"
  ];

  pythonRelaxDeps = [ "lz4" ];

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
