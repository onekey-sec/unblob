{ lib
, nix-filter
, buildPythonPackage
, callPackage
, makeWrapper
, pythonRelaxDepsHook
  # Python dependencies
, arpy
, attrs
, click
, cryptography
, dissect-cstruct
, jefferson
, lark
, lief
, lz4
, plotext
, pluggy
, poetry-core
, pyperscan
, python-magic
, rarfile
, structlog
, ubi_reader
, unblob-native
, treelib
  # Runtime dependencies (extractors)
, pkgs
, e2fsprogs
, lziprecover
, lzop
, p7zip
, sasquatch
, simg2img
, unar
}:

let
  pyproject_toml = (builtins.fromTOML (builtins.readFile ../../pyproject.toml));
  pname = pyproject_toml.tool.poetry.name;
  version = pyproject_toml.tool.poetry.version;

  # These dependencies are only added to PATH
  runtimeDeps = [
    e2fsprogs
    lziprecover
    lzop
    p7zip
    sasquatch
    simg2img
    unar
    # shadowed by python packages of the same name
    pkgs.zstd
    pkgs.lz4
  ];

  tests = callPackage ./tests.nix { inherit pname version; };

  unblob = buildPythonPackage rec {
    inherit pname version;
    format = "pyproject";

    src = nix-filter {
      root = ../../.;
      include = [
        "pyproject.toml"
        "unblob"
      ];
    };

    strictDeps = true;
    doCheck = false;

    buildInputs = [ poetry-core ];

    propagatedBuildInputs = [
      arpy
      attrs
      click
      cryptography
      dissect-cstruct
      jefferson
      lark
      lief.py
      lz4
      plotext
      pluggy
      pyperscan
      python-magic
      structlog
      ubi_reader
      unblob-native
      rarfile
      treelib
    ];

    nativeBuildInputs = [
      makeWrapper
      pythonRelaxDepsHook
    ];

    pythonImportsCheck = [ "unblob" ];

    pythonRelaxDeps = [
      "dissect.cstruct"
      "structlog"
    ];

    makeWrapperArgs = [
      "--prefix PATH : ${lib.makeBinPath runtimeDeps}"
    ];

    passthru = {
      inherit runtimeDeps;
      tests = {
        pytest = tests;
      };
    };
  };
in
unblob
