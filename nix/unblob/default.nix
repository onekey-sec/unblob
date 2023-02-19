{ lib
, nix-filter
, buildPythonApplication
, callPackage
, makeWrapper
, pythonRelaxDepsHook
  # Python dependencies
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
, poetry-core
, pyperscan
, python-lzo
, python-magic
, rarfile
, setuptools
, structlog
, ubi-reader
, yaffshiv
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
    sasquatch.bigEndian
    simg2img
    unar
    # shadowed by python packages of the same name
    pkgs.zstd
    pkgs.lz4
  ];

  unblob = buildPythonApplication rec {
    inherit pname version;
    format = "pyproject";

    src = nix-filter {
      root = ../../.;
      include = [
        "build.py"
        "pyproject.toml"
        "unblob"
      ];
    };

    strictDeps = true;
    doCheck = false;

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

    nativeBuildInputs = [
      makeWrapper
      pythonRelaxDepsHook
    ];

    pythonRelaxDeps = [
      "plotext"
      "yaffshiv"
    ];

    makeWrapperArgs = [
      "--prefix PATH : ${lib.makeBinPath runtimeDeps}"
    ];

  };
in
unblob
