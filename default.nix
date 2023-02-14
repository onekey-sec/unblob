{ lib
, pkgs
, nix-filter
, buildPythonApplication
, poetry-core
, setuptools
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
, pythonRelaxDepsHook
, rarfile
, structlog
, ubi-reader
, yaffshiv
}:

let

  pyproject_toml = (builtins.fromTOML (builtins.readFile ./pyproject.toml));
in
buildPythonApplication rec {
  inherit (pyproject_toml.tool.poetry) name version;
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
    rarfile
    structlog
    ubi-reader
    yaffshiv
  ];

  nativeBuildInputs = [ pythonRelaxDepsHook ];
  pythonRelaxDeps = true; #[ "jefferson" "yaffshiv" "ubi-reader" "pyperscan" ];
}
