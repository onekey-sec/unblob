{ lib
, pkgs
, buildPythonApplication
, poetry-core
, setuptools
, arpy
, attrs
, click
, cstruct
, dissect-cstruct
, hyperscan
, jefferson
, lark
, lief
, lz4
, plotext
, pluggy
, python-lzo
, python-magic
, rarfile
, structlog
, ubi-reader
, yaffshiv
}:

buildPythonApplication rec {
  pname = "unblob";
  version = "0.1.0";

  src = ./.;
  format = "pyproject";

  buildInputs = [ poetry-core setuptools ];

  patches = [ ./nix/pyproject.toml.patch ];

  propagatedBuildInputs = [
    arpy
    attrs
    click
    cstruct
    dissect-cstruct
    jefferson
    hyperscan
    lark
    lief.py
    lz4
    plotext
    pluggy
    python-lzo
    python-magic
    rarfile
    structlog
    ubi-reader
    yaffshiv
  ];

}
