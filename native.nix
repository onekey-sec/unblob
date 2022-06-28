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

buildPythonApplication rec {
  pname = "unblob";
  version = "0.1.0";

  src = ./.;
  format = "pyproject";

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
