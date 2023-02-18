{ lib, buildPythonPackage, fetchPypi, click, cstruct, poetry-core, python-lzo, pythonOlder, pythonRelaxDepsHook }:

buildPythonPackage rec {
  pname = "jefferson";
  version = "0.4.2";
  format = "pyproject";

  disabled = pythonOlder "3.8";

  src = fetchPypi {
    inherit pname version;
    hash = "sha256-5ZRzuIKXJXeuJVku57X9UXgY+egwfGnfijbf9Dj9ey8=";
  };

  buildInputs = [ click cstruct python-lzo ];
  nativeBuildInputs = [ pythonRelaxDepsHook poetry-core ];
  pythonRelaxDeps = [ "cstruct" ];
  strictDeps = true;
}
