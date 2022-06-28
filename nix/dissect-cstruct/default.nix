{ lib, buildPythonPackage, fetchPypi, setuptools-scm }:

buildPythonPackage rec {
  pname = "dissect.cstruct";
  version = "2.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-Tx05EdqZJwIT/u0KCyLnBnCwT+U7FtldLgS6/NM49Uc";
  };

  format = "pyproject";

  pythonNamespaces = [ "dissect" ];
  buildInputs = [ setuptools-scm ];
}
