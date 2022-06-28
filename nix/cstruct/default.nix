{ lib, buildPythonPackage, fetchPypi, nose }:

buildPythonPackage rec {
  pname = "cstruct";
  version = "2.1";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-nCdB9G+xJhOk90Y2nsCns7HyVxIXjFZ0N5AtRG98Nkg";
  };

  checkInputs = [ nose ];
}
