{ lib, buildPythonPackage, fetchPypi }:

buildPythonPackage rec {
  pname = "cstruct";
  version = "5.2";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-iLLwJ5GSY2bavEIsDKoXCRNzIA8ukhQObvgiWpPNDpw";
  };

  doCheck = false; # Tests are not included in sdist
  strictDeps = true;
}
