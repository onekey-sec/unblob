{ lib, buildPythonPackage, fetchPypi }:

buildPythonPackage rec {
  pname = "plotext";
  version = "4.2.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-/Mt5Qjj5AB2DWxWK4qH1QHV6WNTrtAbZm9aPdfX3qB4=";
  };

  doCheck = false;
}
