{ lib, buildPythonPackage, fetchPypi, nose }:

buildPythonPackage rec {
  pname = "arpy";
  version = "2.3.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-gwKCmpkc/O8mMLYeAPMV23MWQCHOy9f7H8GFJfg/M5w";
  };

  nativeCheckInputs = [ nose ];

  checkPhase = "nosetests";
}
