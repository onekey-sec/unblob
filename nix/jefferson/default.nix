{ lib
, buildPythonPackage
, fetchPypi
, python3
, click
, cstruct
, lzallright
}:

buildPythonPackage rec {
  pname = "jefferson";
  version = "0.4.4";
  format = "pyproject";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-RHEXbKRQWTyPWIzSRLwW82u/TsDgiL7L5o+cUWgLLk0=";
  };

  nativeBuildInputs = with python3.pkgs; [
    poetry-core
  ];

  propagatedBuildInputs = [
    click
    cstruct
    lzallright
  ];

  pythonImportsCheck = [ "jefferson" ];

}
