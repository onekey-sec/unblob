{ lib, buildPythonPackage, fetchFromGitHub, python-lzo }:

buildPythonPackage rec {
  pname = "ubi-reader";
  version = "0.8.0";

  src = fetchFromGitHub {
    owner = "onekey-sec";
    repo = "ubi_reader";
    rev = "8c956d47b28af4085366e2acfee8d3ba016f6e90";
    sha256 = "sha256-tYK1bQtX6odaL3N5uELsDKYjJuAaRD7Po+u+gmaFBZE";
  };

  buildInputs = [ python-lzo ];

  doCheck = false;
}
