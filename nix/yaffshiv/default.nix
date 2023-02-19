{ lib, buildPythonPackage, fetchFromGitHub }:

buildPythonPackage rec {
  pname = "yaffshiv";
  version = "0.1";

  src = fetchFromGitHub {
    owner = "onekey-sec";
    repo = "yaffshiv";
    rev = "24e6e453a36a02144ae2d159eb3229f9c6312828";
    sha256 = "sha256-xq/NNx36x47gGfuepBBthpiEQSM8Mc+LKxkVqaSrOOc";
  };

  doCheck = false;
}
