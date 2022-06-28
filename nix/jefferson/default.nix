{ lib, buildPythonPackage, fetchFromGitHub, cstruct }:

buildPythonPackage rec {
  pname = "jefferson";
  version = "0.3.99";

  src = fetchFromGitHub {
    owner = "onekey-sec";
    repo = "jefferson";
    rev = "ddbc592edd81e8d53e5d49668da095e7a9293ade";
    sha256 = "sha256-oJ6fH+eriO75+sSHz1mpJTTJqfkdSqmE8UdDve6pr54";
  };

  buildInputs = [ cstruct ];
}
