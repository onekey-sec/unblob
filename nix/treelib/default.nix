{ lib, buildPythonPackage, fetchPypi, future }:

buildPythonPackage rec {
  pname = "treelib";
  version = "1.6.1";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-HL//stK3XMrCfQIAzuBQe2+7Bybgr7n64Bet5dLOh4g=";
  };

  propagatedBuildInputs = [ future ];

  doCheck = false;
}
