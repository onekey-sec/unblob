{ lib, buildPythonPackage, fetchPypi, click, cstruct, poetry-core, python-lzo, pythonOlder, pythonRelaxDepsHook }:

buildPythonPackage rec {
  pname = "ubi_reader";
  version = "0.8.5";

  src = fetchPypi {
    inherit pname version;
    hash = "sha256-DRRn5YKhybpXS7H5QeRft0+Sq4rPy6FYaopGSwQy6B4=";
  };

  buildInputs = [ python-lzo ];
  doCheck = false;
  strictDeps = true;
}
