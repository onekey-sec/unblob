{ lib, buildPythonPackage, fetchPypi }:

buildPythonPackage rec {
  pname = "plotext";
  version = "5.0.2";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-4ezimZnyQdzCgGpVMxJlZZvL6MvYlnQwZ7lB+XqDSNw";
  };

  doCheck = false;
}
