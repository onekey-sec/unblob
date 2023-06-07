{ _sources, buildPythonPackage, future }:

buildPythonPackage rec {
  inherit (_sources.treelib) pname version src;

  propagatedBuildInputs = [ future ];

  doCheck = false;
}
