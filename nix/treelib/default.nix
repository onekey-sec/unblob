{
  _sources,
  buildPythonPackage,
  future,
  six,
}:

buildPythonPackage rec {
  inherit (_sources.treelib) pname version src;

  propagatedBuildInputs = [
    future
    six
  ];

  doCheck = false;
}
