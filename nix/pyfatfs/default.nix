{ _sources, python3 }:

python3.pkgs.buildPythonApplication rec {
  inherit (_sources.pyfatfs) pname version src;

  format = "pyproject";

  nativeBuildInputs = with python3.pkgs; [ setuptools setuptools-scm ];
  propagatedBuildInputs = with python3.pkgs; [ fs ];
}
