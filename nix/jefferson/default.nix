{ _sources, python3 }:

python3.pkgs.buildPythonApplication rec {
  inherit (_sources.jefferson) pname version src;
  format = "pyproject";

  nativeBuildInputs = with python3.pkgs; [
    poetry-core
  ];

  propagatedBuildInputs = with python3.pkgs; [
    click
    cstruct
    lzallright
  ];

  pythonImportsCheck = [ "jefferson" ];

}
