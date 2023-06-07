{ _sources, python3 }:

python3.pkgs.buildPythonApplication rec {
  inherit (_sources.ubi_reader) pname version src;
  format = "pyproject";

  nativeBuildInputs = with python3.pkgs; [ poetry-core ];
  propagatedBuildInputs = with python3.pkgs; [ lzallright ];
}
