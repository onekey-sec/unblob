{ lib
, buildPythonPackage
, fetchPypi
, python3
, lzallright
}:

buildPythonPackage rec {
  pname = "ubi_reader";
  version = "0.8.9";
  format = "pyproject";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-b6Jp8xB6jie35F/oLEea1RF+F8J64AiiQE3/ufwu1mE=";
  };

  nativeBuildInputs = with python3.pkgs; [ poetry-core ];
  propagatedBuildInputs = with python3.pkgs; [ lzallright ];

}
