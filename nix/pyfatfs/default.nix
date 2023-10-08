{ _sources, python3 }:

python3.pkgs.buildPythonApplication rec {
  inherit (_sources.pyfatfs) pname version src;

  format = "setuptools";

  doCheck = false;

  nativeBuildInputs = with python3.pkgs; [ pytest-runner setuptools-scm ];

  propagatedBuildInputs = with python3.pkgs; [ pip fs ];

  postPatch = ''
    substituteInPlace ./setup.py --replace 'setuptools_scm~=5.0.0' setuptools_scm
  '';

  env.SETUPTOOLS_SCM_PRETEND_VERSION = version;
}
