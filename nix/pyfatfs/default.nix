{ _sources, python3 }:

python3.pkgs.buildPythonApplication rec {
  inherit (_sources.pyfatfs) pname version src;

  format = "pyproject";

  doCheck = false;

  nativeBuildInputs = with python3.pkgs; [ setuptools setuptools-scm ];
  propagatedBuildInputs = with python3.pkgs; [ fs ];

  postPatch = ''
    substituteInPlace ./pyproject.toml \
       --replace-fail 'setuptools ~= 67.8' setuptools \
       --replace-fail '"setuptools_scm[toml] ~= 7.1"' ""
  '';

  env.SETUPTOOLS_SCM_PRETEND_VERSION = version;
}
