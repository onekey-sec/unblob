{ pname, version, nix-filter, buildPythonApplication, unblob, pytestCheckHook, pytest-cov }:

buildPythonApplication
{
  pname = "${pname}-tests";
  inherit version;
  format = "other";

  src = nix-filter
    {
      root = ../../.;
      include = [
        "pyproject.toml"
        "tests"
      ];
    };

  dontBuild = true;
  dontInstall = true;

  nativeCheckInputs = [
    pytestCheckHook
    pytest-cov
    unblob
  ] ++ unblob.runtimeDeps ++ unblob.propagatedBuildInputs;
  pytestFlagsArray = [
    "--no-cov"
  ];
}
