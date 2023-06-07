{ lib
, stdenv
, buildPythonPackage
, callPackage
, fetchFromGitHub
, rustPlatform
, libiconv
}:

buildPythonPackage rec {
  pname = "lzallright";
  version = "0.2.3";

  src = fetchFromGitHub {
    owner = "vlaci";
    repo = pname;
    rev = "refs/tags/v${version}";
    sha256 = "sha256-Zzif6WtecgAkNmml0kt0Z+Ewx0L30ahr+kwzYR5aUAM=";
  };

  cargoDeps = rustPlatform.fetchCargoTarball {
    inherit src;
    name = "${pname}-${version}";
    hash = "sha256-WSwIKJBtyorKg7hZgxwPd/ORujjyY0x/1R+TBbIxyWQ=";
  };

  format = "pyproject";

  nativeBuildInputs = with rustPlatform; [ cargoSetupHook maturinBuildHook ];

  buildInputs = lib.optionals stdenv.isDarwin [ libiconv ];

  pythonImportsCheck = [ "lzallright" ];

  doCheck = false;

  passthru.tests = {
    pytest = callPackage ./tests.nix { };
  };

}
