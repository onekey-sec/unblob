{ _sources
, lib
, stdenv
, buildPythonPackage
, rustPlatform
, libiconv
}:

buildPythonPackage rec {
  inherit (_sources.lzallright) pname version src;

  cargoDeps = rustPlatform.importCargoLock
    _sources.lzallright.cargoLock."Cargo.lock";

  format = "pyproject";

  nativeBuildInputs = with rustPlatform; [ cargoSetupHook maturinBuildHook ];

  buildInputs = lib.optionals stdenv.isDarwin [ libiconv ];

  pythonImportsCheck = [ "lzallright" ];

  doCheck = false;
}
