# This file is to let "legacy" nix-shell command work in addition to `nix develop`
let
  flake = builtins.getFlake (toString ./.);
  flakePkgs = flake.legacyPackages.${builtins.currentSystem};
in
{ pkgs ? flakePkgs }:

with pkgs; let
  update = writeShellScriptBin "update-python-libraries"
    ''${update-python-libraries} "$@"'';
in
mkShell {
  packages = [
    unblob
    unblob.runtimeDeps
    ruff
    pyright
    python3Packages.pytest
    python3Packages.pytest-cov
    (pdm.overridePythonAttrs (super: rec {
      version = "2.6.1";
      src = fetchPypi {
        inherit (super) pname;
        inherit version;
        hash = "sha256-EFlYhJovjZqp7yGDosUOrp60rEf8gScs1QT92ckO3qI=";
      };
      nativeCheckInputs = super.nativeCheckInputs ++ [ python3Packages.pytest-httpserver ];
    }))
    lzo
    update
  ];
}
