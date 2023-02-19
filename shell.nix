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
    poetry
    lzo
    update
  ];
}
