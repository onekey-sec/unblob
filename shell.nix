# This file is to let "legacy" nix-shell command work in addition to `nix develop`
let
  flake = builtins.getFlake (toString ./.);
  flakePkgs = flake.legacyPackages.${builtins.currentSystem};
in
{ pkgs ? flakePkgs }:

with pkgs; mkShell {
  packages = [
    unblob
    poetry
    lzo
  ];
}
