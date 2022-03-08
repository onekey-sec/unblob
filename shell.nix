# This file is to let "legacy" nix-shell command work in addition to `nix develop`
let
  flake = builtins.getFlake (toString ./.);
  system = builtins.currentSystem;
in
flake.devShell."${system}"
