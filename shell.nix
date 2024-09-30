# This file is to let "legacy" nix-shell command work in addition to `nix develop`
let
  flakeManifest = [
    ./flake.lock
    ./flake.nix
    ./overlay.nix
    ./nix
    ./devenv.nix
    ".devenv"
  ];

  lock = builtins.fromJSON (builtins.readFile ./flake.lock);
  flake-compat = fetchTarball {
    url = "https://github.com/edolstra/flake-compat/archive/${lock.nodes.flake-compat.locked.rev}.tar.gz";
    sha256 = lock.nodes.flake-compat.locked.narHash;
  };
  nix-filter = import (fetchTarball {
    url = "https://github.com/numtide/nix-filter/archive/${lock.nodes.filter.locked.rev}.tar.gz";
    sha256 = lock.nodes.filter.locked.narHash;
  });

  src = nix-filter {
    root = ./.;
    include = flakeManifest;
  };
in
(import flake-compat { inherit src; }).shellNix.default
