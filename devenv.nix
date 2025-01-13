{ lib, pkgs, ... }:

# https://devenv.sh/reference/options/
{
  languages.python = {
    enable = true;
    libraries = with pkgs; [
      file # python-magic
    ];
    poetry = {
      enable = true;
      activate.enable = true;
      install.enable = true;
      install = {
        groups = [ "dev" ];
        installRootPackage = true;
      };
    };
  };

  packages =
    with pkgs;
    [
      nvfetcher
      nodejs # for pyright and renovate
    ]
    ++ unblob.runtimeDeps;

  tasks = {
    "venv:patchelf" = {
      exec = ''
        for exe in taplo ruff; do
          ${lib.getExe pkgs.patchelf} --set-interpreter ${pkgs.stdenv.cc.bintools.dynamicLinker} $VIRTUAL_ENV/bin/$exe
        done
      '';
      after = [ "devenv:python:poetry" ];
      before = [ "devenv:enterShell" ];
    };
  };
}
