{ pkgs, ... }:

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
    ]
    ++ unblob.runtimeDeps;
}
