{
  config,
  pkgs,
  ...
}:

# https://devenv.sh/reference/options/
{
  languages.python = {
    enable = true;
    libraries = with pkgs; [
      file # python-magic
    ];
    venv.enable = true; # put venv in PATH
    uv = {
      enable = true;
      sync.enable = true;
      sync.arguments = [
        # by default it contains `--no-install-workspace`
        "--frozen"
        "--group"
        "dev"
      ];
    };
    # https://github.com/vlaci/devenv-extras
    extras = {
      auto-patchelf.enable = true;
      clear-ldpath.enable = true;
    };
  };
  languages.rust.enable = true;

  env.UV_LINK_MODE = "copy";

  packages =
    with pkgs;
    [
      nodejs # for pyright and renovate
    ]
    ++ unblob.runtimeDeps;

  tasks = {
    "venv:link" = {
      exec = ''
        VENV_DIR="${config.devenv.root}/.venv"

        if [[ -d "$VENV_DIR" && ! -L "$VENV_DIR" ]]; then
          echo "Found an existing ${config.devenv.root}/.venv directory. Please remove it."
          exit 1
        fi
        ln -snf "${config.devenv.state}/venv" "${config.devenv.root}/.venv"
      '';
      after = [ "devenv:python:uv" ];
      before = [ "devenv:enterShell" ];
    };
  };
}
