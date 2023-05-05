---
hide:
  - navigation
---

# Installation

Unblob consists of two main parts:

- unblob, the Python package.
- extractor command line tools like `7zip`, `unar`, etc. (See [Extractors](./extractors.md) for explanation.)

All of these need to be installed to make unblob fully functional.  
Depending the packaging solution you choose, you might need to
install external extractors manually.

## Python package

unblob can be installed (without the extractors) from PyPI (Python Package Index).  
This might be the easiest method, depending on whether you have Python 3 installed already.

1.  First, install the Python package:

        python3 -m pip install --user unblob

    This will install the `unblob` script in `~/.local/bin`. You can put that
    directory in your `PATH` environment variable, or call it directly.

    !!! Warning

        System-wide installation (with `sudo`) is not recommended, because it can potentially break your system.

2.  Make sure to [install extractors](#install-extractors).

3.  Check that everything works correctly:

        unblob --show-external-dependencies

## Docker image

unblob can be used right away from a `docker` image: `ghcr.io/onekey-sec/unblob:latest`,
which contains everything needed to run unblob, even the [extractors](extractors.md).

The `--pull always` option is recommended, because the project is currently under heavy development, so we expect frequent changes.

The extracted files will be in the `/data/output` folder inside the container. Mount
your host directory where you want to see the extracted files there:

```console
docker run \
  --rm \
  --pull always \
  -v /path/to/extract-dir/on/host:/data/output \
  -v /path/to/files/on/host:/data/input \
ghcr.io/onekey-sec/unblob:latest /data/input/path/to/file
```

Help on usage:

```shell
docker run --rm --pull always ghcr.io/onekey-sec/unblob:latest --help
```

## nix package

unblob can be built and run using the [Nix](https://nixos.org) package manager.
The Nix derivation installs all 3rd party dependencies.

1.  [Install and configure Nix](https://nixos.org/download.html).

1.  _Optional_: enable the experimental features so that you don't need to pass  
    `--extra-experimental-features "nix-command flakes"` to `nix` command invocations:

          cat > ~/.config/nix/nix.conf <<EOF
          experimental-features = nix-command flakes
          EOF

1.  _Optional_: use pre-built binaries from GitHub using [cachix](https://app.cachix.org/cache/unblob):

        nix-env -iA cachix -f https://cachix.org/api/v1/install
        cachix use unblob

1.  Install unblob:

        nix profile install github:onekey-sec/unblob

- Check that everything works correctly:

        unblob --show-external-dependencies

## From source

1.  Install [Git](https://git-scm.com/download/) if you don't have it yet.
2.  Install the [PDM](https://python-poetry.org/docs/#installation) Python package manager.
3.  **Clone** the unblob **repository from GitHub**:

        git clone https://github.com/onekey-sec/unblob.git

4.  Install **Python dependencies** with Poetry:

    1.  Python packages:

            cd unblob
            pdm sync

    2.  Make sure you [installed all extractors](#install-extractors).

    3.  Check that everything works correctly:

            pdm run unblob --show-external-dependencies

## Install extractors

1.  With your operating system package manager:  
    On Ubuntu 22.04, install extractors with APT:

        sudo apt install e2fsprogs p7zip-full unar zlib1g-dev liblzo2-dev lzop lziprecover img2simg libhyperscan-dev zstd

2.  If you need **squashfs support**, install sasquatch:

        curl -L -o sasquatch_1.0_amd64.deb https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-3/sasquatch_1.0_amd64.deb
        sudo dpkg -i sasquatch_1.0_amd64.deb
        rm sasquatch_1.0_amd64.deb
