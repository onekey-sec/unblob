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

## Kali Linux

If you're on Kali Linux, unblob is available through the [distribution
repository](https://www.kali.org/tools/unblob/). You can install it with:

```
apt install unblob
```

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

          mkdir -p ~/.config/nix
          cat > ~/.config/nix/nix.conf <<EOF
          experimental-features = nix-command flakes
          EOF

1.  Install unblob:

        $ nix profile install github:onekey-sec/unblob
        do you want to allow configuration setting 'extra-substituters' to be set to 'https://unblob.cachix.org' (y/N)? y
        do you want to permanently mark this value as trusted (y/N)? y
        do you want to allow configuration setting 'extra-trusted-public-keys' to be set to
        'unblob.cachix.org-1:5kWA6DwOg176rSqU8TOTBXWxsDB4LoCMfGfTgL5qCAE=' (y/N)? y
        do you want to permanently mark this value as trusted (y/N)? y

    Using and trusting substituter (binary cache) and its public key is optional but greatly speeds up installation.

- Check that everything works correctly:

        unblob --show-external-dependencies

## From source

1.  Install [Git](https://git-scm.com/download/) if you don't have it yet.
2.  Install the [Poetry](https://python-poetry.org/docs/#installation) Python package manager.
3.  **Clone** the unblob **repository from GitHub**:

        git clone https://github.com/onekey-sec/unblob.git

4.  Install **Python dependencies** with Poetry:

    1.  Python packages:

            cd unblob
            poetry install --no-dev

    2.  Make sure you [installed all extractors](#install-extractors).

    3.  Check that everything works correctly:

            poetry run unblob --show-external-dependencies

## Install extractors

There is a handy `install-deps.sh` script included in the repository and PyPI packages that can be used to install the following dependencies.

1.  With your operating system package manager:  
    On Ubuntu 22.04, install extractors with APT:

        sudo apt install android-sdk-libsparse-utils e2fsprogs p7zip-full unar zlib1g-dev liblzo2-dev lzop lziprecover libhyperscan-dev zstd

2.  If you need **squashfs support**, install sasquatch:

        curl -L -o sasquatch_1.0_amd64.deb https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-4/sasquatch_1.0_amd64.deb
        sudo dpkg -i sasquatch_1.0_amd64.deb
        rm sasquatch_1.0_amd64.deb
