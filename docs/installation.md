---
hide:
  - navigation
---

# Installation

## Docker image

Unblob can be used right away from a `docker` image: `ghcr.io/onekey-sec/unblob:latest`,
which contains everything needed to run unblob, even the [extractors](extractors.md).

The `--pull always` option is recommended, because the project is currently under heavy development, so we expect frequent changes.

The extracted files will be in the `/data/output` inside the container, mount
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

Unblob can be built and run using the [Nix](https://nixos.org) package manager.
The Nix derivation installs all 3rd party dependencies.

1. [Install and configure Nix](https://nixos.org/download.html).

1. _Optional_: enable the experimental features so that you don't need to pass  
  `--extra-experimental-features "nix-command flakes"` to `nix` command invocations:

        cat > ~/.config/nix/nix.conf <<EOF
        experimental-features = nix-command flakes
        EOF

1. _Optional_: use pre-built binaries from GitHub using [cachix](https://app.cachix.org/cache/unblob):

        nix-env -iA cachix -f https://cachix.org/api/v1/install
        cachix use unblob

1. Install unblob:

        nix profile install github:onekey-sec/unblob

- Check that everything works correctly:

        unblob --show-external-dependencies


## From source

1. Install [Git](https://git-scm.com/download/) if you don't have it yet.
2. Install the [Poetry](https://python-poetry.org/docs/#installation) Python package manager.
3. **Clone** the unblob **repository from GitHub**:

        git clone https://github.com/onekey-sec/unblob.git

4.  Install **Python dependencies** with Poetry:

    1.  _Optional_: With Rust optimizations
        (you need a [Rust compiler](https://www.rust-lang.org/tools/install)):

            cd unblob
            UNBLOB_BUILD_RUST_EXTENSION=1 poetry install --no-dev

    2. Python packages only:

            cd unblob
            poetry install --no-dev

5. Install **required extractors** with your operating system package manager:

    - on Ubuntu 22.04, install extractors with APT:

            sudo apt install e2fsprogs p7zip-full unar zlib1g-dev liblzo2-dev lzop lziprecover img2simg libhyperscan-dev zstd

    - If you need squashfs support, install sasquatch:

            curl -L -o sasquatch_1.0_amd64.deb https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v1.0/sasquatch_1.0_amd64.deb
            sudo dpkg -i sasquatch_1.0_amd64.deb
            rm sasquatch_1.0_amd64.deb

6. Check that everything works correctly:

        unblob --show-external-dependencies
