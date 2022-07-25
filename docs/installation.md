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

- [Install and configure Nix](https://nixos.org/download.html).

- Optional: enable the experimental features so that you don't need to pass
  `--extra-experimental-features "nix-command flakes"` to `nix` command invocations:

```shell
cat > ~/.config/nix/nix.conf <<EOF
experimental-features = nix-command flakes
EOF
```

- Optional: use pre-built binaries from GitHub using [cachix](https://app.cachix.org/cache/unblob):

```shell
nix-env -iA cachix -f https://cachix.org/api/v1/install
cachix use unblob
```

- Install unblob:

```shell
nix profile install github:onekey-sec/unblob
```

- Check that everything works correctly:

```shell
unblob --show-external-dependencies
```

## From source

- Install [Git](https://git-scm.com/download/) if you don't have it yet.
- Install the [Poetry](https://python-poetry.org/docs/#installation) Python package manager.
- Clone the unblob repository from GitHub:

```
git clone https://github.com/onekey-sec/unblob.git
```

- Install Python dependencies with Poetry:

- A. Optional: With Rust optimizations
  (you need a [Rust compiler](https://www.rust-lang.org/tools/install)):

```shell
cd unblob
UNBLOB_BUILD_RUST_EXTENSION=1 poetry install --no-dev
```

- B. Python packages only:

```shell
cd unblob
poetry install --no-dev
```

- Install required extractors with your operating system package manager:

- on Ubuntu 22.04, install extractors with APT:

```shell
sudo apt install e2fsprogs p7zip-full unar zlib1g-dev liblzo2-dev lzop lziprecover img2simg libhyperscan-dev zstd
```

- If you need squashfs support, install sasquatch:

```shell
curl -L -o sasquatch_1.0_amd64.deb https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v1.0/sasquatch_1.0_amd64.deb
sudo dpkg -i sasquatch_1.0_amd64.deb
rm sasquatch_1.0_amd64.deb
```

- Check that everything works correctly:

```
unblob --show-external-dependencies
```
