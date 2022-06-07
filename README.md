# unblob

unblob is a tool for getting information out of any kind of binary blob.

## Quickstart

Unblob can be used right away from a `docker` container: \
`ghcr.io/iot-inspector/unblob:latest`

The `--pull always` option is recommended, because the project is currently under heavy development, so we expect frequent changes.


```shell
docker run \
  --rm \
  --pull always \
  -v /path/to/out/dir/on/host:/data/output \
  -v /path/to/files/on/host:/data/input \
ghcr.io/iot-inspector/unblob:latest /data/input/path/to/file
```

Help on usage:
```shell
docker run --rm --pull always ghcr.io/iot-inspector/unblob:latest --help
```

### Using Nix

Unblob can be built and run using [Nix](https://nixos.org). The Nix
derivation installs all 3rd party dependencies:

1. [Install and configure Nix](https://nixos.org/download.html)

    a. Optional: enable the experimental features so that you don't
       need to pass `--extra-experimental-features "nix-command
       flakes"` to `nix` command invocations:

     ```console
     $ cat > ~/.config/nix/nix.conf <<EOF
     experimental-features = nix-command flakes
     EOF
     ```

    b. Optional: use pre-built binaries from GitHub using [cachix](https://app.cachix.org/cache/unblob):

     ```console
     nix-env -iA cachix -f https://cachix.org/api/v1/install
     cachix use unblob
     ```

2. Install unblob

    ```console
    $ nix profile install github:onekey-sec/unblob
    $ unblob --show-external-dependencies
    The following executables found installed, which are needed by unblob:
        7z                          ✓
        jefferson                   ✓
        lz4                         ✓
        lziprecover                 ✓
        lzop                        ✓
        simg2img                    ✓
        tar                         ✓
        ubireader_extract_files     ✓
        ubireader_extract_images    ✓
        unar                        ✓
        unromfs                     ✓
        unsquashfs                  ✓
        yaffshiv                    ✓
    ```

## Extractors

Unblob relies on various tools for extracting the contents of a blob. These extractors are either third party tools (e.g. 7z), or internally developed extractors (available in [unblob/extractors](https://github.com/onekey-sec/unblob/tree/main/unblob/extractors) directory). \
To be able to use unblob properly, all extractors needs to be installed.

Hints for extractor installation:
* If you are using unblob from the official docker container, nothing to be done.
* Internally developed extractors are always installed with unblob installation.
* There is a `--show-external-dependencies` CLI option, which displays the name of the extractors used by unblob and shows if they are available for unblob to use or not. \
**NOTE**: This option does NOT check the version of the extractors.

### External extractors

These are the **external** extractor version recommendations. These are used in the official Docker container:

| Extractor                                 |   Version   |
|-------------------------------------------| ----------- |
| 7z (p7zip-full)                           | 16.02       |
| lz4                                       | 1.9.3       |
| lziprecover                               | 1.22        |
| lzop                                      | 1.04        |
| simg2img                                  | 8.1.0       |
| tar                                       | 1.34        |
| unar                                      | 1.10.1      |
| unsquashfs                                | 4.4         |

### Internal extractors

These are the **internal** extractors which are automatically installed by unblob. \
For more info on these extractors, check the [pyproject.toml](https://github.com/onekey-sec/unblob/blob/main/pyproject.toml).


| Extractor                |
|--------------------------|
| jefferson                |
| ubireader_extract_files  |
| ubireader_extract_images |
| unromfs                  |
| yaffshiv                 |


## Development

### Dependencies

We are using [poetry](https://python-poetry.org/) for managing dependencies.

`poetry install` will install all required dependencies in a virtualenv.

### Rust extension module (optional)

Unblob has an optional Rust extension for performance intensive
processing. Building it is entirely optional and requires
`[rustup](https://rustup.rs/)` to be installed on the host system. Run
`UNBLOB_BUILD_RUST_EXTENSION=1 poetry install` to build and install
the extension. Set `RUST_DEBUG=1` to build it in debug mode.

### Testing

We are using pytest for running our test suite.\
We have big integration files in the `tests/integration` directory,
we are using [Git LFS to track them](https://git-lfs.github.com/).
You need to install Git LFS first to be able to run the whole test suite:

```console
$ sudo apt install git-lfs
$ git lfs install
```

If you have cloned the repository prior to installing Git LFS, you
need to run the following commands once:

```console
$ git lfs pull
$ git lfs checkout
```

After you installed Git LFS, you can run all tests, with
`python -m pytest tests/` in the activated virtualenv.

### Linting

We are using [pre-commit](https://pre-commit.com/) for running checks.
Important commands:

- `pre-commit install` makes the pre-commit run automatically
  during git commits with git hooks.
- `pre-commit run --all-files` runs the pre-commit for everything.
