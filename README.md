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

After you installed Git LFS, you can run all tests, with
`python -m pytest tests/` in the activated virtualenv.

### Linting

We are using [pre-commit](https://pre-commit.com/) for running checks.
Important commands:

- `pre-commit install` makes the pre-commit run automatically
  during git commits with git hooks.
- `pre-commit run --all-files` runs the pre-commit for everything.
