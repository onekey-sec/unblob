# unblob

**Accurate, fast, and easy-to-use extraction suite for binary blobs.**

unblob parses unknown binary blobs for **78+ archive, compression, and file-system formats**, extracts their content recursively, and carves out unknown chunks. It is the perfect companion for extracting, analyzing, and reverse engineering firmware images.

[![CI](https://github.com/onekey-sec/unblob/actions/workflows/CI.yml/badge.svg)](https://github.com/onekey-sec/unblob/actions/workflows/CI.yml)
[![PyPI version](https://img.shields.io/pypi/v/unblob)](https://pypi.org/project/unblob/)
[![PyPI downloads](https://img.shields.io/pypi/dm/unblob)](https://pypi.org/project/unblob/)
[![License: MIT](https://img.shields.io/github/license/onekey-sec/unblob)](https://github.com/onekey-sec/unblob/blob/main/LICENSE)

---

## Demo

![demo](docs/demo.gif)

---

## Features

- **78+ supported formats** — archives, compression streams, and file systems including SquashFS, JFFS2, UBI/UBIFS, ext, CPIO, ZIP, 7-Zip, gzip, XZ, LZMA, LZ4, and many more. See the [full list](https://unblob.org/formats/).
- **Recursive extraction** — extracts containers within containers up to a configurable depth (default: 10 levels).
- **Precise chunk detection** — identifies both start and end offsets of each chunk according to the format standard, minimizing false positives.
- **Unknown chunk carving** — carves out and reports data that does not match any known format, automatically identifying null/`0xFF` padding.
- **Entropy analysis** — calculates Shannon entropy and chi-square probability for unknown chunks, useful for spotting encrypted or compressed data.
- **JSON metadata reports** — generates structured reports with chunk offsets, sizes, entropy, file ownership, permissions, timestamps, and more.
- **Multi-processing** — uses all available CPU cores by default for fast extraction.
- **Extensible plugin system** — write custom format handlers and extractors and load them at runtime with `--plugins-path`.
- **No elevated privileges required** — runs safely as a regular user.
- **Battle-tested** — fuzz tested against a large corpus of firmware images; relies on audited, pinned dependencies.

---

## Installation

### pip (recommended for most users)

```console
pip install unblob
```

Then install the required external extractor tools. On Ubuntu/Debian:

```console
sudo apt install android-sdk-libsparse-utils e2fsprogs p7zip-full unar zlib1g-dev liblzo2-dev lzop lziprecover libhyperscan-dev zstd lz4
```

For SquashFS support, also install [sasquatch](https://github.com/onekey-sec/sasquatch):

```console
curl -L -o sasquatch_1.0.deb "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-6/sasquatch_1.0_$(dpkg --print-architecture).deb"
sudo dpkg -i sasquatch_1.0.deb && rm sasquatch_1.0.deb
```

Verify that all extractors are available:

```console
unblob --show-external-dependencies
```

### Docker (batteries included)

The Docker image bundles all extractors — no extra setup needed:

```console
docker run \
  --rm \
  --pull always \
  -v /path/to/extract-dir:/data/output \
  -v /path/to/files:/data/input \
  ghcr.io/onekey-sec/unblob:latest /data/input/firmware.bin
```

> **Note:** Mount directories must be owned by the same `uid:gid`. On multi-user systems, add `-u $UID:$GID` to the command.

### Kali Linux

```console
sudo apt install unblob
```

### Nix

```console
nix profile install nixpkgs#unblob
```

Or add it to your NixOS/home-manager configuration — see the [installation docs](https://unblob.org/installation/) for flake and overlay examples.

### From source

```console
git clone https://github.com/onekey-sec/unblob.git
cd unblob
uv sync --no-dev
uv run unblob --show-external-dependencies
```

Requires Python ≥ 3.10, [uv](https://docs.astral.sh/uv/), and a Rust toolchain (for the compiled extensions).

---

## Usage

### Command line

Extract a file (output goes to `<filename>_extract/` by default):

```console
unblob firmware.bin
```

Specify a custom output directory:

```console
unblob -e /tmp/output firmware.bin
```

Generate a JSON metadata report:

```console
unblob --report report.json firmware.bin
```

Limit recursion depth and enable entropy analysis:

```console
unblob -d 5 -n 2 firmware.bin
```

Skip files matching a magic string prefix:

```console
unblob --skip-magic "POSIX tar archive" firmware.bin
```

Load a custom handler plugin:

```console
unblob -P ./myplugins/ firmware.bin
```

#### Full CLI reference

```
Usage: unblob [OPTIONS] FILE

Options:
  -e, --extract-dir DIRECTORY     Extract the files to this directory.
  -f, --force                     Force extraction even if outputs already exist.
  -d, --depth INTEGER             Recursion depth (default: 10).
  -n, --entropy-depth INTEGER     Entropy calculation depth (default: 1; 0 = off).
  -P, --plugins-path PATH         Load plugins from the provided path.
  -S, --skip-magic TEXT           Skip files with a given magic prefix.
  -p, --process-num INTEGER       Number of parallel worker processes (default: CPU count).
  --report PATH                   Write a JSON metadata report to this file.
  -k, --keep-extracted-chunks     Keep extracted chunks on disk.
  --delete-extracted-files TEXT   Delete intermediate files after extraction.
  -v, --verbose                   Increase verbosity (-v, -vv, -vvv).
  --show-external-dependencies    List required external tools and their status.
  -h, --help                      Show this message and exit.
```

### Python API

```python
from pathlib import Path
from unblob.processing import ExtractionConfig, process_file

config = ExtractionConfig(
    extract_root=Path("/tmp/output"),
    randomness_depth=1,
)

result = process_file(config, Path("firmware.bin"))
```

To also write a JSON report:

```python
process_file(config, Path("firmware.bin"), report_file=Path("report.json"))
```

`ExtractionConfig` accepts the same options as the CLI: `max_depth`, `process_num`, `skip_magic`, `force_extract`, `keep_extracted_chunks`, and more. See the [API reference](https://unblob.org/api/) for the full list.

---

## Testing

unblob uses [pytest](https://docs.pytest.org/). Integration test fixtures are stored in Git LFS.

```console
# Install Git LFS (one-time setup)
git lfs install

# Install all development dependencies
uv sync --all-extras --dev

# Run the full test suite
uv run pytest tests/ -v
```

---

## Documentation

Full documentation is available at **[https://unblob.org](https://unblob.org)**:

- [Installation](https://unblob.org/installation/)
- [User guide](https://unblob.org/guide/)
- [Supported formats](https://unblob.org/formats/)
- [API reference](https://unblob.org/api/)
- [Development guide](https://unblob.org/development/) — writing custom handlers, extractors, and plugins
- [Contribution guide](CONTRIBUTING.md)

---

## Contributing

Contributions are welcome! If you would like to add support for a new format or improve an existing one:

1. Open an [issue](https://github.com/onekey-sec/unblob/issues/new) to describe the format (hex dumps, spec links, and sample files help a lot).
2. Read the [development guide](https://unblob.org/development/) to learn how to write handlers and extractors.
3. Fork the repository, implement your changes, and open a pull request.

If you just need a format supported and don't want to implement it yourself, open an issue — we'll consider adding it.

See [CONTRIBUTING](CONTRIBUTING.md) for more details.

---

## License

unblob is licensed under the [MIT License](LICENSE).
