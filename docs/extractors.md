---
hide:
  - navigation
---

# Extractors

unblob relies on various tools for extracting the contents of a blob. These
extractors are either **third party tools (e.g. 7z)**, or part of unblob (available
in [`unblob/extractors`](https://github.com/onekey-sec/unblob/tree/main/python/unblob/extractors)
directory or specific ones next to the handler, e.g.:
[`unblob/handlers/filesystem/romfs.py`](https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/romfs.py#L334)).

To use unblob with all supported formats, **all extractors need to be installed**.

See the [Installation section](installation.md) on how to install extractors for
various methods. You _don't need_ to install any of these _if you use Docker or Nix_,
as all extractors are included in those solutions.

## Checking installed extractors

There is a `--show-external-dependencies` CLI option, which displays the name of
the extractors used by unblob and shows if they are available for unblob to use
or not:

```shell
$ unblob --show-external-dependencies
The following executables found installed, which are needed by unblob:
    7z                          ✓
    debugfs                     ✓
    jefferson                   ✓
    lz4                         ✓
    lziprecover                 ✓
    lzop                        ✓
    sasquatch                   ✓
    sasquatch-v4be              ✓
    simg2img                    ✓
    ubireader_extract_files     ✓
    ubireader_extract_images    ✓
    unar                        ✓
    zstd                        ✓
```

**NOTE**: This option does NOT check the version of the extractors.

## Required extractors

❌: If you installed unblob from source, you need to install these manually.

✅: These extractors come with unblob, check
[pyproject.toml](https://github.com/onekey-sec/unblob/blob/main/pyproject.toml)
and [uv.lock](https://github.com/onekey-sec/unblob/blob/main/uv.lock)
for current versions.

| Extractor                   | Provided commands                                     | Minimum version | Pre-Installed | More information                                                 |
| --------------------------- | ----------------------------------------------------- | --------------- | ------------- | ---------------------------------------------------------------- |
| p7zip-full                  | `7z`                                                  | 16.02           | ❌            | https://www.7-zip.org/                                           |
| e2fsprogs                   | `debugfs`                                             | 1.45.5          | ❌            | http://e2fsprogs.sourceforge.net/                                |
| lz4                         | `lz4`                                                 | 1.9.3           | ❌            | https://github.com/lz4/lz4                                       |
| lziprecover                 | `lziprecover`                                         | 1.22            | ❌            | http://www.nongnu.org/lzip/lziprecover.html                      |
| lzop                        | `lzop`                                                | 1.04            | ❌            | https://www.lzop.org/                                            |
| android-sdk-libsparse-utils | `img2simg`                                            | 8.1.0           | ❌            | https://packages.debian.org/unstable/android-sdk-libsparse-utils |
| unar                        | `unar`                                                | 1.10.1          | ❌            | https://theunarchiver.com/command-line                           |
| sasquatch                   | `sasquatch`, `sasquatch-v4be`                         | 1.0             | ❌            | https://github.com/onekey-sec/sasquatch                          |
| jefferson                   | `jefferson`                                           | master          | ✅            | https://github.com/onekey-sec/jefferson                          |
| ubireader                   | `ubireader_extract_files`, `ubireader_extract_images` | master          | ✅            | https://github.com/onekey-sec/ubi_reader                         |

## Maintained projects and forks

We maintain a fork of several extractors, with many fixes and improvements.
They are also available on GitHub:

- [Jefferson](https://github.com/onekey-sec/jefferson) for extracting JFFS2 is also a project of ONEKEY
- [Fork of sasquatch](https://github.com/onekey-sec/sasquatch) based on squashfs-tools
- [Fork of ubi_reader](https://github.com/onekey-sec/ubi_reader) Python scripts for extracting UBI and UBIFS images
