# Supported file formats

Unblob supports more than 30 formats.

## Archives

| Format  | Handler | Extractor |
| ------- | ------- | --------- |
| AR      |         |           |
| ARC     |         |           |
| ARJ     |         |           |
| CAB     |         |           |
| CPIO    |         |           |
| DMG     |         |           |
| RAR     |         |           |
| 7ZIP    |         |           |
| StuffIt |         |           |
| TAR     |         |           |
| ZIP     |         |           |

## Compression

| Format        | Handler | Extractor |
| ------------- | ------- | --------- |
| bzip2         |         |           |
| UNIX compress |         |           |
| gzip          |         |           |
| LZ4           |         |           |
| LZH           |         |           |
| LZIP          |         |           |
| LZMA          |         |           |
| LZO           |         |           |
| XZ            |         |           |

## Filesystems

| Format               | Handler | Extractor |
| -------------------- | ------- | --------- |
| Android sparse image |         |           |
| CRAMFS               |         |           |
| ExtFS                |         |           |
| FAT                  |         |           |
| ISO9660              |         |           |
| JFFS2                |         |           |
| NTFS                 |         |           |
| RomFS                |         |           |
| SquashFS (v3, v4)    |         |           |
| UBI                  |         |           |
| UBIfs                |         |           |
| YAFFS (1, 2)         |         |           |

## Proprietary formats

We developed about a dozen of proprietary format `Handler`s that we can't
release to the Open Source version for legal or other reasons.

If you are interested in a custom format not supported by the Open Source
version, check out our platform at https://www.onekey.com or you can
[Contact Us](support.md).

You can write your own format, see how in the [Development section](development.md).
