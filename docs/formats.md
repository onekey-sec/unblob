---
hide:
  - navigation
---

# Supported file formats

unblob supports more than 30 formats. You can see their code in
[`unblob/handlers/`](https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/__init__.py).

✅: Some or all metadata is preserved for the format.  
❌: Metadata is not preserved (limitation of the format).

## Archives

| Format  |            | Preserved metadata |           | Handler                               | Extractor command           |
| ------- | ---------- | ------------------ | --------- | ------------------------------------- | --------------------------- |
|         | timestamps | permissions        | ownership |                                       |                             |
| AR      | ❌         | ❌                 | ❌        | [archive/ar.py][ar-handler]           | [`unar`][ar-extractor]      |
| ARC     | ❌         | ❌                 | ❌        | [archive/arc.py][arc-handler]         | [`unar`][arc-extractor]     |
| ARJ     | ✅         | ✅                 | ❌        | [archive/arj.py][arj-handler]         | [`7z`][arj-extractor]       |
| CAB     | ❌         | ❌                 | ❌        | [archive/cab.py][cab-handler]         | [`7z`][cab-extractor]       |
| CPIO    | ✅         | ✅                 | ✅        | [archive/cpio.py][cpio-handler]       | [`7z`][cpio-extractor]      |
| DMG     | ❌         | ❌                 | ❌        | [archive/dmg.py][dmg-handler]         | [`7z`][dmg-extractor]       |
| RAR     | ❌         | ❌                 | ❌        | [archive/rar.py][rar-handler]         | [`unar`][rar-extractor]     |
| 7ZIP    | ❌         | ❌                 | ❌        | [archive/sevenzip.py][7zip-handler]   | [`7z`][7zip-extractor]      |
| StuffIt | ❌         | ❌                 | ❌        | [archive/stuffit.py][stuffit-handler] | [`unar`][stuffit-extractor] |
| TAR     | ✅         | ✅                 | ✅        | [archive/tar.py][tar-handler]         | [`7z`][tar-extractor]       |
| ZIP     | ✅         | ✅                 | ✅        | [archive/zip.py][zip-handler]         | [`7z`][zip-extractor]       |

[ar-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/archive/ar.py
[ar-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/archive/ar.py#L30
[arc-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/archive/arc.py
[arc-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/archive/arc.py#L44
[arj-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/archive/arj.py
[arj-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/archive/arj.py#L102
[cab-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/archive/cab.py
[cab-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/archive/cab.py#L43
[cpio-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/archive/cpio.py
[cpio-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/archive/cpio.py#L49
[dmg-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/archive/dmg.py
[dmg-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/archive/dmg.py#L67-L69
[rar-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/archive/rar.py
[rar-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/archive/rar.py#L32
[7zip-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/archive/sevenzip.py
[7zip-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/archive/sevenzip.py#L58
[stuffit-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/archive/stuffit.py
[stuffit-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/archive/stuffit.py#L39
[tar-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/archive/tar.py
[tar-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/archive/tar.py#L105-L107
[zip-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/archive/zip.py
[zip-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/archive/zip.py#L62

## Compression

For compression formats, metadata cannot be preserved, as this information in most cases is not stored in the format.

| Format        | Handler                                     | Extractor                                     |
| ------------- | ------------------------------------------- | --------------------------------------------- |
| bzip2         | [compression/bzip2.py][bzip2-handler]       | [`7z`][bzip2-extractor]                       |
| UNIX compress | [compression/compress.py][compress-handler] | [`7z`][compress-extractor]                    |
| gzip          | [compression/gzip.py][gzip-handler]         | [`7z`][gzip-extractor]                        |
| LZ4           | [compression/lz4.py][lz4-handler]           | [`lz4`][lz4-extractor]                        |
| LZH           | [compression/lzh.py][lzh-handler]           | [`7z`][lzh-extractor]                         |
| LZIP          | [compression/lzip.py][lzip-handler]         | [`lziprecover`][lzip-extractor]               |
| LZMA          | [compression/lzma.py][lzma-handler]         | [`7z`][lzma-extractor]                        |
| LZO           | [compression/lzo.py][lzo-handler]           | [`lzop`][lzo-extractor]                       |
| XZ            | [compression/xz.py][xz-handler]             | [`7z`][xz-extractor]                          |
| ZLIB          | [compression/zlib.py][zlib-handler]         | [`ZlibExtractor` custom code][zlib-extractor] |
| ZSTD          | [compression/zstd.py][zstd-handler]         | [`zstd`][zstd-extractor]                      |

[bzip2-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/compression/bzip2.py
[bzip2-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/compression/bzip2.py#L139
[compress-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/compression/compress.py
[compress-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/compression/compress.py#L61
[gzip-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/compression/gzip.py
[gzip-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/compression/gzip.py#L63
[lz4-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/compression/lz4.py
[lz4-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/compression/lz4.py#L70
[lzh-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/compression/lzh.py
[lzh-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/compression/lzh.py#L58
[lzip-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/compression/lzip.py
[lzip-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/compression/lzip.py#L43-L45
[lzma-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/compression/lzma.py
[lzma-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/compression/lzma.py#L44
[lzo-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/compression/lzo.py
[lzo-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/compression/lzo.py#L78
[xz-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/compression/xz.py
[xz-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/compression/xz.py#L173
[zlib-handler]: https://github.com/onekey-sec/unblob/blob/8fe0d558265b87cb5c29dbc8f618b79297732a1a/unblob/handlers/compression/zlib.py
[zlib-extractor]: https://github.com/onekey-sec/unblob/blob/8fe0d558265b87cb5c29dbc8f618b79297732a1a/unblob/handlers/compression/zlib.py#L16-L22
[zstd-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/compression/zstd.py
[zstd-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/compression/zstd.py#L27

## Filesystems

| Format                 | Preserved metadata                 | Handler                                         | Extractor command                               |
| ---------------------- | ---------------------------------- | ----------------------------------------------- | ----------------------------------------------- |
| Android sparse image   | ❌                                 | [filesystem/android/sparse.py][android-handler] | [`simg2img`][android-extractor]                 |
| CRAMFS                 | ✅                                 | [filesystem/cramfs.py][cramfs-handler]          | [`7z`][cramfs-extractor]                        |
| ExtFS                  | ✅                                 | [filesystem/extfs.py][extfs-handler]            | [`debugfs`][extfs-extractor]                    |
| FAT                    | ✅                                 | [filesystem/fat.py][fat-handler]                | [`7z`][fat-extractor]                           |
| ISO9660                | ✅                                 | [filesystem/iso9660.py][iso9660-handler]        | [`7z`][iso9660-extractor]                       |
| JFFS2                  | ✅                                 | [filesystem/jffs2.py][jffs2-handler]            | [`jefferson`][jffs2-extractor]                  |
| NTFS                   | ✅                                 | [filesystem/ntfs.py][ntfs-handler]              | [`7z`][ntfs-extractor]                          |
| RomFS                  | ✅ everything is `o+rw` or `o+rwx` | [filesystem/romfs.py][romfs-handler]            | [`RomFsExtractor` custom code][romfs-extractor] |
| SquashFS (v3, v4)      | ✅                                 | [filesystem/squashfs.py][squashfs-handler]      | [`sasquatch`][squashfs-extractor]               |
| SquashFS v4 Big Endian | ✅                                 | [filesystem/squashfs.py][squashfs-handler]      | [`sasquatch-v4-be`][squashfs-v4-be-extractor]   |
| UBI                    | ✅                                 | [filesystem/ubi.py][ubi-handler]                | [`ubireader_extract_images`][ubi-extractor]     |
| UBIFS                  | ✅                                 | [filesystem/ubi.py][ubi-handler]                | [`ubireader_extract_files`][ubifs-extractor]    |
| YAFFS (1, 2)           | ✅                                 | [filesystem/yaffs.py][yaffs-handler]            | [`yaffshiv`][yaffs-extractor]                   |

[android-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/filesystem/android/sparse.py
[android-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/android/sparse.py#L61
[cramfs-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/filesystem/cramfs.py
[cramfs-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/cramfs.py#L45
[extfs-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/filesystem/extfs.py
[extfs-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/extfs.py#L68
[fat-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/filesystem/fat.py
[fat-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/fat.py#L103
[iso9660-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/filesystem/iso9660.py
[iso9660-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/iso9660.py#L111
[jffs2-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/filesystem/jffs2.py
[jffs2-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/jffs2.py#L56
[ntfs-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/filesystem/ntfs.py
[ntfs-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/ntfs.py#L63
[romfs-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/filesystem/romfs.py
[romfs-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/romfs.py#L334-L340
[squashfs-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/filesystem/squashfs.py
[squashfs-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/squashfs.py#L18-L20
[squashfs-v4-be-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/squashfs.py#L233-L235
[ubi-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/filesystem/ubi.py
[ubi-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/ubi.py#L105
[ubifs-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/ubi.py#L82
[yaffs-handler]: https://github.com/onekey-sec/unblob/blob/main/unblob/handlers/filesystem/yaffs.py
[yaffs-extractor]: https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/handlers/filesystem/yaffs.py#L113

## Didn't find your format supported yet?

unblob is easily extensible, and you can write your own handler and include your own extractors for proprietary formats.
To learn more about this, see the [development section](development.md).
Alternatively, just open a [new ticket](https://github.com/onekey-sec/unblob/issues) in the Github issue tracker.

Whenever we stumble upon proprietary formats in our ONEKEY analysis platform, we will add support for it.
At this point, we have developed about a dozen of additional, proprietary format Handlers.

If you are interested in a custom format not supported by the open source version, check out our platform at
[https://www.onekey.com](https://www.onekey.com) or you can [Contact Us](support.md).
