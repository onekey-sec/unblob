---
hide:
  - navigation
---

# User guide

## Quickstart

unblob has a very _simple_ command line interface with _sensible defaults_.
You just need to pass it a file you want to extract:

```console
$ unblob alpine-minirootfs-3.16.1-x86_64.tar.gz
2022-07-30 06:33.07 [info     ] Start processing file          file=openwrt-21.02.2-x86-64-generic-ext4-combined.img.gz pid=7092
```

It will make a new directory with the original filename appended with `_extract`:

```console
$ ls -l
total 2656
drwxrwxr-x 3 walkman walkman    4096 Jul 30 08:43 alpine-minirootfs-3.16.1-x86_64.tar.gz_extract
-rw-r--r-- 1 walkman walkman 2711958 Jul 30 08:43 alpine-minirootfs-3.16.1-x86_64.tar.gz
```

And will extract [all known file formats](formats.md) **recursively** until the
specified _recursion depth_ level (which is **10** by default):

```console
$ tree -L 2
alpine-minirootfs-3.16.1-x86_64.tar.gz_extract
├── alpine-minirootfs-3.16.1-x86_64.tar
└── alpine-minirootfs-3.16.1-x86_64.tar_extract
    ├── bin
    ├── dev
    ├── etc
    ├── home
    ├── lib
    ├── media
    ├── mnt
    ├── opt
    ├── proc
    ├── root
    ├── run
    ├── sbin
    ├── srv
    ├── sys
    ├── tmp
    ├── usr
    └── var

18 directories, 1 file
```

## Features

### Metadata extraction

unblob can generate a metadata file about the extracted files in a JSON format
by using the `--report` CLI option:

```console
$ unblob --report alpine-report.json alpine-minirootfs-3.16.1-x86_64.tar.gz
2022-07-30 07:06.59 [info     ] Start processing file          file=alpine-minirootfs-3.16.1-x86_64.tar.gz pid=13586
2022-07-30 07:07.00 [info     ] JSON report written            path=alpine-report.json pid=13586

$ cat alpine-report.json
[
  {
    "task": {
      "path": "/home/walkman/Projects/unblob/demo/alpine-minirootfs-3.16.1-x86_64.tar.gz",
      "depth": 0,
      "chunk_id": ""
    },
    "reports": [
      {
        "path": "/home/walkman/Projects/unblob/demo/alpine-minirootfs-3.16.1-x86_64.tar.gz",
        "size": 2711958,
        "is_dir": false,
        "is_file": true,
        "is_link": false,
        "link_target": null,
        "report_type": "StatReport"
      },
      {
        "magic": "gzip compressed data, max compression, from Unix, original size modulo 2^32 5816320\\012- data",
        "mime_type": "application/gzip",
        "report_type": "FileMagicReport"
      },
      {
        "id": "13590:1",
        "handler_name": "gzip",
        "start_offset": 0,
        "end_offset": 2711958,
        "size": 2711958,
        "is_encrypted": false,
        "extraction_reports": [],
        "report_type": "ChunkReport"
      }
    ],
    "subtasks": [
      {
        "path": "/home/walkman/Projects/unblob/demo/alpine-minirootfs-3.16.1-x86_64.tar.gz_extract",
        "depth": 1,
        "chunk_id": "13590:1"
      }
    ]
  },
  ...
]
```

### Randomness calculation

If you are analyzing an unknown file format, it might be useful to know the
randomness of the contained files, so you can quickly see for example whether the
file is **encrypted** or contains some random content.

Let's make a file with fully random content at the start and end:

```console
$ dd if=/dev/random of=random1.bin bs=10M count=1
$ dd if=/dev/random of=random2.bin bs=10M count=1
$ cat random1.bin alpine-minirootfs-3.16.1-x86_64.tar.gz random2.bin > unknown-file
```

A nice ASCII randomness plot is drawn on verbose level 3:

```console
$ unblob -vvv unknown-file | grep -C 15 "Entropy distribution"

2024-10-30 10:52.03 [debug    ] Calculating chunk for pattern match handler=arc pid=1963719 real_offset=0x1685f5b start_offset=0x1685f5b
2024-10-30 10:52.03 [debug    ] Header parsed                  header=<arc_head archive_marker=0x1a, header_type=0x1, name=b'8\xa7i&po\xc77\xd5h\x9a\x9d\xf1', size=0x26d171fa, date=0x1bfd, time=0xe03f, crc=-0x3b95, length=0x349997d5> pid=1963719
2024-10-30 10:52.03 [debug    ] Ended searching for chunks     all_chunks=[0xa00000-0xc96196] pid=1963719
2024-10-30 10:52.03 [debug    ] Removed inner chunks           outer_chunk_count=1 pid=1963719 removed_inner_chunk_count=0
2024-10-30 10:52.03 [warning  ] Found unknown Chunks           chunks=[0x0-0xa00000, 0xc96196-0x1696196] pid=1963719
2024-10-30 10:52.03 [info     ] Extracting unknown chunk       chunk=0x0-0xa00000 path=unknown-file_extract/0-10485760.unknown pid=1963719
2024-10-30 10:52.03 [debug    ] Carving chunk                  path=unknown-file_extract/0-10485760.unknown pid=1963719
2024-10-30 10:52.03 [debug    ] Calculating randomness for file path=unknown-file_extract/0-10485760.unknown pid=1963719 size=0xa00000
2024-10-30 10:52.03 [debug    ] Shannon entropy calculated     block_size=0x20000 highest=99.99 lowest=99.98 mean=99.98 path=unknown-file_extract/0-10485760.unknown pid=1963719 size=0xa00000
2024-10-30 10:52.03 [debug    ] Chi square probability calculated block_size=0x20000 highest=97.88 lowest=3.17 mean=52.76 path=unknown-file_extract/0-10485760.unknown pid=1963719 size=0xa00000
2024-10-30 10:52.03 [debug    ] Entropy chart                  chart=
                              Randomness distribution
   ┌───────────────────────────────────────────────────────────────────────────┐
100┤ •• Shannon entropy (%)        •••••••••♰••••••••••••••••••••••••••••••••••│
 90┤ ♰♰ Chi square probability (%)   ♰ ♰ ♰♰♰♰                    ♰    ♰  ♰     │
 80┤♰ ♰ ♰♰  ♰♰       ♰♰       ♰ ♰   ♰♰♰♰♰♰♰♰♰   ♰           ♰♰♰♰♰♰   ♰♰ ♰♰     │
 70┤♰♰♰♰  ♰ ♰ ♰ ♰   ♰♰♰  ♰ ♰  ♰ ♰   ♰♰♰♰♰♰♰♰♰  ♰♰      ♰ ♰ ♰   ♰♰♰  ♰♰♰♰♰♰     │
 60┤♰♰♰♰  ♰♰  ♰♰ ♰ ♰♰♰♰ ♰ ♰♰ ♰  ♰ ♰ ♰♰♰♰♰♰ ♰♰ ♰ ♰     ♰♰♰♰ ♰   ♰♰♰ ♰♰♰♰♰♰♰     │
 50┤ ♰♰♰  ♰♰  ♰♰ ♰♰ ♰♰♰♰  ♰♰ ♰  ♰♰♰ ♰♰♰♰♰♰  ♰ ♰ ♰    ♰♰♰♰♰ ♰   ♰♰♰ ♰ ♰♰♰♰♰  ♰  │
 40┤  ♰♰  ♰♰   ♰ ♰♰ ♰♰♰♰  ♰♰ ♰  ♰♰♰ ♰♰♰♰♰♰   ♰♰  ♰♰ ♰♰♰♰♰♰ ♰   ♰♰♰ ♰  ♰♰♰♰ ♰♰ ♰│
 30┤   ♰  ♰♰     ♰♰ ♰♰♰♰  ♰ ♰♰  ♰♰ ♰♰ ♰ ♰♰    ♰   ♰ ♰♰♰ ♰ ♰     ♰♰ ♰  ♰♰♰ ♰♰ ♰ │
 20┤      ♰♰     ♰♰  ♰♰♰  ♰ ♰♰   ♰ ♰♰    ♰        ♰ ♰ ♰ ♰         ♰    ♰♰      │
 10┤       ♰      ♰    ♰  ♰  ♰     ♰♰    ♰         ♰                   ♰♰      │
  0┤                                ♰                                   ♰      │
   └─┬──┬─┬──┬────┬───┬──┬──┬──┬───┬───┬──┬────┬───┬────┬──┬──┬────┬──┬───┬──┬─┘
   0 2  5 7 11   16  20 23 27 30  34  38 42   47  51   56 60 63   68 71  76 79
                                   131072 bytes
 path=unknown-file_extract/0-10485760.unknown pid=1963719
2024-10-30 10:52.03 [info     ] Extracting unknown chunk       chunk=0xc96196-0x1696196 path=unknown-file_extract/13197718-23683478.unknown pid=1963719
2024-10-30 10:52.03 [debug    ] Carving chunk                  path=unknown-file_extract/13197718-23683478.unknown pid=1963719
2024-10-30 10:52.03 [debug    ] Calculating randomness for file path=unknown-file_extract/13197718-23683478.unknown pid=1963719 size=0xa00000
2024-10-30 10:52.03 [debug    ] Shannon entropy calculated     block_size=0x20000 highest=99.99 lowest=99.98 mean=99.98 path=unknown-file_extract/13197718-23683478.unknown pid=1963719 size=0xa00000
2024-10-30 10:52.03 [debug    ] Chi square probability calculated block_size=0x20000 highest=99.03 lowest=0.23 mean=42.62 path=unknown-file_extract/13197718-23683478.unknown pid=1963719 size=0xa00000
2024-10-30 10:52.03 [debug    ] Entropy chart                  chart=
                              Randomness distribution
   ┌───────────────────────────────────────────────────────────────────────────┐
100┤ •• Shannon entropy (%)        •••••••••••••••••••••♰••••••••••••••••••••••│
 90┤ ♰♰ Chi square probability (%)         ♰           ♰♰            ♰         │
 80┤♰♰        ♰♰    ♰♰    ♰               ♰♰       ♰   ♰♰        ♰  ♰♰         │
 70┤♰ ♰   ♰  ♰  ♰  ♰ ♰    ♰ ♰    ♰        ♰♰      ♰♰   ♰♰♰   ♰  ♰♰  ♰♰         │
 60┤  ♰  ♰♰ ♰   ♰ ♰  ♰  ♰♰♰♰♰   ♰♰        ♰♰ ♰♰   ♰ ♰  ♰♰♰  ♰♰ ♰ ♰  ♰♰   ♰     │
 50┤  ♰ ♰♰♰ ♰   ♰ ♰  ♰ ♰ ♰♰♰♰ ♰ ♰♰      ♰ ♰♰♰ ♰   ♰ ♰  ♰♰♰  ♰♰ ♰ ♰  ♰♰  ♰♰   ♰ │
 40┤  ♰♰♰♰ ♰♰    ♰♰  ♰ ♰ ♰♰  ♰♰♰  ♰♰♰  ♰♰♰ ♰♰ ♰   ♰  ♰ ♰♰ ♰ ♰♰ ♰ ♰ ♰ ♰ ♰♰♰  ♰♰ │
 30┤  ♰♰♰♰ ♰♰    ♰♰   ♰♰ ♰♰   ♰♰     ♰♰♰♰♰ ♰♰ ♰   ♰  ♰ ♰♰  ♰♰♰ ♰ ♰ ♰ ♰ ♰ ♰  ♰ ♰│
 20┤   ♰♰♰  ♰     ♰      ♰♰   ♰♰      ♰♰♰♰ ♰♰ ♰   ♰  ♰ ♰♰   ♰♰ ♰ ♰♰  ♰♰  ♰  ♰  │
 10┤     ♰                ♰    ♰       ♰ ♰  ♰ ♰ ♰♰   ♰ ♰♰     ♰♰ ♰♰   ♰  ♰ ♰   │
  0┤                                           ♰ ♰    ♰♰          ♰       ♰♰   │
   └─┬──┬─┬──┬────┬───┬──┬──┬──┬───┬───┬──┬────┬───┬────┬──┬──┬────┬──┬───┬──┬─┘
   0 2  5 7 11   16  20 23 27 30  34  38 42   47  51   56 60 63   68 71  76 79
                                   131072 bytes
```

### Skip extraction with file magic

The extraction process can be **faster** and produce **fewer false positives** if we just
ignore some files, which we know will not contain meaningful results, or it
makes no sense to extract them. Examples of such file formats are SQLite, images,
fonts, or PDF documents.

We have a [default for the skip list](https://github.com/onekey-sec/unblob/blob/3008039881a0434deb75962e7999b7e35aca8271/unblob/processing.py#L44-L56),
but you can change it with the `--skip-magic` CLI option. Here is a silly example:

```console
$ unblob --skip-magic "POSIX tar archive" alpine-minirootfs-3.16.1-x86_64.tar.gz
2022-07-30 07:18.09 [info ] Start processing file file=alpine-minirootfs-3.16.1-x86_64.tar.gz pid=14971

$ tree .
├── alpine-minirootfs-3.16.1-x86_64.tar.gz
└── alpine-minirootfs-3.16.1-x86_64.tar.gz_extract
└── alpine-minirootfs-3.16.1-x86_64.tar
```

Here gzip has been extracted, but we skipped the tar extraction, so no other
files have been extracted further.

## Full Command line interface

```
Usage: unblob [OPTIONS] FILE

  A tool for getting information out of any kind of binary blob.

  You also need these extractor commands to be able to extract the supported
  file types: 7z, debugfs, jefferson, lz4, lziprecover, lzop, sasquatch,
  sasquatch-v4be, simg2img, ubireader_extract_files, ubireader_extract_images,
  unar, zstd

  NOTE: Some older extractors might not be compatible.

Options:
  -e, --extract-dir DIRECTORY     Extract the files to this directory. Will be
                                  created if doesn't exist.
  -f, --force                     Force extraction even if outputs already
                                  exist (they are removed).
  -d, --depth INTEGER RANGE       Recursion depth. How deep should we extract
                                  containers.  [default: 10; x>=1]
  -n, --entropy-depth INTEGER RANGE
                                  Entropy calculation depth. How deep should
                                  we calculate entropy for unknown files? 1
                                  means input files only, 0 turns it off.
                                  [default: 1; x>=0]
  -P, --plugins-path PATH         Load plugins from the provided path.
  -S, --skip-magic TEXT           Skip processing files with given magic
                                  prefix  [default: BFLT, JPEG, GIF, PNG,
                                  SQLite, compiled Java class, TrueType Font
                                  data, PDF document, magic binary file, MS
                                  Windows icon resource, PE32+ executable (EFI
                                  application)]
  -p, --process-num INTEGER RANGE
                                  Number of worker processes to process files
                                  parallelly.  [default: 12; x>=1]
  --report PATH                   File to store metadata generated during the
                                  extraction process (in JSON format).
  -k, --keep-extracted-chunks     Keep extracted chunks
  -v, --verbose                   Verbosity level, counting, maximum level: 3
                                  (use: -v, -vv, -vvv)
  --show-external-dependencies    Shows commands needs to be available for
                                  unblob to work properly
  -h, --help                      Show this message and exit.

```
