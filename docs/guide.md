# User guide

## Command line interface

```
Usage: unblob [OPTIONS] FILE

  A tool for getting information out of any kind of binary blob.

  You also need these extractor commands to be able to extract the supported
  file types: 7z, debugfs, jefferson, lz4, lziprecover, lzop, sasquatch,
  sasquatch-v4be, simg2img, ubireader_extract_files, ubireader_extract_images,
  unar, yaffshiv, zstd

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
