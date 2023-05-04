# unblob-native

Looking for Unblob? Check out at https://unblob.org.

This package holds performance-critical components of Unblob,
an _accurate, fast, and easy-to-use_ **extraction suite**. It parses
unknown binary blobs for more than 30 different _archive, compression, and
file-system formats_, **extracts** their **content recursively**, and **carves**
out **unknown chunks** that have not been accounted for.

Unblob is _free to use_, licensed with the _MIT license_. It has a
Command Line Interface and can be used as a Python library.
This turns unblob into the perfect companion for extracting, **analyzing**,
and **reverse engineering firmware images**.

## Development

This package is easiest to develop using [Nix](https://nixos.org). Refer to the
relevant section of [The Unblob Documentation](https://unblob.org/installation/#nix-package)
on how to install Nix.

Once ready, issue `nix develop`, and the required tools will be set-up for you.

The package is managed via [PDM](https://pdm.fming.dev/latest/). Just call `pdm
all`, and it will execute the required check and test steps for you. Use `pdm
run --list` to see what commands are being executed.
