#!/usr/bin/env python3
import click
from typing import List
from pathlib import Path
from .finder import search_blobs


@click.group(context_settings={"help_option_names": ["--help", "-h"]})
def main():
    pass


@main.command()
@click.argument(
    "files",
    nargs=-1,
    type=click.Path(path_type=Path, exists=True, resolve_path=True),
)
@click.option(
    "-o",
    "--output-dir",
    "extract_root",
    type=click.Path(path_type=Path, dir_okay=True, file_okay=False, resolve_path=True),
    help="Extract the files to this directory. Will be created if doesn't exist.",
)
@click.option(
    "-d",
    "--depth",
    type=int,
    default=10,
    help="Recursion depth. How deep should we extract containers.",
)
def priority_extract(files: Tuple[Path], extract_root: Path, depth: int):
    """Extract based on a priority list.

    \b
    The files will be extracted in this order:
    0 - Known specific firmware container formats.
    1 - Disk filesystems (EXT, FAT, GPT, Android)
    2 - Flash filesystems (SquashFS, CramFS, ROMFS, YAFFS, etc)
    4 - Archive/container formats (with verbose headers) - 7z, tar, gzip
    6 - Compression streams (LZMA, XZ)\b
    8 - File formats (ELF, PE)\b
    """
@main.command()
@click.argument(
    "files",
    nargs=-1,
    type=click.Path(path_type=Path, exists=True, resolve_path=True),
)
@click.option(
    "-o",
    "--output-dir",
    "extract_root",
    type=click.Path(path_type=Path, dir_okay=True, file_okay=False, resolve_path=True),
    help="Extract the files to this directory. Will be created if doesn't exist.",
)
def linear_extract(files: Tuple[Path], extract_root: Path, depth: int):
    """Extract any blobs found in the files without recursion.
    This is similar to how radare2 works.
    """


@main.command()
@click.argument(
    "files",
    nargs=-1,
    type=click.Path(path_type=Path, exists=True, resolve_path=True),
)
def analyze(files: Tuple[Path]):
    """Just analyze the blobs, don't extract anything. Print lots of debugging information."""


@main.command()
@click.argument(
    "files",
    nargs=-1,
    type=click.Path(path_type=Path, exists=True, resolve_path=True),
)
@click.option(
    "-o",
    "--output-dir",
    "extract_root",
    type=click.Path(path_type=Path, dir_okay=True, file_okay=False, resolve_path=True),
    help="Extract the files to this directory. Will be created if doesn't exist.",
)
def create_wx_tags(files: Tuple[Path], extract_root: Path, depth: int):
    """Extract blobs and create WX Hex Editor Tags.

    It generates XML tag files, which can be imported in WX Hex Editor:
    https://sourceforge.net/projects/wxhexeditor/
    """

if __name__ == "__main__":
    main()
