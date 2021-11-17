#!/usr/bin/env python3
import click
from typing import List
from pathlib import Path
from .finder import search_blobs


@click.command()
@click.argument(
    "files",
    nargs=-1,
    type=click.Path(exists=True, path_type=Path),
)
@click.option(
    "-e",
    "--extract-dir",
    "extract_root",
    type=click.Path(path_type=Path, dir_okay=True, file_okay=False, resolve_path=True),
    default=Path.cwd(),
    help="Extract the files to this directory. Will be created if doesn't exist.",
)
@click.option(
    "-d",
    "--depth",
    type=int,
    default=1,
    help="Recursion depth. How deep should we extract containers.",
)
@click.option(
    "-s",
    "--strategy",
    type=click.Choice(["priority"]),
    default="priority",
    help="The strategy of how we do extraction. Default is priority.",
)
def main(files, extract_dir, depth):
    click.echo(f"Got files: {files}")
    process_files(files, extract_dir)


if __name__ == "__main__":
    main()
