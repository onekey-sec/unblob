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
    "--extract",
    "extract_dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Extract the files to the given directory",
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
