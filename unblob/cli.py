#!/usr/bin/env python3
import click
from typing import Tuple
from pathlib import Path
from structlog import get_logger
from .logging import configure_logger
from .strategies import extract_with_priority


logger = get_logger()


@click.command()
@click.argument(
    "files",
    nargs=-1,
    type=click.Path(path_type=Path, exists=True, resolve_path=True),
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
    default=10,
    help="Recursion depth. How deep should we extract containers.",
)
def main(files: Tuple[Path], extract_root: Path, depth: int):
    configure_logger()
    logger.info(f"Got files: {files}")
    for path in files:
        process_file(path.parent, path, extract_root, depth)


def process_file(
    root: Path,
    path: Path,
    extract_root: Path,
    depth: int,
):
    if depth <= 0:
        logger.info("Reached maximum depth, stop further processing")
        return

    if path.is_dir():
        logger.info(f"Path is a dir: {path}")
        for path in path.iterdir():
            process_file(root, path, extract_root, depth - 1)
        return

    if path.is_symlink():
        logger.info("Path is symlink, ignoring")
        return

    file_size = path.stat().st_size
    logger.info(f"File: {path.resolve()}\n" f"Size: 0x{file_size:x} ({file_size})\n")
    if file_size == 0:
        logger.info("Filesize is 0, skipping.")
        return

    for new_path in extract_with_priority(root, path, extract_root):
        process_file(extract_root, new_path, extract_root, depth - 1)


if __name__ == "__main__":
    main()
