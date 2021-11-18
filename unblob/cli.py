#!/usr/bin/env python3
import click
from typing import Tuple
from pathlib import Path
from structlog import get_logger
from .logging import configure_logger, format_hex
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
@click.option("-v", "--verbose", is_flag=True, help="Verbose mode, enable debug logs.")
def main(files: Tuple[Path], extract_root: Path, depth: int, verbose: bool):
    configure_logger(verbose=verbose)
    logger.info("Start processing files", count=len(files))
    for path in files:
        process_file(path.parent, path, extract_root, depth)


def process_file(
    root: Path,
    path: Path,
    extract_root: Path,
    depth: int,
):
    log = logger.bind(path=path)
    log.info("Start processing file")

    if depth <= 0:
        log.info("Reached maximum depth, stop further processing")
        return

    if path.is_dir():
        log.info("Found directory")
        for path in path.iterdir():
            process_file(root, path, extract_root, depth - 1)
        return

    if path.is_symlink():
        log.info("Ignoring symlink")
        return

    file_size = path.stat().st_size
    if file_size == 0:
        log.info("Ignoring empty file")
        return

    log.info("Calculated file size", size=format_hex(file_size))
    for new_path in extract_with_priority(root, path, extract_root):
        process_file(extract_root, new_path, extract_root, depth - 1)


if __name__ == "__main__":
    main()
