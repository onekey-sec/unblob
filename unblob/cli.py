#!/usr/bin/env python3
import sys
from pathlib import Path
from typing import Tuple

import click
from structlog import get_logger

from .logging import configure_logger
from .processing import DEFAULT_DEPTH, process_file

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
    default=DEFAULT_DEPTH,
    help="Recursion depth. How deep should we extract containers.",
)
@click.option("-v", "--verbose", is_flag=True, help="Verbose mode, enable debug logs.")
def cli(files: Tuple[Path], extract_root: Path, depth: int, verbose: bool):
    configure_logger(verbose, extract_root)
    logger.info("Start processing files", count=len(files))
    for path in files:
        process_file(path.parent, path, extract_root, max_depth=depth)


def main():
    try:
        ctx = cli.make_context("unblob", sys.argv[1:])
    except click.ClickException as e:
        e.show()
        sys.exit(e.exit_code)
    except click.exceptions.Exit as e:
        sys.exit(e.exit_code)

    with ctx:
        cli.invoke(ctx)


if __name__ == "__main__":
    main()
