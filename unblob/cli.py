#!/usr/bin/env python3
import sys
from pathlib import Path
from typing import Tuple

import click
from structlog import get_logger

from .dependencies import get_dependencies, pretty_format_dependencies
from .handlers import ALL_HANDLERS
from .logging import configure_logger, noformat
from .processing import DEFAULT_DEPTH, process_file
from .state import exit_code_var

logger = get_logger()


def show_external_dependencies(
    ctx: click.Context, _param: click.Option, value: bool
) -> None:
    if not value or ctx.resilient_parsing:
        return

    dependencies = get_dependencies(ALL_HANDLERS)
    text = pretty_format_dependencies(dependencies)
    exit_code = 0 if all(dep.is_installed for dep in dependencies) else 1

    click.echo(text)
    ctx.exit(code=exit_code)


def get_help_text():
    dependencies = get_dependencies(ALL_HANDLERS)
    lines = [
        "A tool for getting information out of any kind of binary blob.",
        "",
        "You also need these extractor commands to be able to extract the supported file types:",
        ", ".join(dep.command for dep in dependencies),
        "",
        "NOTE: Some older extractors might not be compatible.",
    ]
    return "\n".join(lines)


@click.command(help=get_help_text())
@click.argument(
    "files",
    nargs=-1,
    type=click.Path(path_type=Path, exists=True, resolve_path=True),
    required=True,
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
    default=DEFAULT_DEPTH,
    type=click.IntRange(1),
    show_default=True,
    help="Recursion depth. How deep should we extract containers.",
)
@click.option(
    "-n",
    "--entropy-depth",
    type=click.IntRange(0),
    default=1,
    show_default=True,
    help=(
        "Entropy calculation depth. How deep should we calculate entropy for unknown files? "
        "1 means input files only, 0 turns it off."
    ),
)
@click.option("-v", "--verbose", is_flag=True, help="Verbose mode, enable debug logs.")
@click.option(
    "--show-external-dependencies",
    help="Shows commands needs to be available for unblob to work properly",
    is_flag=True,
    callback=show_external_dependencies,
    expose_value=False,
    is_eager=True,
)
def cli(
    files: Tuple[Path],
    extract_root: Path,
    depth: int,
    entropy_depth: int,
    verbose: bool,
):
    configure_logger(verbose, extract_root)
    logger.info("Start processing files", count=noformat(len(files)))
    for path in files:
        root = path if path.is_dir() else path.parent
        process_file(
            root,
            path,
            extract_root,
            max_depth=depth,
            entropy_depth=entropy_depth,
            verbose=verbose,
        )


def main():
    try:
        # Click argument parsing
        ctx = cli.make_context("unblob", sys.argv[1:])
    except click.ClickException as e:
        e.show()
        sys.exit(e.exit_code)
    except click.exceptions.Exit as e:
        sys.exit(e.exit_code)
    except Exception:
        logger.exception("Unhandled exception during unblob")
        sys.exit(1)

    try:
        with ctx:
            cli.invoke(ctx)
    except Exception:
        logger.exception("Unhandled exception during unblob")
        sys.exit(1)

    sys.exit(exit_code_var.get(0))


if __name__ == "__main__":
    main()
