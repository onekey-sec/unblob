#!/usr/bin/env python3
import itertools
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import click
from structlog import get_logger

from unblob.plugins import UnblobPluginManager
from unblob.report import Report

from .cli_options import verbosity_option
from .dependencies import get_dependencies, pretty_format_dependencies
from .handlers import BUILTIN_HANDLERS, Handlers
from .logging import configure_logger, noformat
from .processing import DEFAULT_DEPTH, DEFAULT_PROCESS_NUM, process_file

logger = get_logger()


def show_external_dependencies(
    ctx: click.Context, _param: click.Option, value: bool
) -> None:
    if not value or ctx.resilient_parsing:
        return

    plugin_manager = ctx.params["plugin_manager"]
    handlers = ctx.params["handlers"]
    plugins = ctx.params.get(
        "plugins_path"
    )  # may not exist, depends on parameter order...
    handlers = add_handlers_from_plugins(plugin_manager, handlers, plugins)

    dependencies = get_dependencies(handlers)
    text = pretty_format_dependencies(dependencies)
    exit_code = 0 if all(dep.is_installed for dep in dependencies) else 1

    click.echo(text)
    ctx.exit(code=exit_code)


def add_handlers_from_plugins(
    plugin_manager: UnblobPluginManager,
    handlers: Handlers,
    plugin_path: Optional[Path],
):
    if plugin_path:
        plugin_manager.import_path(plugin_path)

    plugin_manager.load_setuptools_entrypoints()

    plugins = [name for name, _plugin in plugin_manager.list_name_plugin()]
    if not plugins:
        return handlers

    logger.info("Loaded plugins", plugins=plugins)

    extra_handlers = list(itertools.chain(*plugin_manager.hook.unblob_register_handlers()))  # type: ignore

    logger.debug("Loaded handlers from plugins", handlers=extra_handlers)

    return handlers.with_prepended(extra_handlers)


def get_help_text():
    dependencies = get_dependencies(BUILTIN_HANDLERS)
    lines = [
        "A tool for getting information out of any kind of binary blob.",
        "",
        "You also need these extractor commands to be able to extract the supported file types:",
        ", ".join(dep.command for dep in dependencies),
        "",
        "NOTE: Some older extractors might not be compatible.",
    ]
    return "\n".join(lines)


class UnblobContext(click.Context):
    def __init__(
        self,
        *args,
        handlers: Optional[Handlers] = None,
        plugin_manager: Optional[UnblobPluginManager] = None,
        **kwargs
    ):
        super().__init__(*args, **kwargs)
        handlers = handlers or BUILTIN_HANDLERS
        plugin_manager = plugin_manager or UnblobPluginManager()

        self.params["handlers"] = handlers
        self.params["plugin_manager"] = plugin_manager


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
@click.option(
    "-P",
    "--plugins-path",
    type=click.Path(path_type=Path, exists=True, resolve_path=True),
    default=None,
    help="Load plugins from the provided path.",
    show_default=True,
)
@click.option(
    "-p",
    "--process-num",
    "process_num",
    type=click.IntRange(1),
    default=DEFAULT_PROCESS_NUM,
    help="Number of worker processes to process files parallelly.",
    show_default=True,
)
@verbosity_option
@click.option(
    "--show-external-dependencies",
    help="Shows commands needs to be available for unblob to work properly",
    is_flag=True,
    callback=show_external_dependencies,
    expose_value=False,
)
def cli(
    files: Tuple[Path],
    extract_root: Path,
    depth: int,
    entropy_depth: int,
    process_num: int,
    verbose: int,
    plugins_path: Optional[Path],
    handlers: Handlers,
    plugin_manager,
) -> List[Report]:
    configure_logger(verbose, extract_root)

    handlers = add_handlers_from_plugins(plugin_manager, handlers, plugins_path)

    logger.info("Start processing files", count=noformat(len(files)))
    all_reports = []
    for path in files:
        report = process_file(
            path,
            extract_root,
            max_depth=depth,
            entropy_depth=entropy_depth,
            entropy_plot=bool(verbose >= 3),
            process_num=process_num,
            handlers=handlers,
        )
        all_reports.extend(report)
    return all_reports


cli.context_class = UnblobContext


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
            reports = cli.invoke(ctx)
    except Exception:
        logger.exception("Unhandled exception during unblob")
        sys.exit(1)

    exit_code = 0 if not reports else 1
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
