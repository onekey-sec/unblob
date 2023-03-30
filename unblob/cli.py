#!/usr/bin/env python3
import sys
from pathlib import Path
from typing import Iterable, Optional

import click
from structlog import get_logger

from unblob.models import ProcessResult
from unblob.plugins import UnblobPluginManager
from unblob.report import Severity

from .cli_options import verbosity_option
from .dependencies import get_dependencies, pretty_format_dependencies
from .handlers import BUILTIN_HANDLERS, Handlers
from .logging import configure_logger
from .processing import (
    DEFAULT_DEPTH,
    DEFAULT_PROCESS_NUM,
    DEFAULT_SKIP_MAGIC,
    ExtractionConfig,
    process_file,
)

logger = get_logger()


def show_external_dependencies(
    ctx: click.Context, _param: click.Option, value: bool  # noqa: FBT001
) -> None:
    if not value or ctx.resilient_parsing:
        return

    plugin_manager = ctx.params["plugin_manager"]
    plugins_path = ctx.params.get(
        "plugins_path"
    )  # may not exist, depends on parameter order...
    plugin_manager.import_plugins(plugins_path)
    extra_handlers = plugin_manager.load_handlers_from_plugins()
    handlers = ctx.params["handlers"] + tuple(extra_handlers)

    dependencies = get_dependencies(handlers)
    text = pretty_format_dependencies(dependencies)
    exit_code = 0 if all(dep.is_installed for dep in dependencies) else 1

    click.echo(text)
    ctx.exit(code=exit_code)


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


@click.command(
    help=get_help_text(), context_settings=dict(help_option_names=["--help", "-h"])
)
@click.argument(
    "file",
    type=click.Path(path_type=Path, dir_okay=False, exists=True, resolve_path=True),
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
    "-f",
    "--force",
    is_flag=True,
    show_default=True,
    help="Force extraction even if outputs already exist (they are removed).",
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
    "-S",
    "--skip-magic",
    "skip_magic",
    type=click.STRING,
    default=DEFAULT_SKIP_MAGIC,
    help="Skip processing files with given magic prefix",
    show_default=True,
    multiple=True,
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
@click.option(
    "--report",
    "report_file",
    type=click.Path(path_type=Path),
    help="File to store metadata generated during the extraction process (in JSON format).",
)
@click.option(
    "-s",
    "--skip_extraction",
    "skip_extraction",
    is_flag=True,
    show_default=True,
    help="Only carve chunks and skip further extraction",
)
@click.option(
    "-k",
    "--keep-extracted-chunks",
    "keep_extracted_chunks",
    is_flag=True,
    show_default=True,
    help="Keep extracted chunks",
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
    file: Path,
    extract_root: Path,
    report_file: Optional[Path],
    force: bool,  # noqa: FBT001
    process_num: int,
    depth: int,
    entropy_depth: int,
    skip_magic: Iterable[str],
    skip_extraction: bool,  # noqa: FBT001
    keep_extracted_chunks: bool,  # noqa: FBT001
    handlers: Handlers,
    plugins_path: Optional[Path],
    plugin_manager: UnblobPluginManager,
    verbose: int,
) -> ProcessResult:
    configure_logger(verbose, extract_root)

    plugin_manager.import_plugins(plugins_path)
    extra_handlers = plugin_manager.load_handlers_from_plugins()
    handlers += tuple(extra_handlers)

    config = ExtractionConfig(
        extract_root=extract_root,
        force_extract=force,
        max_depth=depth,
        entropy_depth=entropy_depth,
        entropy_plot=bool(verbose >= 3),
        skip_extraction=skip_extraction,
        skip_magic=skip_magic,
        process_num=process_num,
        handlers=handlers,
        keep_extracted_chunks=keep_extracted_chunks,
    )

    logger.info("Start processing file", file=file)
    return process_file(config, file, report_file)


cli.context_class = UnblobContext


def get_exit_code_from_reports(reports: ProcessResult) -> int:
    severity_to_exit_code = [
        (Severity.ERROR, 1),
        (Severity.WARNING, 0),
    ]
    severities = {error.severity for error in reports.errors}

    for severity, exit_code in severity_to_exit_code:
        if severity in severities:
            return exit_code

    return 0


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

    sys.exit(get_exit_code_from_reports(reports))


if __name__ == "__main__":
    main()
