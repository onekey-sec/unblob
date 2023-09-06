import logging
import pdb  # noqa: T100
import sys
from logging.handlers import WatchedFileHandler
from os import getpid
from pathlib import Path
from typing import Any

import structlog
from dissect.cstruct import Instance, dumpstruct


def format_hex(value: int):
    return f"0x{value:x}"


class noformat:  # noqa: N801
    """Keep the value from formatting.

    Even if it would match one of the types in pretty_print_types processor.
    """

    def __init__(self, value):
        self._value = value

    def get(self):
        return self._value

    def __repr__(self) -> str:
        return repr(self._value)


def _format_message(value: Any, extract_root: Path) -> Any:
    if isinstance(value, noformat):
        return value.get()

    if isinstance(value, Path):
        try:
            new_value = value.relative_to(extract_root)
        except ValueError:
            # original files given to unblob may not be relative to extract_root
            new_value = value
        return new_value.as_posix().encode("utf-8", errors="surrogateescape")

    if isinstance(value, Instance):
        return dumpstruct(value, output="string")

    if isinstance(value, int):
        return format_hex(value)

    if isinstance(value, str):
        try:
            value.encode()
        except UnicodeEncodeError:
            return value.encode("utf-8", errors="surrogateescape")

    return value


def pretty_print_types(extract_root: Path):
    def convert_type(_logger, _method_name: str, event_dict: structlog.types.EventDict):
        for key, value in event_dict.items():
            event_dict[key] = _format_message(value, extract_root)

        return event_dict

    return convert_type


def add_pid_to_log_message(
    _logger, _method_name: str, event_dict: structlog.types.EventDict
):
    event_dict["pid"] = getpid()
    return event_dict


def filter_debug_logs(verbosity_level: int):
    def filter_(_logger, _method_name: str, event_dict: structlog.types.EventDict):
        if event_dict["level"] != "debug":
            return event_dict

        message_verbosity: int = event_dict.pop("_verbosity", 1)
        if verbosity_level >= message_verbosity:
            return event_dict

        raise structlog.DropEvent

    return filter_


def configure_logger(verbosity_level: int, extract_root: Path, log_path: Path):
    log_path.unlink(missing_ok=True)

    log_level = logging.DEBUG if verbosity_level > 0 else logging.CRITICAL

    processors = [
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ]

    shared_processors = [
        structlog.stdlib.add_log_level,
        filter_debug_logs(verbosity_level or 2),
        structlog.processors.TimeStamper(
            key="timestamp", fmt="%Y-%m-%d %H:%M.%S", utc=True
        ),
        pretty_print_types(extract_root),
        add_pid_to_log_message,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.StackInfoRenderer(),
    ]

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
        processors=shared_processors + processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(
                colors=sys.stdout.isatty(),
                exception_formatter=structlog.dev.plain_traceback,
            ),
        ],
    )

    file_formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(
                colors=False, exception_formatter=structlog.dev.plain_traceback
            ),
        ],
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)

    file_handler = WatchedFileHandler(log_path.as_posix())
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)

    root_logger = logging.getLogger()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    root_logger.setLevel(logging.DEBUG)
    structlog.get_logger().debug(
        "Logging configured",
        vebosity_level=noformat(verbosity_level),
        extract_root=extract_root.expanduser().resolve(),
    )


class _MultiprocessingPdb(pdb.Pdb):
    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        with Path("/dev/stdin").open() as new_stdin:
            try:
                sys.stdin = new_stdin
                pdb.Pdb.interaction(self, *args, **kwargs)
            finally:
                sys.stdin = _stdin


def multiprocessing_breakpoint():
    """Call this in Process forks instead of the builtin `breakpoint` function for debugging with PDB."""
    return _MultiprocessingPdb().set_trace(frame=sys._getframe(1))  # noqa: SLF001
