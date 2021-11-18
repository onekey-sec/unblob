import structlog
import logging
import pathlib


def format_hex(value: int):
    return f"0x{value:x}"


def pretty_print_paths(logger, method_name: str, event_dict: structlog.types.EventDict):
    for key, value in event_dict.items():
        if isinstance(value, pathlib.Path):
            event_dict[key] = str(value)
    return event_dict


def configure_logger(*, verbose: bool):
    log_level = logging.DEBUG if verbose else logging.INFO
    processors = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(
            key="timestamp", fmt="%Y-%m-%d %H:%M.%S", utc=True
        ),
        pretty_print_paths,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.ConsoleRenderer(),
    ]

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        processors=processors,
        cache_logger_on_first_use=True,
    )
