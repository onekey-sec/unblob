import logging
from pathlib import Path

import structlog
from dissect.cstruct import cstruct, dumpstruct


def format_hex(value: int):
    return f"0x{value:x}"


def pretty_print_types(extract_root: Path):
    def convert_type(logger, method_name: str, event_dict: structlog.types.EventDict):
        use_absolute_path = event_dict.pop("_absolute_path", False)
        for key, value in event_dict.items():
            if isinstance(value, Path):
                path = value if use_absolute_path else value.relative_to(extract_root)
                event_dict[key] = str(path)

            elif isinstance(value, cstruct):
                event_dict[key] = dumpstruct(value, output="string")

        return event_dict

    return convert_type


def configure_logger(verbose: bool, extract_root: Path):
    log_level = logging.DEBUG if verbose else logging.INFO
    processors = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(
            key="timestamp", fmt="%Y-%m-%d %H:%M.%S", utc=True
        ),
        pretty_print_types(extract_root),
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
