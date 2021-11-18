import structlog
import logging


def configure_logger():
    processors = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(
            key="timestamp", fmt="%Y-%m-%d %H:%M.%S", utc=True
        ),
        structlog.processors.UnicodeDecoder(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.ConsoleRenderer(),
    ]

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
        processors=processors,
        cache_logger_on_first_use=True,
    )
