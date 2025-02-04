import functools

import click


def verbosity_option(func):
    @click.option(
        "-v",
        "--verbose",
        count=True,
        help="Verbosity level, counting, maximum level: 3 (use: -v, -vv, -vvv)",
    )
    @functools.wraps(func)
    def decorator(*args, **kwargs):
        return func(*args, **kwargs)

    return decorator
