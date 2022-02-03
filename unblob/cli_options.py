import functools

import click


def verbosity_option(func):
    @click.option(
        "-v", "--verbose", is_flag=True, help="Verbose mode, enable debug logs."
    )
    @functools.wraps(func)
    def decorator(*args, **kwargs):
        return func(*args, **kwargs)

    return decorator
