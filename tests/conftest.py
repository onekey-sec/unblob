from pathlib import Path

import pytest
from pytest_cov.embed import cleanup_on_sigterm

from unblob.handlers import Handler
from unblob.logging import configure_logger


@pytest.fixture(scope="session", autouse=True)
def configure_logging():
    configure_logger(verbose=True, extract_root=Path(""))

    # https://pytest-cov.readthedocs.io/en/latest/subprocess-support.html#if-you-use-multiprocessing-process
    cleanup_on_sigterm()


class TestHandler(Handler):
    NAME = "test_handler"
    YARA_RULE = r"""
        strings:
            $handler1_magic = { 21 3C }
        condition:
            $handler1_magic
    """

    def calculate_chunk(self, *args, **kwargs):
        pass

    @staticmethod
    def make_extract_command(*args, **kwargs):
        return ["testcommand", "for", "test", "handler"]
