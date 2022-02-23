from pathlib import Path

import pytest
from pytest_cov.embed import cleanup_on_sigterm

from unblob.extractors import Command
from unblob.logging import configure_logger
from unblob.models import Handler


@pytest.fixture(scope="session", autouse=True)
def configure_logging():
    configure_logger(verbosity_level=3, extract_root=Path(""))

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
    EXTRACTOR = Command("testcommand", "for", "test", "handler")

    def calculate_chunk(self, *args, **kwargs):
        pass
