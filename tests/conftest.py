from pathlib import Path

import pytest

from unblob.logging import configure_logger


@pytest.fixture(scope="session", autouse=True)
def configure_logging():
    configure_logger(verbose=True, extract_root=Path(""))
