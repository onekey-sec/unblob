from pathlib import Path

import pytest

from unblob.extractors import Command
from unblob.models import Handler, HexString, Task, TaskResult
from unblob.testing import (  # noqa: F401 (module imported but unused)
    configure_logging,
    extraction_config,
)


class TestHandler(Handler):
    NAME = "test_handler"
    PATTERNS = [HexString("21 3C")]
    EXTRACTOR = Command("testcommand", "for", "test", "handler")

    def calculate_chunk(self, *args, **kwargs):
        pass


@pytest.fixture
def task_result():
    task = Task(Path("/nonexistent"), 0)
    return TaskResult(task)
