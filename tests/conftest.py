from pathlib import Path

import pytest

from unblob.models import Task, TaskResult
from unblob.testing import (  # noqa: F401 (module imported but unused)
    configure_logging,
    extraction_config,
)


@pytest.fixture
def task_result():
    task = Task(Path("/nonexistent"), 0)
    return TaskResult(task)
