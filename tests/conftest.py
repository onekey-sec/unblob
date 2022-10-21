from pathlib import Path

import pytest

from unblob.tasks import Task, TaskResult
from unblob.testing import (  # noqa: F401 (module imported but unused)
    configure_logging,
    extraction_config,
)


@pytest.fixture
def task_result():
    task = Task(path=Path("/nonexistent"), depth=0, chunk_id="")
    return TaskResult(task)
