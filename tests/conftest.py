from pathlib import Path

import pytest

from unblob.models import Task, TaskResult
from unblob.testing import (  # noqa: F401 (module imported but unused)
    configure_logging,
    extraction_config,
)


def pytest_addoption(parser):
    parser.addoption(
        "--with-e2e", action="store_true", default=False, help="run end-to-end tests"
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--with-e2e"):
        return
    skip_e2e = pytest.mark.skip(reason="need --e2e option to run")
    for item in items:
        if item.get_closest_marker("e2e"):
            item.add_marker(skip_e2e)


@pytest.fixture
def task_result():
    task = Task(path=Path("/nonexistent"), depth=0, blob_id="")
    return TaskResult(task=task)
