from pathlib import Path

import pytest

E2E_DIR = Path(__file__).parent


def pytest_collection_modifyitems(items):
    # imply e2e to all tests under this directory
    for item in items:
        if Path(item.fspath).is_relative_to(E2E_DIR):
            item.add_marker(pytest.mark.e2e)
