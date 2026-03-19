import pytest


def pytest_collection_modifyitems(items):
    # imply e2e to all tests under this directory
    for item in items:
        item.add_marker(pytest.mark.e2e)
