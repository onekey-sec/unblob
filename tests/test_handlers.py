"""
Dynamically generate test cases from files in the tests/integration directory.
Directories can be nested arbitrarily.
Each of the test folders should contain 2 things:
- The original file we want to test.
- Input files in the __input__ folder.
- The expected output in the __output__ folder.
"""

import inspect
from pathlib import Path
from typing import Type

import pytest

from unblob import handlers
from unblob.models import Handler
from unblob.processing import ExtractionConfig, process_files
from unblob.testing import (
    check_output_is_the_same,
    check_result,
    gather_integration_tests,
)

TEST_DATA_PATH = Path(__file__).parent / "integration"
HANDLERS_PACKAGE_PATH = Path(handlers.__file__).parent


@pytest.mark.parametrize(
    "input_dir, output_dir", gather_integration_tests(TEST_DATA_PATH)
)
def test_all_handlers(
    input_dir: Path, output_dir: Path, extraction_config: ExtractionConfig
):
    all_reports = process_files(extraction_config, input_dir)

    check_output_is_the_same(output_dir, extraction_config.extract_root)
    check_result(all_reports)


@pytest.mark.parametrize(
    "handler",
    (pytest.param(handler, id=handler.NAME) for handler in handlers.BUILTIN_HANDLERS),
)
def test_missing_handlers_integrations_tests(handler: Type[Handler]):
    handler_module_path = Path(inspect.getfile(handler))
    handler_test_path = handler_module_path.relative_to(
        HANDLERS_PACKAGE_PATH
    ).with_suffix("")

    if handler.NAME == handler_test_path.name:
        # when there is 1 handler class in the handler module, with the same NAME as the module
        expected_test_path = handler_test_path
    else:
        expected_test_path = handler_test_path.joinpath(handler.NAME)

    test_path = TEST_DATA_PATH.joinpath(expected_test_path)
    if not test_path.exists():
        pytest.fail(
            f"Missing test for handler: {handler.NAME}. Searched in: {test_path}"
        )
