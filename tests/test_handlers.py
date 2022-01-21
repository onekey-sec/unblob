"""
Dynamically generate test cases from files in the tests/integration directory.
Directories can be nested arbitrarily.
Each of the test folders should contain 2 things:
- The original file we want to test.
- Input files in the __input__ folder.
- The expected output in the __output__ folder.
"""

import inspect
import shlex
import subprocess
from pathlib import Path
from typing import Type

import pytest

from unblob import handlers
from unblob.models import Handler
from unblob.processing import DEFAULT_DEPTH, process_file

TEST_DATA_PATH = Path(__file__).parent / "integration"
TEST_INPUT_DIRS = list(TEST_DATA_PATH.glob("**/__input__"))
TEST_CASE_DIRS = [p.parent for p in TEST_INPUT_DIRS]
TEST_OUTPUT_DIRS = [p / "__output__" for p in TEST_CASE_DIRS]
TEST_IDS = [
    f"{str(p.relative_to(TEST_DATA_PATH)).replace('/', '.')}" for p in TEST_CASE_DIRS
]
HANDLERS_PACKAGE_PATH = Path(handlers.__file__).parent


@pytest.mark.parametrize(
    ("input_dir, output_dir"),
    zip(TEST_INPUT_DIRS, TEST_OUTPUT_DIRS),
    ids=TEST_IDS,
)
def test_all_handlers(input_dir: Path, output_dir: Path, tmp_path: Path):
    assert (
        list(input_dir.iterdir()) != []
    ), f"Integration test input dir should contain at least 1 file: {input_dir}"

    process_file(
        path=input_dir,
        extract_root=tmp_path,
        max_depth=DEFAULT_DEPTH,
        entropy_depth=0,
    )

    diff_command = [
        "diff",
        "--recursive",
        "--unified",
        # Non-unicode files would produce garbage output
        # showing file names which are different should be helpful
        "--brief",
        "--exclude",
        ".gitkeep",
        str(output_dir),
        str(tmp_path),
    ]

    try:
        subprocess.run(diff_command, capture_output=True, check=True, text=True)
    except subprocess.CalledProcessError as exc:
        runnable_diff_command = shlex.join(diff_command)
        pytest.fail(f"\nDiff command: {runnable_diff_command}\n{exc.stdout}\n")


@pytest.mark.parametrize(
    "handler",
    (pytest.param(handler, id=handler.NAME) for handler in handlers.ALL_HANDLERS),
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
