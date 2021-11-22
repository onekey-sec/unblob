"""
Dynamically generate test cases from files in the tests/integration directory.
Directories can be nested arbitrarily.
Each of the test folders should contain 2 things:
- The original file we want to test.
- Input files in the __input__ folder.
- The expected output in the __output__ folder.
"""

import subprocess
from pathlib import Path

import pytest

from unblob.processing import DEFAULT_DEPTH, process_file

TEST_DATA_PATH = Path(__file__).parent / "integration"
TEST_INPUT_DIRS = list(TEST_DATA_PATH.glob("**/__input__"))
TEST_CASE_DIRS = [p.parent for p in TEST_INPUT_DIRS]
TEST_OUTPUT_DIRS = [p / "__output__" for p in TEST_CASE_DIRS]
TEST_IDS = [p.name for p in TEST_CASE_DIRS]


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
        root=input_dir, path=input_dir, extract_root=tmp_path, depth=DEFAULT_DEPTH
    )

    diff_command = ["diff", "-r", "-u", str(output_dir), str(tmp_path)]
    try:
        subprocess.run(diff_command, capture_output=True, check=True, text=True)
    except subprocess.CalledProcessError as exc:
        pytest.fail(exc.stdout)
