"""
Dynamically generate test cases from files in the tests/integration directory.
Directories can be nested arbitrarily.
Each of the test folders should contain 2 things:
- The original file we want to test.
- Input files in the __input__ folder.
- The expected output in the __output__ folder.
"""

import hashlib
import inspect
from collections import Counter
from pathlib import Path
from typing import Type

import attr
import pytest

from unblob import handlers
from unblob.models import Handler
from unblob.processing import ExtractionConfig, process_file
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
    for input_file in input_dir.iterdir():
        reports = process_file(extraction_config, input_file)
        check_result(reports)

    check_output_is_the_same(output_dir, extraction_config.extract_root)


BLOCK_SHIFTING_PREFIX = bytes([0]) + b"unique unknown prefix" + bytes([0])
PADDING_CHECK_SUFFIX = bytes([0] * 511) + b"unique unknown suffix" + bytes([0])


@pytest.mark.parametrize(
    "input_dir, output_dir", gather_integration_tests(TEST_DATA_PATH)
)
@pytest.mark.parametrize(
    "prefix, suffix",
    [
        # pytest.param(b"", b"", id="no-extras"),
        pytest.param(BLOCK_SHIFTING_PREFIX, b"", id="block-shifted"),
        pytest.param(b"", PADDING_CHECK_SUFFIX, id="padding-check"),
        pytest.param(
            BLOCK_SHIFTING_PREFIX,
            PADDING_CHECK_SUFFIX,
            id="block-shifted-padding-check",
        ),
    ],
)
def test_all_handlers_chunk_stability(
    input_dir: Path,
    output_dir: Path,
    extraction_config: ExtractionConfig,
    tmp_path: Path,
    prefix: bytes,
    suffix: bytes,
):
    """Test that handlers tolerate a non-empty unknown chunk prefix/suffix"""
    altered_input_file = tmp_path / "input_file"

    for input_file in input_dir.iterdir():
        altered_input_file.write_bytes(prefix + input_file.read_bytes() + suffix)

        config = attr.evolve(
            extraction_config,
            extract_root=extraction_config.extract_root / input_file.name,
        )
        reports = process_file(config, altered_input_file)
        check_result(reports)

        check_output_do_not_change_much_due_to_extras(
            input_file,
            expected=output_dir / (input_file.name + config.extract_suffix),
            actual=config.extract_root,
        )


def hash_bytes(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def hash_dir(root: Path, print=lambda *_: None) -> Counter:
    """Hash all files under an unblob extraction directory :root:, ignoring test prefix/suffix.

    Directory structures having the same set of files will result in the same output,
    even if the file names are different or the directory structure is different.

    Test prefix/suffix is excluded from hash calculation, so that unknown chunks extended
    with them will produce the same hash.

    Returns: count of each hashes found
    """
    hash_counter = Counter()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == ".gitkeep":
            continue

        content = path.read_bytes()
        # ignore newly introduced unknown chunk files
        if content in (BLOCK_SHIFTING_PREFIX, PADDING_CHECK_SUFFIX):
            continue

        # remove extras introduced before hashing
        if content.startswith(BLOCK_SHIFTING_PREFIX):
            content = content[len(BLOCK_SHIFTING_PREFIX) :]
        if content.endswith(PADDING_CHECK_SUFFIX):
            content = content[: -len(PADDING_CHECK_SUFFIX)]

        hash = hash_bytes(content)
        hash_counter[hash] += 1
        # Output for debugging failures
        print(f"    {path} =\n        {hash}")
    return hash_counter


def check_output_do_not_change_much_due_to_extras(
    original_input_file: Path, expected: Path, actual: Path
):
    print(f"{expected=}")
    expected_counts = hash_dir(expected, print=print)
    print(f"{actual=}")
    actual_counts = hash_dir(actual, print=print)

    # original input will show up in the extraction of the modified input due to the extra unknown chunks
    # but it might not show up in the expected output if it was a "whole file chunk"
    hash_original_input = hash_bytes(original_input_file.read_bytes())
    if hash_original_input not in expected_counts:
        print(f"Warn: hash of original input: {hash_original_input} not in expected")
        assert actual_counts[hash_original_input] <= 1
        del actual_counts[hash_original_input]

    assert expected_counts == actual_counts


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
