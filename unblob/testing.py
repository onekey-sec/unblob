import shlex
import subprocess
from pathlib import Path

import pytest
from pytest_cov.embed import cleanup_on_sigterm

from unblob.finder import build_hyperscan_database
from unblob.logging import configure_logger
from unblob.models import ProcessResult
from unblob.processing import ExtractionConfig


@pytest.fixture(scope="session", autouse=True)
def configure_logging():
    configure_logger(verbosity_level=3, extract_root=Path(""))

    # https://pytest-cov.readthedocs.io/en/latest/subprocess-support.html#if-you-use-multiprocessing-process
    cleanup_on_sigterm()


def gather_integration_tests(test_data_path: Path):
    test_input_dirs = list(test_data_path.glob("**/__input__"))
    test_case_dirs = [p.parent for p in test_input_dirs]
    test_output_dirs = [p / "__output__" for p in test_case_dirs]
    test_ids = [
        f"{str(p.relative_to(test_data_path)).replace('/', '.')}"
        for p in test_case_dirs
    ]

    for input_dir, output_dir, test_id in zip(
        test_input_dirs, test_output_dirs, test_ids
    ):
        assert (
            list(input_dir.iterdir()) != []
        ), f"Integration test input dir should contain at least 1 file: {input_dir}"

        yield pytest.param(input_dir, output_dir, id=test_id)


@pytest.fixture
def extraction_config(tmp_path: Path):
    config = ExtractionConfig(
        extract_root=tmp_path,
        entropy_depth=0,
        keep_extracted_chunks=True,
    )

    # Warmup lru_cache before ``process_file`` forks, so child
    # processes can reuse the prebuilt databases without overhead
    build_hyperscan_database(config.handlers)

    return config


def check_output_is_the_same(reference_dir: Path, extract_dir: Path):
    __tracebackhide__ = True

    diff_command = [
        "diff",
        "--recursive",
        "--unified",
        # fix for potential symlinks
        "--no-dereference",
        # Non-unicode files would produce garbage output
        # showing file names which are different should be helpful
        "--brief",
        "--exclude",
        ".gitkeep",
        str(reference_dir),
        str(extract_dir),
    ]

    try:
        subprocess.run(diff_command, capture_output=True, check=True, text=True)
    except subprocess.CalledProcessError as exc:
        runnable_diff_command = shlex.join(diff_command)
        pytest.fail(f"\nDiff command: {runnable_diff_command}\n{exc.stdout}\n")


def check_result(reports: ProcessResult):
    __tracebackhide__ = True

    assert reports.errors == [], "Unexpected error reports"
