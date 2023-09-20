import glob
import shlex
import subprocess
from pathlib import Path

import pytest
from pytest_cov.embed import cleanup_on_sigterm

from unblob.finder import build_hyperscan_database
from unblob.logging import configure_logger
from unblob.models import ProcessResult
from unblob.processing import ExtractionConfig
from unblob.report import ExtractCommandFailedReport


@pytest.fixture(scope="session", autouse=True)
def configure_logging(tmp_path_factory):  # noqa: PT004
    extract_root = tmp_path_factory.mktemp("extract")
    log_path = tmp_path_factory.mktemp("logs") / "unblob.log"
    configure_logger(verbosity_level=3, extract_root=extract_root, log_path=log_path)

    # https://pytest-cov.readthedocs.io/en/latest/subprocess-support.html#if-you-use-multiprocessing-process
    cleanup_on_sigterm()


def gather_integration_tests(test_data_path: Path):
    # Path.glob() trips on some invalid files
    test_input_dirs = [
        Path(p)
        for p in glob.iglob(  # noqa: PTH207
            f"{test_data_path}/**/__input__", recursive=True
        )
    ]
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
        # Special files in test samples follows a strict naming convention
        # so that we can have them without triggering errors on diff.
        # Example diff with special files: https://www.mail-archive.com/bug-diffutils@gnu.org/msg00863.html
        "--exclude",
        "*.socket",
        "--exclude",
        "*.symlink",
        "--exclude",
        "*.fifo",
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
    # filter out error reports about truncated integration test files
    errors = [
        error
        for error in reports.errors
        if not (
            isinstance(error, ExtractCommandFailedReport)
            and error.stderr == b"\nERRORS:\nUnexpected end of archive\n\n"
        )
    ]
    assert errors == [], "Unexpected error reports"
