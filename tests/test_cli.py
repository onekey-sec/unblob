import unittest.mock as mock
from pathlib import Path
from typing import List

import pytest
from click.testing import CliRunner
from conftest import TestHandler

import unblob.cli
from unblob.extractors import Command
from unblob.handlers import BUILTIN_HANDLERS
from unblob.processing import DEFAULT_DEPTH, DEFAULT_PROCESS_NUM, ExtractionConfig


class ExistingCommandHandler(TestHandler):
    EXTRACTOR = Command("sh", "something")


def test_show_external_dependencies_exists():
    handlers = (ExistingCommandHandler, TestHandler)
    runner = CliRunner()
    result = runner.invoke(
        unblob.cli.cli, ["--show-external-dependencies"], handlers=handlers
    )
    assert result.exit_code == 1
    assert (
        result.output
        == """The following executables found installed, which are needed by unblob:
    sh             ✓
    testcommand    ✗
"""
    )


def test_show_external_dependencies_not_exists():
    handlers = (ExistingCommandHandler, ExistingCommandHandler)
    runner = CliRunner()
    result = runner.invoke(
        unblob.cli.cli, ["--show-external-dependencies"], handlers=handlers
    )
    assert result.exit_code == 0
    assert (
        result.output
        == """The following executables found installed, which are needed by unblob:
    sh    ✓
"""
    )


@pytest.mark.parametrize(
    "params",
    (
        pytest.param(["--help"], id="alone"),
        pytest.param(
            [
                "--verbose",
                "--extract-dir",
                "unblob",
                "--depth",
                "2",
                "--process-num",
                "2",
                "--help",
                "tests",
            ],
            id="eager_1",
        ),
        pytest.param(
            [
                "--verbose",
                "--extract-dir",
                "unblob",
                "--depth",
                "2",
                "--process-num",
                "2",
                "tests",
                "--help",
            ],
            id="eager_2",
        ),
    ),
)
def test_help(params):
    runner = CliRunner()
    result = runner.invoke(unblob.cli.cli, params)
    assert result.exit_code == 0
    # NOTE: In practice, it writes "Usage: unblob ...", this is done in the `cli.main` with `click.make_context`
    assert result.output.startswith("Usage: cli [OPTIONS] FILES...")


@pytest.mark.parametrize(
    "params",
    (
        pytest.param(["-v"], id="v"),
        pytest.param(["--verbose"], id="verbose"),
        pytest.param(["-e", "unblob"], id="e"),
        pytest.param(["--extract-dir", "unblob"], id="extract-dir"),
        pytest.param(["-d", "2"], id="d"),
        pytest.param(["--depth", "2"], id="depth"),
        pytest.param(["-p", "2"], id="p"),
        pytest.param(["--process-num", "2"], id="process-num"),
        pytest.param(
            [
                "--verbose",
                "--extract-dir",
                "unblob",
                "--depth",
                "2",
                "--process-num",
                "2",
            ],
            id="verbose+extract-dir+depth+process-num",
        ),
    ),
)
def test_without_file(params: List[str]):
    runner = CliRunner()
    result = runner.invoke(unblob.cli.cli, params)
    assert result.exit_code == 2
    assert "Missing argument 'FILES...'" in result.output


def test_non_existing_file(tmp_path: Path):
    runner = CliRunner()
    path = Path("non/existing/path/54")
    result = runner.invoke(unblob.cli.cli, ["--extract-dir", str(tmp_path), str(path)])
    assert result.exit_code == 2
    assert "Invalid value for 'FILES...'" in result.output
    assert f"Path '{str(path)}' does not exist" in result.output


def test_empty_dir_as_file(tmp_path: Path):
    runner = CliRunner()
    out_path = tmp_path.joinpath("out")
    out_path.mkdir()
    in_path = tmp_path.joinpath("in")
    in_path.mkdir()
    result = runner.invoke(
        unblob.cli.cli, ["--extract-dir", str(out_path), str(in_path)]
    )
    assert result.exit_code == 0


@pytest.mark.parametrize(
    "params, expected_depth, expected_entropy_depth, expected_process_num, expected_verbosity",
    (
        pytest.param([], DEFAULT_DEPTH, 1, DEFAULT_PROCESS_NUM, 0, id="empty"),
        pytest.param(
            ["--verbose"], DEFAULT_DEPTH, 1, DEFAULT_PROCESS_NUM, 1, id="verbose-1"
        ),
        pytest.param(["-vv"], DEFAULT_DEPTH, 1, DEFAULT_PROCESS_NUM, 2, id="verbose-2"),
        pytest.param(
            ["-vvv"], DEFAULT_DEPTH, 1, DEFAULT_PROCESS_NUM, 3, id="verbose-3"
        ),
        pytest.param(["--depth", "2"], 2, 1, DEFAULT_PROCESS_NUM, 0, id="depth"),
        pytest.param(["--process-num", "2"], DEFAULT_DEPTH, 1, 2, 0, id="process-num"),
    ),
)
def test_archive_success(
    params,
    expected_depth: int,
    expected_entropy_depth: int,
    expected_process_num: int,
    expected_verbosity: int,
    tmp_path: Path,
):
    runner = CliRunner()
    in_path = (
        Path(__file__).parent
        / "integration"
        / "archive"
        / "zip"
        / "regular"
        / "__input__/"
    )
    process_files_mock = mock.MagicMock()
    logger_config_mock = mock.MagicMock()
    new_params = params + ["--extract-dir", str(tmp_path), str(in_path)]
    with mock.patch.object(
        unblob.cli, "process_files", process_files_mock
    ), mock.patch.object(unblob.cli, "configure_logger", logger_config_mock):
        result = runner.invoke(unblob.cli.cli, new_params)
    assert result.exit_code == 0
    assert "error" not in result.output
    assert "warning" not in result.output
    config = ExtractionConfig(
        extract_root=tmp_path,
        max_depth=expected_depth,
        entropy_depth=expected_entropy_depth,
        entropy_plot=bool(expected_verbosity >= 3),
        process_num=expected_process_num,
        handlers=BUILTIN_HANDLERS,
    )
    process_files_mock.assert_called_once_with(config, in_path)
    logger_config_mock.assert_called_once_with(expected_verbosity, tmp_path)


@pytest.mark.parametrize(
    "args, keep_extracted_chunks, fail_message",
    [
        ([], False, "Should *NOT* have kept extracted chunks"),
        (["-k"], True, "Should have kept extracted chunks"),
        (["--keep-extracted-chunks"], True, "Should have kept extracted chunks"),
    ],
)
def test_keep_extracted_chunks(
    args: List[str], keep_extracted_chunks: bool, fail_message: str, tmp_path: Path
):
    runner = CliRunner()
    in_path = (
        Path(__file__).parent
        / "integration"
        / "archive"
        / "zip"
        / "regular"
        / "__input__/"
    )
    params = args + ["--extract-dir", str(tmp_path), str(in_path)]

    process_files_mock = mock.MagicMock()
    with mock.patch.object(unblob.cli, "process_files", process_files_mock):
        result = runner.invoke(unblob.cli.cli, params)

    assert result.exit_code == 0
    process_files_mock.assert_called_once()
    assert (
        process_files_mock.call_args.args[0].keep_extracted_chunks
        == keep_extracted_chunks
    ), fail_message
