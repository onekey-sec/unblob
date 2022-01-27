import unittest.mock as mock
from pathlib import Path
from typing import List

import pytest
from click.testing import CliRunner
from conftest import TestHandler

import unblob.cli
from unblob.processing import DEFAULT_DEPTH


class ExistingCommandHandler(TestHandler):
    @staticmethod
    def make_extract_command(*args, **kwargs):
        return ["sh", "something"]


def test_show_external_dependencies_exists(monkeypatch):
    monkeypatch.setattr(
        unblob.cli, "ALL_HANDLERS", [ExistingCommandHandler(), TestHandler()]
    )
    runner = CliRunner()
    result = runner.invoke(unblob.cli.cli, ["--show-external-dependencies"])
    assert result.exit_code == 1
    assert (
        result.output
        == """The following executables found installed, which are needed by unblob:
    sh             ✓
    testcommand    ✗
"""
    )


def test_show_external_dependencies_not_exists(monkeypatch):
    monkeypatch.setattr(
        unblob.cli, "ALL_HANDLERS", [ExistingCommandHandler(), ExistingCommandHandler()]
    )
    runner = CliRunner()
    result = runner.invoke(unblob.cli.cli, ["--show-external-dependencies"])
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
            ["--verbose", "--extract-dir", "unblob", "--depth", "2", "--help", "tests"],
            id="eager_1",
        ),
        pytest.param(
            ["--verbose", "--extract-dir", "unblob", "--depth", "2", "tests", "--help"],
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
        pytest.param(
            ["--verbose", "--extract-dir", "unblob", "--depth", "2"],
            id="verbose+extract-dir+depth",
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
    "params, expected_depth, expected_entropy_depth, expected_verbosity",
    (
        pytest.param([], DEFAULT_DEPTH, 1, False, id="empty"),
        pytest.param(["--verbose"], DEFAULT_DEPTH, 1, True, id="verbose"),
        pytest.param(["--depth", "2"], 2, 1, False, id="depth"),
        pytest.param(["--verbose", "--depth", "2"], 2, 1, True, id="verbose+depth"),
    ),
)
def test_archive_success(
    params,
    expected_depth: int,
    expected_entropy_depth: int,
    expected_verbosity: bool,
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
    process_file_mock = mock.MagicMock()
    logger_config_mock = mock.MagicMock()
    new_params = params + ["--extract-dir", str(tmp_path), str(in_path)]
    with mock.patch.object(
        unblob.cli, "process_file", process_file_mock
    ), mock.patch.object(unblob.cli, "configure_logger", logger_config_mock):
        result = runner.invoke(unblob.cli.cli, new_params)
    assert result.exit_code == 0
    assert "error" not in result.output
    assert "warning" not in result.output
    process_file_mock.assert_called_once_with(
        in_path,
        in_path,
        tmp_path,
        max_depth=expected_depth,
        entropy_depth=expected_entropy_depth,
        verbose=expected_verbosity,
    )
    logger_config_mock.assert_called_once_with(expected_verbosity, tmp_path)


def test_archive_multiple_files(tmp_path: Path):
    runner = CliRunner()
    in_path_1 = (
        Path(__file__).parent
        / "integration"
        / "archive"
        / "zip"
        / "regular"
        / "__input__/"
    )
    in_path_2 = (
        Path(__file__).parent
        / "integration"
        / "archive"
        / "rar"
        / "default"
        / "__input__/"
    )
    process_file_mock = mock.MagicMock()
    with mock.patch.object(unblob.cli, "process_file", process_file_mock):
        result = runner.invoke(
            unblob.cli.cli,
            ["--extract-dir", str(tmp_path), str(in_path_1), str(in_path_2)],
        )
    assert result.exit_code == 0
    assert process_file_mock.call_count == 2
    assert process_file_mock.call_args_list == [
        mock.call(
            in_path_1,
            in_path_1,
            tmp_path,
            max_depth=DEFAULT_DEPTH,
            entropy_depth=1,
            verbose=False,
        ),
        mock.call(
            in_path_2,
            in_path_2,
            tmp_path,
            max_depth=DEFAULT_DEPTH,
            entropy_depth=1,
            verbose=False,
        ),
    ]
