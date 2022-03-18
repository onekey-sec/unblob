from pathlib import Path, PosixPath
from unittest import mock

import pytest

from unblob.extractors import Command
from unblob.extractors.command import InvalidCommandTemplate
from unblob.models import ExtractError, TaskResult
from unblob.report import ExtractCommandFailedReport, ExtractorDependencyNotFoundReport


def test_command_templating():
    command = Command("{infile}", "{outdir}", "{inpath},{outdir}")
    cmdline = command._make_extract_command(
        Path("inputdir") / "input.file", Path("output")
    )

    assert cmdline == ["input", "output", "inputdir/input.file,output"]


@pytest.mark.parametrize(
    "template",
    (
        "{no_such_placeholder}",
        "{malformed",
    ),
)
def test_command_templating_with_invalid_substitution(template):
    command = Command(template)

    with pytest.raises(InvalidCommandTemplate, match=template):
        command._make_extract_command(Path("input"), Path("output"))


def test_command_execution(tmpdir: Path):
    outdir = PosixPath(tmpdir)
    command = Command("sh", "-c", "> {outdir}/created")
    res = TaskResult()
    command.extract(Path("foo"), outdir, res)
    assert (outdir / Path("created")).is_file()

    assert res.reports == []


def test_command_execution_failure(tmpdir: Path):
    outdir = PosixPath(tmpdir)
    command = Command("sh", "-c", ">&1 echo -n stdout; >&2 echo -n stderr; false")

    res = TaskResult()
    with pytest.raises(ExtractError):
        command.extract(Path("input"), outdir, res)
    assert res.reports == [
        ExtractCommandFailedReport(
            handler=None,
            command=mock.ANY,
            stdout=b"stdout",
            stderr=b"stderr",
            exit_code=1,
        )
    ]


def test_command_not_found(tmpdir: Path):
    outdir = PosixPath(tmpdir)
    command = Command("this-command-should-not-exist-in-any-system")

    res = TaskResult()
    with pytest.raises(ExtractError):
        command.extract(Path("input"), outdir, res)
    assert res.reports == [
        ExtractorDependencyNotFoundReport(
            handler=None, dependencies=["this-command-should-not-exist-in-any-system"]
        )
    ]
