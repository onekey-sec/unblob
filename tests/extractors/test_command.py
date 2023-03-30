from pathlib import Path, PosixPath
from unittest import mock

import pytest

from unblob.extractors import Command
from unblob.extractors.command import InvalidCommandTemplate
from unblob.models import ExtractError
from unblob.report import ExtractCommandFailedReport, ExtractorDependencyNotFoundReport


def test_command_templating():
    command = Command("{outdir}", "{inpath},{outdir}")
    cmdline = command._make_extract_command(  # noqa: SLF001
        Path("inputdir") / "input.file", Path("output")
    )

    assert cmdline == ["output", "inputdir/input.file,output"]


@pytest.mark.parametrize(
    "template",
    [
        "{no_such_placeholder}",
        "{malformed",
    ],
)
def test_command_templating_with_invalid_substitution(template):
    command = Command(template)

    with pytest.raises(InvalidCommandTemplate, match=template):
        command._make_extract_command(Path("input"), Path("output"))  # noqa: SLF001


def test_command_execution(tmpdir: Path):
    outdir = PosixPath(tmpdir)
    command = Command("sh", "-c", "> {outdir}/created")

    command.extract(Path("foo"), outdir)

    assert (outdir / Path("created")).is_file()


def test_command_execution_failure(tmpdir: Path):
    outdir = PosixPath(tmpdir)
    command = Command("sh", "-c", ">&1 echo -n stdout; >&2 echo -n stderr; false")

    with pytest.raises(ExtractError) as excinfo:
        command.extract(Path("input"), outdir)

    assert list(excinfo.value.reports) == [
        ExtractCommandFailedReport(
            command=mock.ANY,
            stdout=b"stdout",
            stderr=b"stderr",
            exit_code=1,
        )
    ]


def test_command_not_found(tmpdir: Path):
    outdir = PosixPath(tmpdir)
    command = Command("this-command-should-not-exist-in-any-system")

    with pytest.raises(ExtractError) as excinfo:
        command.extract(Path("input"), outdir)

    assert list(excinfo.value.reports) == [
        ExtractorDependencyNotFoundReport(
            dependencies=["this-command-should-not-exist-in-any-system"],
        )
    ]
