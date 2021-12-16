from click.testing import CliRunner
from conftest import TestHandler

import unblob.cli


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
