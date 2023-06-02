import platform
from pathlib import Path

import pytest

from unblob_native.sandbox import AccessFS, SandboxError, restrict_access

FILE_CONTENT = b"HELLO"


@pytest.mark.skipif(platform.system() == "Linux", reason="Linux is supported.")
def test_unsupported_platform():
    with pytest.raises(SandboxError):
        restrict_access(AccessFS.read("/"))


@pytest.fixture(scope="session")
def sandbox_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    sandbox_path = tmp_path_factory.mktemp("sandbox")

    file_path = sandbox_path / "file.txt"
    dir_path = sandbox_path / "dir"
    link_path = sandbox_path / "link"

    with file_path.open("wb") as f:
        assert f.write(FILE_CONTENT) == len(FILE_CONTENT)

    dir_path.mkdir()
    link_path.symlink_to(file_path)

    return sandbox_path


@pytest.mark.skipif(
    platform.system() != "Linux" or platform.machine() != "x86_64",
    reason="Only supported on Linux x86-64.",
)
def test_read_sandboxing(request: pytest.FixtureRequest, sandbox_path: Path):
    restrict_access(
        AccessFS.read("/"),
        AccessFS.read(sandbox_path),
        # allow pytest caching, coverage, etc...
        AccessFS.read_write(request.config.rootpath),
    )

    with pytest.raises(PermissionError):
        (sandbox_path / "some-dir").mkdir()

    with pytest.raises(PermissionError):
        (sandbox_path / "some-file").touch()

    with pytest.raises(PermissionError):
        (sandbox_path / "some-link").symlink_to("file.txt")

    for path in sandbox_path.rglob("**/*"):
        if path.is_file() or path.is_symlink():
            with path.open("rb") as f:
                assert f.read() == FILE_CONTENT
            with pytest.raises(PermissionError):
                assert path.open("r+")
            with pytest.raises(PermissionError):
                assert path.unlink()
        elif path.is_dir():
            with pytest.raises(PermissionError):
                path.rmdir()
