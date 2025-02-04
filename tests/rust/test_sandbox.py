import ctypes
import errno
import os
import platform
import threading
from pathlib import Path

import pytest

from unblob._rust.sandbox import AccessFS, SandboxError, restrict_access

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


# In include/uapi/asm-generic/unistd.h:
# #define __NR_landlock_create_ruleset 444
__NR_landlock_create_ruleset = 444
# In include/uapi/linux/landlock.h:
# #define LANDLOCK_CREATE_RULESET_VERSION			(1U << 0)
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0


def landlock_supported() -> int:
    if platform.system() != "Linux":
        return 0

    # https://docs.kernel.org/userspace-api/landlock.html#creating-a-new-ruleset
    libc = ctypes.CDLL(None, use_errno=True)

    max_abi_version = libc.syscall(
        __NR_landlock_create_ruleset,
        None,
        ctypes.c_size_t(0),
        ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION),
    )
    if max_abi_version > 0:
        return max_abi_version

    err = ctypes.get_errno()
    if err in (
        errno.EOPNOTSUPP,  # disabled at boot time
        errno.ENOSYS,  # not implememented
    ):
        return 0

    raise RuntimeError("landlock_create_ruleset failed", err, os.strerror(err))


@pytest.mark.skipif(
    not landlock_supported(), reason="Landlock support is not available on this system"
)
def test_read_sandboxing(request: pytest.FixtureRequest, sandbox_path: Path):  # noqa: C901
    exception = None

    def _run_catching_exceptions(fn):
        def wrapper():
            __tracebackhide__ = True
            nonlocal exception
            try:
                fn()
            except BaseException as exc:
                exception = exc

        return wrapper

    # Sandbox applies to the current thread and future threads spawned
    # from it.
    #
    # Running the test on a new thread keeps the main-thread
    # clean, so sandboxing won't interfere with other tests executed
    # after this one.

    @_run_catching_exceptions
    def _run_in_thread():
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

    t = threading.Thread(target=_run_in_thread)
    t.start()
    t.join()
    __tracebackhide__ = True
    if exception:
        raise exception
