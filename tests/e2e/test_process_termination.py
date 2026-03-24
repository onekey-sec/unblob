import contextlib
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pexpect
import psutil
import pytest

from . import mock_handler

PLUGIN_PATH = Path(mock_handler.__file__)

TIMEOUT = 10


@pytest.mark.parametrize(
    "process_num",
    [
        pytest.param(1, id="single-process"),
        pytest.param(2, id="multi-process"),
    ],
)
def test_sigterm_terminates_promptly(input_file, start_unblob, process_num):
    input_file.write_bytes(mock_handler.BLOCKING_MAGIC)

    proc = start_unblob(_start_subprocess, process_num)

    os.kill(proc.pid, signal.SIGTERM)

    assert proc.wait(timeout=TIMEOUT) != 0

    _assert_no_orphans(proc.pid)


def test_sigkill_leaves_no_orphans(input_file, start_unblob):
    input_file.write_bytes(mock_handler.BLOCKING_MAGIC)

    proc = start_unblob(_start_subprocess, 2)

    os.kill(proc.pid, signal.SIGKILL)

    assert proc.wait(timeout=TIMEOUT) != 0

    _assert_no_orphans(proc.pid)


@pytest.mark.parametrize(
    "process_num",
    [
        pytest.param(1, id="single-process"),
        pytest.param(2, id="multi-process"),
    ],
)
def test_sigint_terminates_promptly(input_file, start_unblob, process_num):
    input_file.write_bytes(mock_handler.BLOCKING_MAGIC)

    proc = start_unblob(_start_pexpect, process_num)
    proc.sendintr()

    proc.expect(pexpect.EOF, timeout=TIMEOUT)
    proc.close()
    # Process may exit with non-zero status or be killed by signal
    # (Python re-raises SIGINT with SIG_DFL for proper parent notification)
    assert proc.exitstatus != 0 or proc.signalstatus is not None

    _assert_no_orphans(proc.pid)


@pytest.mark.parametrize(
    "process_num",
    [
        pytest.param(1, id="single-process"),
        pytest.param(2, id="multi-process"),
    ],
)
def test_worker_crash_terminates_main_process(input_file, start_unblob, process_num):
    input_file.write_bytes(mock_handler.TERMINATING_MAGIC)
    proc = start_unblob(_start_subprocess, process_num)
    assert proc.wait(timeout=TIMEOUT) != 0

    _assert_no_orphans(proc.pid)


@pytest.fixture
def input_file(tmp_path):
    return tmp_path / "input.bin"


@pytest.fixture
def extract_dir(tmp_path):
    return tmp_path / "extract"


@pytest.fixture
def start_unblob(input_file, extract_dir):
    def run(runner, process_num):
        cmd = _unblob_command(input_file, extract_dir, process_num)
        proc = runner(cmd)
        _wait_for_ready(extract_dir, proc)
        return proc

    return run


def _unblob_command(input_file, extract_dir, process_num):
    return [
        sys.executable,
        "-m",
        "unblob.cli",
        "-P",
        str(PLUGIN_PATH),
        "-p",
        str(process_num),
        "-e",
        str(extract_dir),
        "-v",
        str(input_file),
    ]


def _start_subprocess(args):
    # we need to start processes in a new session to reliably track all child-processes
    return subprocess.Popen(args, start_new_session=True)


def _start_pexpect(args):
    # pexpect already allocates a new session to child
    return pexpect.spawn(args[0], args[1:])


def _wait_for_ready(extract_dir: Path, proc=None):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if extract_dir.exists() and any(
            extract_dir.rglob(mock_handler.READY_FLAG_NAME)
        ):
            return
        # pexpect allocates a PTY for the child. If nobody reads the master side, the
        # child may block if the write buffer is small.
        if isinstance(proc, pexpect.spawn):
            with contextlib.suppress(pexpect.TIMEOUT, pexpect.EOF):
                proc.read_nonblocking(size=65536, timeout=0)
        time.sleep(0.1)
    pytest.fail(f"Unblob did not become ready in {TIMEOUT}s")


def _assert_no_orphans(sid):
    # we consider a process orphan if it is running in unblob's session
    # so it is either unblob or (transitively) spawned by unblob
    __tracebackhide__ = True
    orphans = []
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        orphans = _processes_in_session(sid)
        if not orphans:
            return
        time.sleep(0.1)
    pytest.fail(f"Orphaned processes with SID {sid}: {orphans}")


def _processes_in_session(sid):
    rv = []
    for proc in psutil.process_iter(["pid"]):
        with contextlib.suppress(ProcessLookupError):  # process may have already exited
            if os.getsid(proc.pid) == sid:
                rv.append(proc)
    return rv
