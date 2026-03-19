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
        pytest.param(
            1, id="single-process", marks=pytest.mark.xfail(reason="does not terminate")
        ),
        pytest.param(
            2,
            id="multi-process",
            marks=pytest.mark.xfail(reason="terminates with exit code 0"),
        ),
    ],
)
def test_sigterm_terminates_promptly(input_file, start_unblob, process_num):
    input_file.write_bytes(mock_handler.BLOCKING_MAGIC)

    proc = start_unblob(_start_subprocess, process_num)

    os.kill(proc.pid, signal.SIGTERM)

    assert proc.wait(timeout=TIMEOUT) != 0

    _assert_no_orphans(proc.pid)


@pytest.mark.parametrize(
    "process_num",
    [
        pytest.param(
            1, id="single-process", marks=pytest.mark.xfail(reason="does not terminate")
        ),
        pytest.param(
            2,
            id="multi-process",
            marks=pytest.mark.xfail(reason="terminates with exit code 0"),
        ),
    ],
)
def test_sigint_terminates_promptly(input_file, start_unblob, process_num):
    input_file.write_bytes(mock_handler.BLOCKING_MAGIC)

    proc = start_unblob(_start_pexpect, process_num)
    proc.sendintr()

    proc.expect(pexpect.EOF, timeout=TIMEOUT)
    proc.close()
    assert proc.exitstatus is not None
    assert proc.exitstatus != 0

    _assert_no_orphans(proc.pid)


@pytest.mark.parametrize(
    "process_num",
    [
        pytest.param(1, id="single-process"),
        pytest.param(
            2, id="multi-process", marks=pytest.mark.xfail(reason="does not terminate")
        ),
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
        _wait_for_ready(extract_dir)
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
    # pexpect alraedy allocates a new session to child
    return pexpect.spawn(args[0], args[1:])


def _wait_for_ready(extract_dir: Path):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if extract_dir.exists() and any(
            extract_dir.rglob(mock_handler.READY_FLAG_NAME)
        ):
            return
        time.sleep(0.1)
    pytest.fail(f"Unblob did not become ready in {TIMEOUT}s")


def _assert_no_orphans(sid):
    # we consider a process orphan it is running in unblob's session
    # so it is either unblob or (transitively) spawned by unblob
    __tracebackhide__ = True
    orphans = _processes_in_session(sid)
    deadline = time.monotonic() + TIMEOUT
    while orphans and time.monotonic() < deadline:
        orphans = []
        for p in orphans:
            if p.is_alive():
                orphans.append(p)
        time.sleep(0.1)
    assert not orphans, f"Orphaned processes with SID {sid}: {orphans}"


def _processes_in_session(sid):
    rv = []
    for proc in psutil.process_iter(["pid"]):
        with contextlib.suppress(ProcessLookupError):  # process may have already exited
            if os.getsid(proc.pid) == sid:
                rv.append(proc)
    return rv
