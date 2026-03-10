import multiprocessing
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from textwrap import dedent

import pytest

from unblob import pool as pool_module
from unblob.pool import MultiPool, SinglePool, WorkerDiedError


def test_singlepool():
    results = []
    handled = []

    def _handler(i):
        handled.append(i)
        return i

    def _callback(pool, result):
        results.append(result)
        if result > 0:
            pool.submit(result - 1)

    with SinglePool(handler=_handler, result_callback=_callback) as pool:
        pool.submit(5)
        pool.process_until_done()

    assert handled == [5, 4, 3, 2, 1, 0]
    assert results == [5, 4, 3, 2, 1, 0]


@pytest.mark.parametrize("process_num", [-1, 0])
def test_multipool_dummy_process_num(process_num: int):
    def _dummy(*_args):
        pass

    with pytest.raises(ValueError, match="process_num must be greater than 0"):
        MultiPool(process_num=process_num, handler=_dummy, result_callback=_dummy)


@pytest.mark.parametrize("process_num", range(1, 5))
def test_multipool(process_num: int):
    handled = multiprocessing.Manager().list()
    results = []

    def _handler(i):
        handled.append(i)
        return i

    def _callback(pool, result):
        results.append(result)
        if result > 0:
            pool.submit(result - 1)

    with MultiPool(
        process_num=process_num, handler=_handler, result_callback=_callback
    ) as pool:
        pool.submit(5)
        pool.process_until_done()

    assert list(handled) == [5, 4, 3, 2, 1, 0]
    assert list(results) == [5, 4, 3, 2, 1, 0]


def test_input_cannot_be_submitted_from_worker():
    pool: MultiPool

    def submit_task(_):
        nonlocal pool
        try:
            pool.submit("this should fail")
        except Exception as exc:
            return exc

    def raise_result(_pool, result):
        raise result

    pool = MultiPool(process_num=1, handler=submit_task, result_callback=raise_result)

    with pool:
        pool.submit(1)
        with pytest.raises(RuntimeError, match="can only be called"):
            pool.process_until_done()


@pytest.fixture
def reset_shutdown_event():
    pool_module.shutdown_event.clear()
    yield
    pool_module.shutdown_event.clear()


@pytest.mark.usefixtures("reset_shutdown_event")
def test_multipool_request_shutdown_unblocks_process_until_done():
    def _handler(i):
        time.sleep(0.5)
        return i

    def _callback(_pool, _result):
        pass

    with MultiPool(process_num=1, handler=_handler, result_callback=_callback) as pool:
        pool.submit(1)

        done = threading.Event()

        def run():
            pool.process_until_done()
            done.set()

        t = threading.Thread(target=run)
        t.start()

        pool_module.shutdown_event.set()
        pool.request_shutdown()

        t.join(5)
        assert done.is_set()


@pytest.mark.usefixtures("reset_shutdown_event")
def test_multipool_sigterm_does_not_raise_oserror():
    repo_root = Path(__file__).resolve().parents[1]
    code = dedent(
        """
        import os
        import signal
        import threading
        import time
        import sys

        def _noop(_signum, _frame):
            pass

        signal.signal(signal.SIGTERM, _noop)

        sys.path.insert(0, os.path.abspath("python"))

        from unblob.pool import MultiPool  # noqa: E402

        def _handler(_arg):
            time.sleep(0.5)
            return 1

        def _callback(_pool, _result):
            pass

        with MultiPool(process_num=1, handler=_handler, result_callback=_callback) as pool:
            pool.submit(1)
            done = threading.Event()

            def run():
                pool.process_until_done()
                done.set()

            t = threading.Thread(target=run)
            t.start()
            os.kill(os.getpid(), signal.SIGTERM)
            t.join(5)
            assert done.is_set()

        print("ok")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "OSError: handle is closed" not in result.stderr
    assert "ok" in result.stdout


def test_multipool_raises_when_worker_dies(monkeypatch):
    def kill_worker(_):
        os.kill(os.getpid(), signal.SIGKILL)

    monkeypatch.setattr(MultiPool, "_result_poll_interval", 0.01)

    pool = MultiPool(
        process_num=1,
        handler=kill_worker,
        result_callback=lambda *_args: None,
    )

    with pool:
        pool.submit(1)
        with pytest.raises(WorkerDiedError, match="SIGKILL"):
            pool.process_until_done()
