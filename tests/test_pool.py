import multiprocessing
import os
import time

import pytest

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


def test_multipool_worker_death():
    def _die(_):
        os._exit(1)

    def _noop_callback(_pool, _result):
        pass

    with MultiPool(process_num=1, handler=_die, result_callback=_noop_callback) as pool:
        pool.submit("anything")
        with pytest.raises(WorkerDiedError):
            pool.process_until_done()


def test_multipool_worker_death_aborts_other_workers():
    def _handler(action):
        if action == "die":
            os._exit(1)
        time.sleep(100)

    def _noop_callback(_pool, _result):
        pass

    started_at = time.perf_counter()
    with MultiPool(
        process_num=3, handler=_handler, result_callback=_noop_callback
    ) as pool:
        pool.submit("block")
        pool.submit("die")
        pool.submit("block")
        with pytest.raises(WorkerDiedError):
            pool.process_until_done()

    delta = time.perf_counter() - started_at
    # hopefully it works on overloaded systems, still 10 << 100...
    assert delta < 10
