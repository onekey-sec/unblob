import multiprocessing

import pytest

from unblob.pool import MultiPool, SinglePool


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
    def _dummy(*args):
        pass

    with pytest.raises(ValueError):
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
