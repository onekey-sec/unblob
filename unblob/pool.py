import abc
import multiprocessing as mp
import sys
from multiprocessing.queues import JoinableQueue
from typing import Any, Callable, Union

from .logging import multiprocessing_breakpoint


class PoolBase(abc.ABC):
    @abc.abstractmethod
    def submit(self, args):
        pass

    @abc.abstractmethod
    def process_until_done(self):
        pass

    def start(self):
        pass

    def close(self):
        pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.close()


class Queue(JoinableQueue):
    def is_empty(self) -> bool:
        """Checks if all ``task_done`` has been called for all items.
        Based on ``multiprocessing.JoinableQueue.join``."""
        with self._cond:  # type: ignore
            return self._unfinished_tasks._semlock._is_zero()  # type: ignore


def _worker_process(handler, input, output):
    sys.breakpointhook = multiprocessing_breakpoint
    while True:
        args = input.get()
        result = handler(args)
        output.put(result)


class MultiPool(PoolBase):
    def __init__(
        self,
        process_num: int,
        handler: Callable[[Any], Any],
        *,
        result_callback: Callable[["MultiPool", Any], Any],
    ):
        if process_num <= 0:
            raise ValueError("At process_num must be greater than 0")

        self._result_callback = result_callback
        self._input = Queue(ctx=mp.get_context())
        self._output = mp.Queue()
        self._procs = [
            mp.Process(
                target=_worker_process,
                args=(handler, self._input, self._output),
            )
            for _ in range(process_num)
        ]

    def start(self):
        for p in self._procs:
            p.start()

    def close(self):
        for p in self._procs:
            p.terminate()
            p.join()

    def submit(self, args):
        self._input.put(args)

    def process_until_done(self):
        while not self._input.is_empty():
            result = self._output.get()
            self._result_callback(self, result)
            self._input.task_done()


class SinglePool(PoolBase):
    def __init__(self, handler, *, result_callback):
        self._handler = handler
        self._result_callback = result_callback

    def submit(self, args):
        result = self._handler(args)
        self._result_callback(self, result)

    def process_until_done(self):
        pass


def make_pool(process_num, handler, result_callback) -> Union[SinglePool, MultiPool]:
    if process_num == 1:
        return SinglePool(handler=handler, result_callback=result_callback)

    return MultiPool(
        process_num=process_num,
        handler=handler,
        result_callback=result_callback,
    )
