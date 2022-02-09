import abc
import multiprocessing as mp
import queue
import sys
import threading
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


class _Sentinel:
    pass


_SENTINEL = _Sentinel


def _worker_process(handler, input, output):
    sys.breakpointhook = multiprocessing_breakpoint
    while (args := input.get()) is not _SENTINEL:
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
        self._tid = threading.get_native_id()

    def start(self):
        for p in self._procs:
            p.start()

    def close(self):
        self._clear_input_queue()
        self._request_workers_to_quit()
        self._wait_for_workers_to_quit()

    def _clear_input_queue(self):
        try:
            while True:
                self._input.get_nowait()
        except queue.Empty:
            pass

    def _request_workers_to_quit(self):
        for _ in self._procs:
            self._input.put(_SENTINEL)

    def _wait_for_workers_to_quit(self):
        for p in self._procs:
            p.join()

    def submit(self, args):
        if threading.get_native_id() != self._tid:
            raise RuntimeError(
                "Submit can only be called from the same "
                "thread/process where the pool is created"
            )
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
