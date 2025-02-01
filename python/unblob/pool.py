import abc
import contextlib
import multiprocessing as mp
import os
import queue
import signal
import sys
import threading
from multiprocessing.queues import JoinableQueue
from typing import Any, Callable, Union

from .logging import multiprocessing_breakpoint

mp.set_start_method("fork")


class PoolBase(abc.ABC):
    def __init__(self):
        with pools_lock:
            pools.add(self)

    @abc.abstractmethod
    def submit(self, args):
        pass

    @abc.abstractmethod
    def process_until_done(self):
        pass

    def start(self):
        pass

    def close(self, *, immediate=False):  # noqa: ARG002
        with pools_lock:
            pools.remove(self)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, _exc_value, _tb):
        self.close(immediate=exc_type is not None)


pools_lock = threading.Lock()
pools: set[PoolBase] = set()


class Queue(JoinableQueue):
    def is_empty(self) -> bool:
        """Check if all ``task_done`` has been called for all items.

        Based on ``multiprocessing.JoinableQueue.join``.
        """
        with self._cond:  # type: ignore
            return self._unfinished_tasks._semlock._is_zero()  # type: ignore  # noqa: SLF001


class _Sentinel:
    pass


_SENTINEL = _Sentinel


def _worker_process(handler, input_, output):
    # Creates a new process group, making sure no signals are
    # propagated from the main process to the worker processes.
    os.setpgrp()

    # Restore default signal handlers, otherwise workers would inherit
    # them from main process
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    sys.breakpointhook = multiprocessing_breakpoint
    while (args := input_.get()) is not _SENTINEL:
        result = handler(args)
        output.put(result)
    output.put(_SENTINEL)


class MultiPool(PoolBase):
    def __init__(
        self,
        process_num: int,
        handler: Callable[[Any], Any],
        *,
        result_callback: Callable[["MultiPool", Any], Any],
    ):
        super().__init__()
        if process_num <= 0:
            raise ValueError("At process_num must be greater than 0")

        self._running = False
        self._result_callback = result_callback
        self._input = Queue(ctx=mp.get_context())
        self._input.cancel_join_thread()
        self._output = mp.SimpleQueue()
        self._procs = [
            mp.Process(
                target=_worker_process,
                args=(handler, self._input, self._output),
            )
            for _ in range(process_num)
        ]
        self._tid = threading.get_native_id()

    def start(self):
        self._running = True
        for p in self._procs:
            p.start()

    def close(self, *, immediate=False):
        if not self._running:
            return
        self._running = False

        if immediate:
            self._terminate_workers()
        else:
            self._clear_input_queue()
            self._request_workers_to_quit()
            self._clear_output_queue()

        self._wait_for_workers_to_quit()
        super().close(immediate=immediate)

    def _terminate_workers(self):
        for proc in self._procs:
            proc.terminate()

        self._input.close()
        self._output.close()

    def _clear_input_queue(self):
        try:
            while True:
                self._input.get_nowait()
        except queue.Empty:
            pass

    def _request_workers_to_quit(self):
        for _ in self._procs:
            self._input.put(_SENTINEL)
        self._input.close()

    def _clear_output_queue(self):
        process_quit_count = 0
        process_num = len(self._procs)
        while process_quit_count < process_num:
            result = self._output.get()
            if result is _SENTINEL:
                process_quit_count += 1

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
        with contextlib.suppress(EOFError):
            while not self._input.is_empty():
                result = self._output.get()
                self._result_callback(self, result)
                self._input.task_done()


class SinglePool(PoolBase):
    def __init__(self, handler, *, result_callback):
        super().__init__()
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


orig_signal_handlers = {}


def _on_terminate(signum, frame):
    pools_snapshot = list(pools)
    for pool in pools_snapshot:
        pool.close(immediate=True)

    if callable(orig_signal_handlers[signum]):
        orig_signal_handlers[signum](signum, frame)


orig_signal_handlers[signal.SIGTERM] = signal.signal(signal.SIGTERM, _on_terminate)
orig_signal_handlers[signal.SIGINT] = signal.signal(signal.SIGINT, _on_terminate)
