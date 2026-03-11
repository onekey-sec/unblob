import abc
import contextlib
import multiprocessing as mp
import multiprocessing.connection
import os
import queue
import signal
import sys
import threading
from collections.abc import Callable
from multiprocessing.queues import JoinableQueue, SimpleQueue
from typing import Any

from .logging import multiprocessing_breakpoint

mp.set_start_method("fork")


class PoolBase(abc.ABC):
    @abc.abstractmethod
    def submit(self, args):
        pass

    @abc.abstractmethod
    def process_until_done(self):
        pass

    def start(self):
        pass

    def close(self, *, immediate=False):
        pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, _exc_value, _tb):
        self.close(immediate=exc_type is not None)


class Queue(JoinableQueue):
    def is_empty(self) -> bool:
        """Check if all ``task_done`` has been called for all items.

        Based on ``multiprocessing.JoinableQueue.join``.
        """
        with self._cond:  # type: ignore
            return self._unfinished_tasks._semlock._is_zero()  # type: ignore  # noqa: SLF001


class ResultQueue(SimpleQueue):
    @property
    def reader(self) -> multiprocessing.connection.Connection:
        return self._reader  # type: ignore


class _Sentinel:
    pass


_SENTINEL = _Sentinel


class WorkerDiedError(RuntimeError):
    pass


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
        if process_num <= 0:
            raise ValueError("At process_num must be greater than 0")

        self._running = False
        self._result_callback = result_callback
        self._input = Queue(ctx=mp.get_context())
        self._input.cancel_join_thread()
        self._output = ResultQueue(ctx=mp.get_context())
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

    def _any_worker_exited(self) -> bool:
        sentinels = [p.sentinel for p in self._procs]
        return bool(multiprocessing.connection.wait(sentinels, timeout=0))

    def close(self, *, immediate=False):
        if not self._running:
            return
        self._running = False
        immediate = immediate or self._any_worker_exited()

        if not immediate:
            try:
                self._clear_input_queue()
                self._request_workers_to_quit()
                self._clear_output_queue()
            except BaseException:
                immediate = True

        if immediate:
            self._terminate_workers()

        self._wait_for_workers_to_quit()

    def _terminate_workers(self):
        for proc in self._procs:
            proc.terminate()

        self._input.close()
        self._output.close()

    def _clear_input_queue(self):
        with contextlib.suppress(queue.Empty):
            while True:
                self._input.get_nowait()

    def _request_workers_to_quit(self):
        for proc in self._procs:
            if proc.exitcode is not None:
                continue
            self._input.put(_SENTINEL)
        self._input.close()

    def _clear_output_queue(self):
        alive = {p.sentinel: p for p in self._procs if p.exitcode is None}
        while alive:
            ready = multiprocessing.connection.wait([self._output.reader, *alive])
            for fd in ready:
                alive.pop(fd, None)  # type: ignore[arg-type]
            if self._output.reader in ready:
                self._output.get()

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

    def _check_worker_deaths(self, sentinels, ready):
        for fd in ready:
            if fd not in sentinels:
                continue
            proc = sentinels.pop(fd)
            if proc.exitcode != 0:
                exitcode = proc.exitcode
                if exitcode is not None and exitcode < 0:
                    reason = f"killed by signal {-exitcode}"
                else:
                    reason = f"exited with code {exitcode}"
                raise WorkerDiedError(
                    f"Worker process {proc.pid} exited unexpectedly ({reason})"
                )

    def process_until_done(self):
        sentinels = {p.sentinel: p for p in self._procs}
        with contextlib.suppress(EOFError):
            while not self._input.is_empty():
                ready = multiprocessing.connection.wait(
                    [self._output.reader, *sentinels]
                )
                self._check_worker_deaths(sentinels, ready)
                if self._output.reader in ready:
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


def make_pool(process_num, handler, result_callback) -> SinglePool | MultiPool:
    if process_num == 1:
        return SinglePool(handler=handler, result_callback=result_callback)

    return MultiPool(
        process_num=process_num,
        handler=handler,
        result_callback=result_callback,
    )


def _on_terminate(signum, _frame):
    raise SystemExit(128 + signum)


signal.signal(signal.SIGTERM, _on_terminate)
