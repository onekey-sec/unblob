import abc
import atexit
import contextlib
import fcntl
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


def _worker_process(handler, input_, output, lifeline_worker_side, lifeline_host_side):
    # Creates a new process group, making sure no signals are
    # propagated from the main process to the worker processes.
    os.setpgrp()

    # Restore default signal handlers, otherwise workers would inherit
    # them from main process. When used as a library, the hosting app
    # is free to set-up its own signal handlers.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    os.close(  # forked processes inherit open files, we don't need the host FD
        lifeline_host_side
    )

    def _exit_on_parent_death():
        os.read(lifeline_worker_side, 1)
        # We cannot really do anything about this, best to reliably
        # abort the process
        os._exit(1)

    parent_liveness_monitor = threading.Thread(
        target=_exit_on_parent_death, daemon=True
    )
    parent_liveness_monitor.start()

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
        # see search results for "death-pipe" or "forkfd concept"
        (self._lifeline_worker_side, self._lifeline_host_side) = os.pipe()
        fcntl.fcntl(self._lifeline_host_side, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        fcntl.fcntl(self._lifeline_worker_side, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

        self._procs = [
            mp.Process(
                target=_worker_process,
                args=(
                    handler,
                    self._input,
                    self._output,
                    self._lifeline_worker_side,
                    self._lifeline_host_side,
                ),
            )
            for _ in range(process_num)
        ]
        self._tid = threading.get_native_id()

    def start(self):
        self._running = True
        for p in self._procs:
            p.start()
        # We are the host process, we don't need this anymore.
        # Had to keep the file alive until inherited by the forked subprocess
        os.close(self._lifeline_worker_side)
        atexit.register(self._close_immediate)

    def _any_worker_exited(self) -> bool:
        sentinels = [p.sentinel for p in self._procs]
        return bool(multiprocessing.connection.wait(sentinels, timeout=0))

    def close(self, *, immediate=False):
        if not self._running:
            return
        self._running = False
        atexit.unregister(self._close_immediate)
        immediate = immediate or self._any_worker_exited()

        termination_exception = None
        if not immediate:
            try:
                self._clear_input_queue()
                self._request_workers_to_quit()
                self._clear_output_queue()
            except BaseException as exc:
                termination_exception = exc
                immediate = True

        if immediate:
            self._terminate_workers()

        self._wait_for_workers_to_quit()

        # closing this FD any sooner would cause workers to abort
        # immediately, should close only after workers quit
        os.close(self._lifeline_host_side)

        if termination_exception:
            raise termination_exception

    def _close_immediate(self):
        self.close(immediate=True)

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
