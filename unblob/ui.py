from typing import Protocol

from rich import progress
from rich.style import Style

from .models import TaskResult


class ProgressReporter(Protocol):
    def __enter__(self):
        ...

    def __exit__(self, _exc_type, _exc_value, _tb):
        ...

    def update(self, result: TaskResult):
        ...


class NullProgressReporter:
    def __enter__(self):
        pass

    def __exit__(self, _exc_type, _exc_value, _tb):
        pass

    def update(self, result: TaskResult):
        pass


class RichConsoleProgressReporter:
    def __init__(self):
        self._progress = progress.Progress(
            progress.TextColumn(
                "Extraction progress: {task.percentage:>3.0f}%",
                style=Style(color="#00FFC8"),
            ),
            progress.BarColumn(
                complete_style=Style(color="#00FFC8"), style=Style(color="#002060")
            ),
        )
        self._overall_progress_task = self._progress.add_task("Extraction progress:")

    def __enter__(self):
        self._progress.start()

    def __exit__(self, _exc_type, _exc_value, _tb):
        self._progress.remove_task(self._overall_progress_task)
        self._progress.stop()

    def update(self, result: TaskResult):
        if (total := self._progress.tasks[0].total) is not None:
            self._progress.update(
                self._overall_progress_task,
                advance=1,
                total=total + len(result.subtasks),
            )
