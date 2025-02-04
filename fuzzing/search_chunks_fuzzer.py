#!/usr/bin/env python3
import logging
import sys
from pathlib import Path

import atheris.import_hook
import atheris.instrument_bytecode
import structlog


def set_unblob_log_level(level=logging.CRITICAL):
    logger = logging.getLogger("unblob")

    def logger_factory():
        return logger

    structlog.configure(logger_factory=logger_factory)
    logger.setLevel(level)


def extract(inpath: Path, outpath: Path):  # noqa: ARG001
    return


with atheris.import_hook.instrument_imports(
    include=["unblob"], exclude=["unblob._rust"]
):
    from unblob.extractors.command import Command
    from unblob.file_utils import File
    from unblob.finder import search_chunks
    from unblob.models import Task, TaskResult
    from unblob.processing import ExtractionConfig

    # NOTE: monkey patch Command extractor so we don't loose time executing subprocesses
    Command.extract = classmethod(extract)  # type: ignore


@atheris.instrument_bytecode.instrument_func
def test_search_chunks(data):
    config = ExtractionConfig(
        extract_root=Path("/dev/shm"),  # noqa: S108
        force_extract=True,
        randomness_depth=0,
        randomness_plot=False,
        skip_magic=[],
        skip_extension=[],
        skip_extraction=False,
        process_num=1,
        keep_extracted_chunks=True,
        verbose=0,
    )

    if not len(data):
        return

    with File.from_bytes(data) as file:
        task = Task(
            path=Path("/dev/shm/nonexistent"),  # noqa: S108
            depth=0,
            blob_id="",
        )
        result = TaskResult(task)
        search_chunks(file, len(data), config.handlers, result)


if __name__ == "__main__":
    set_unblob_log_level()
    atheris.Setup(sys.argv, test_search_chunks)
    atheris.Fuzz()
