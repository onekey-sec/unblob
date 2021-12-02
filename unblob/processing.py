from pathlib import Path

from structlog import get_logger

from .strategies import extract_with_priority

logger = get_logger()

DEFAULT_DEPTH = 10


def process_file(
    root: Path,
    path: Path,
    extract_root: Path,
    max_depth: int,
    current_depth: int = 0,
):
    is_initial_file = current_depth == 0
    log = logger.bind(path=path)
    log.info("Start processing file", _absolute_path=is_initial_file)

    if current_depth >= max_depth:
        log.info("Reached maximum depth, stop further processing")
        return

    if path.is_dir():
        log.info("Found directory")
        for path in path.iterdir():
            process_file(root, path, extract_root, max_depth, current_depth + 1)
        return

    if path.is_symlink():
        log.info("Ignoring symlink")
        return

    file_size = path.stat().st_size
    if file_size == 0:
        log.info("Ignoring empty file")
        return

    log.info("Calculated file size", size=file_size, _absolute_path=is_initial_file)
    for new_path in extract_with_priority(root, path, extract_root, file_size):
        process_file(extract_root, new_path, extract_root, max_depth, current_depth + 1)
