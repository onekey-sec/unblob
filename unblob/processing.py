import stat
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
    log = logger.bind(path=path)
    if current_depth >= max_depth:
        log.info("Reached maximum depth, stop further processing")
        return

    log.info("Start processing file")

    statres = path.lstat()
    mode, size = statres.st_mode, statres.st_size

    if stat.S_ISDIR(mode):
        log.info("Found directory")
        for path in path.iterdir():
            process_file(root, path, extract_root, max_depth, current_depth + 1)
        return

    elif stat.S_ISLNK(mode):
        log.info("Ignoring symlink")
        return

    elif size == 0:
        log.info("Ignoring empty file")
        return

    log.info("Calculated file size", size=size)

    for new_path in extract_with_priority(root, path, extract_root, size):
        process_file(extract_root, new_path, extract_root, max_depth, current_depth + 1)
