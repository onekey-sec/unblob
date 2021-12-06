import stat
from pathlib import Path

from structlog import get_logger

from .extractor import carve_unknown_chunks, extract_valid_chunks, make_extract_dir
from .strategies import (
    calculate_unknown_chunks,
    remove_inner_chunks,
    search_chunks_by_priority,
)

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

    with path.open("rb") as file:
        all_chunks = search_chunks_by_priority(path, file, size)
        outer_chunks = remove_inner_chunks(all_chunks)
        unknown_chunks = calculate_unknown_chunks(outer_chunks, size)
        if not outer_chunks and not unknown_chunks:
            return

        extract_dir = make_extract_dir(root, path, extract_root)
        carve_unknown_chunks(extract_dir, file, unknown_chunks)
        for new_path in extract_valid_chunks(extract_dir, file, outer_chunks):
            process_file(
                extract_root, new_path, extract_root, max_depth, current_depth + 1
            )
