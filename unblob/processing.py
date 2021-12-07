import stat
from operator import attrgetter
from pathlib import Path
from typing import List

from structlog import get_logger

from .extractor import carve_unknown_chunks, extract_valid_chunks, make_extract_dir
from .finder import search_chunks_by_priority
from .iter_utils import pairwise
from .logging import noformat
from .models import UnknownChunk, ValidChunk

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


def remove_inner_chunks(chunks: List[ValidChunk]) -> List[ValidChunk]:
    """Remove all chunks from the list which are within another bigger chunks."""
    if not chunks:
        return []

    chunks_by_size = sorted(chunks, key=attrgetter("size"), reverse=True)
    outer_chunks = [chunks_by_size[0]]
    for chunk in chunks_by_size[1:]:
        if not any(outer.contains(chunk) for outer in outer_chunks):
            outer_chunks.append(chunk)

    outer_count = len(outer_chunks)
    removed_count = len(chunks) - outer_count
    logger.info(
        "Removed inner chunks",
        outer_chunk_count=noformat(outer_count),
        removed_inner_chunk_count=noformat(removed_count),
    )
    return outer_chunks


def calculate_unknown_chunks(
    chunks: List[ValidChunk], file_size: int
) -> List[UnknownChunk]:
    """Calculate the empty gaps between chunks."""
    if not chunks or file_size == 0:
        return []

    sorted_by_offset = sorted(chunks, key=attrgetter("start_offset"))

    unknown_chunks = []

    first = sorted_by_offset[0]
    if first.start_offset != 0:
        unknown_chunk = UnknownChunk(0, first.start_offset)
        unknown_chunks.append(unknown_chunk)

    for chunk, next_chunk in pairwise(sorted_by_offset):
        diff = next_chunk.start_offset - chunk.end_offset
        if diff != 0:
            unknown_chunk = UnknownChunk(
                start_offset=chunk.end_offset,
                end_offset=next_chunk.start_offset,
            )
            unknown_chunks.append(unknown_chunk)

    last = sorted_by_offset[-1]
    if last.end_offset < file_size:
        unknown_chunk = UnknownChunk(
            start_offset=last.end_offset,
            end_offset=file_size,
        )
        unknown_chunks.append(unknown_chunk)

    return unknown_chunks
