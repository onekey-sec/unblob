import stat
import statistics
from operator import attrgetter
from pathlib import Path
from typing import List

from structlog import get_logger

from .extractor import carve_unknown_chunks, extract_valid_chunks, make_extract_dir
from .file_utils import iterate_file
from .finder import search_chunks_by_priority
from .iter_utils import pairwise
from .logging import noformat
from .math import shannon_entropy
from .models import UnknownChunk, ValidChunk

logger = get_logger()

DEFAULT_DEPTH = 10


# TODO: this function became too complex when adding entropy calculation, but
# it will be simplified in a separate branch, because the refactor is very complex
def process_file(  # noqa: C901
    root: Path,
    path: Path,
    extract_root: Path,
    max_depth: int,
    entropy_depth: int,
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
            process_file(
                root, path, extract_root, max_depth, entropy_depth, current_depth + 1
            )
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
            # we don't consider whole files as unknown chunks, but we still want to
            # calculate entropy for whole files which produced no valid chunks
            if current_depth < entropy_depth:
                calculate_entropy(path)
            return

        extract_dir = make_extract_dir(root, path, extract_root)

        carved_paths = carve_unknown_chunks(extract_dir, file, unknown_chunks)
        if current_depth < entropy_depth:
            for carved_path in carved_paths:
                calculate_entropy(carved_path)

        for new_path in extract_valid_chunks(extract_dir, file, outer_chunks):
            process_file(
                extract_root,
                new_path,
                extract_root,
                max_depth,
                entropy_depth,
                current_depth + 1,
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


def calculate_entropy(path: Path):
    """Calculate and log shannon entropy divided by 8 for the file in 1mB chunks.

    Shannon entropy returns the amount of information (in bits) of some numeric
    sequence. We calculate the average entropy of byte chunks, which in theory
    can contain 0-8 bits of entropy. We normalize it for visualization to a
    0-100% scale, to make it easier to interpret the graph.
    """
    percentages = []

    # We could use the chunk size instead of another syscall,
    # but we rely on the actual file size written to the disk
    file_size = path.stat().st_size
    logger.info("Calculating entropy for file", path=path, size=file_size)

    # Smaller chuk size would be very slow to calculate. This takes ~ 3sec for a 4,5 GB file.
    buffer_size = 1024 * 1024

    with path.open("rb") as file:
        for chunk in iterate_file(file, 0, file_size, buffer_size=buffer_size):
            entropy = shannon_entropy(chunk)
            entropy_percentage = round(entropy / 8 * 100, 2)
            percentages.append(entropy_percentage)

    logger.info(
        "Entropy calculated",
        mean=round(statistics.mean(percentages), 2),
        highest=max(percentages),
        lowest=min(percentages),
    )
