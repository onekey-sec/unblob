import io
from operator import attrgetter
from pathlib import Path
from typing import Generator, List

from structlog import get_logger

from .extractor import carve_chunk_to_file, extract_with_command, make_extract_dir
from .finder import search_chunks
from .handlers import _ALL_MODULES_BY_PRIORITY
from .logging import format_hex
from .models import Chunk, UnknownChunk

logger = get_logger()


def search_chunks_by_priority(path: Path, file: io.BufferedReader) -> List[Chunk]:
    all_chunks = []

    for priority_level, handlers in enumerate(_ALL_MODULES_BY_PRIORITY, start=1):
        logger.info("Starting priority level", priority_level=priority_level)
        yara_results = search_chunks(handlers, path)

        if yara_results:
            logger.info("Found YARA results", count=len(yara_results))

        for result in yara_results:
            handler = result.handler
            match = result.match
            for offset, identifier, string_data in match.strings:
                file.seek(0)
                logger.info(
                    "Calculating chunk for YARA match",
                    start_offset=format_hex(offset),
                    identifier=identifier,
                )
                chunk = handler.calculate_chunk(file, offset)
                chunk.handler = handler
                log = logger.bind(chunk=chunk, handler=handler.NAME)
                if isinstance(chunk, UnknownChunk):
                    log.info("Found unknown chunk")
                    continue
                log.info("Found valid chunk")
                all_chunks.append(chunk)

    return all_chunks


def remove_inner_chunks(chunks: List[Chunk]):
    """Remove all chunks from the list which are within another bigger chunks."""
    chunks.sort(key=attrgetter("size"), reverse=True)
    outer_chunks = [chunks[0]]
    for chunk in chunks[1:]:
        if not any(outer.contains(chunk) for outer in outer_chunks):
            outer_chunks.append(chunk)
    logger.info("Removed inner chunks", outer_chunk_count=len(outer_chunks))
    return outer_chunks


def extract_with_priority(
    root: Path, path: Path, extract_root: Path
) -> Generator[Path, None, None]:

    with path.open("rb") as file:
        all_chunks = search_chunks_by_priority(path, file)
        if not all_chunks:
            return

        outer_chunks = remove_inner_chunks(all_chunks)
        for chunk in outer_chunks:
            extract_dir = make_extract_dir(root, path, extract_root)
            carved_path = carve_chunk_to_file(extract_dir, file, chunk)
            extracted = extract_with_command(extract_dir, carved_path, chunk.handler)
            yield extracted
