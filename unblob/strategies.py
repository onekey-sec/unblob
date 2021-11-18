import io
from typing import Callable, List, Optional, Generator
from operator import attrgetter
from pathlib import Path
from structlog import get_logger
from .finder import search_chunks
from .extractor import make_extract_dir, carve_chunk_to_file, extract_with_command
from .models import Chunk, UnknownChunk
from .handlers import _ALL_MODULES_BY_PRIORITY


logger = get_logger()


def search_chunks_by_priority(path: Path, file: io.BufferedReader) -> List[Chunk]:
    all_chunks = []

    for ind, handlers in enumerate(_ALL_MODULES_BY_PRIORITY, start=1):
        logger.info(f"Starting priority level: {ind}")
        yara_results = search_chunks(handlers, path)

        logger.info(f"YARA results: {yara_results}")
        for result in yara_results:
            handler = result.handler
            match = result.match
            logger.info(f"Next match to look at: {match}")
            for offset, identifier, string_data in match.strings:
                file.seek(0)
                chunk = handler.calculate_chunk(file, offset)
                chunk.handler = handler
                if isinstance(chunk, UnknownChunk):
                    # TODO: Log these chunks too, entropy analysis, etc.
                    continue
                logger.info(f"Found chunk: {chunk}")
                all_chunks.append(chunk)

    return all_chunks


def remove_inner_chunks(chunks: List[Chunk]):
    """Remove all chunks from the list which are within another bigger chunks."""
    chunks.sort(key=attrgetter("size"), reverse=True)
    outer_chunks = [chunks[0]]
    for chunk in chunks[1:]:
        if not any(outer.contains(chunk) for outer in outer_chunks):
            outer_chunks.append(chunk)
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
