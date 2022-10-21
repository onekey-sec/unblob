"""
File extraction related functions.
"""
from pathlib import Path

from structlog import get_logger

from .file_utils import iterate_file
from .models import Chunk, File, UnknownChunk, ValidChunk

logger = get_logger()


def carve_chunk_to_file(carve_path: Path, file: File, chunk: Chunk):
    """Extract valid chunk to a file, which we then pass to another tool to extract it."""
    carve_path.parent.mkdir(parents=True, exist_ok=True)
    logger.debug("Carving chunk", path=carve_path)

    with carve_path.open("wb") as f:
        for data in iterate_file(file, chunk.start_offset, chunk.size):
            f.write(data)


def is_safe_path(basedir: Path, path: Path) -> bool:
    try:
        basedir.joinpath(path).resolve().relative_to(basedir.resolve())
    except ValueError:
        return False
    return True


def is_recursive_link(path: Path) -> bool:
    try:
        path.resolve()
        return False
    except RuntimeError:
        return True


def carve_unknown_chunk(extract_dir: Path, file: File, chunk: UnknownChunk) -> Path:
    filename = f"{chunk.start_offset}-{chunk.end_offset}.unknown"
    carve_path = extract_dir / filename
    logger.info("Extracting unknown chunk", path=carve_path, chunk=chunk)
    carve_chunk_to_file(carve_path, file, chunk)
    return carve_path


def carve_valid_chunk(extract_dir: Path, file: File, chunk: ValidChunk) -> Path:
    filename = f"{chunk.start_offset}-{chunk.end_offset}.{chunk.handler.NAME}"
    carve_path = extract_dir / filename
    logger.info("Extracting valid chunk", path=carve_path, chunk=chunk)
    carve_chunk_to_file(carve_path, file, chunk)
    return carve_path
