"""
File extraction related functions.
"""
import io
import os
from pathlib import Path
from typing import List, Tuple

from structlog import get_logger

from .models import Chunk, TaskResult, UnknownChunk, ValidChunk
from .report import MaliciousSymlinkRemoved

logger = get_logger()


APPEND_NAME = "_extract"


def make_extract_dir(root: Path, path: Path, extract_root: Path) -> Path:
    """Create extraction dir under root with the name of path."""
    relative_path = path.relative_to(root)
    extract_name = relative_path.name + APPEND_NAME
    extract_dir = extract_root / relative_path.with_name(extract_name)
    extract_dir.mkdir(parents=True, exist_ok=True)
    logger.debug("Created extraction dir", path=extract_dir)
    return extract_dir.expanduser().resolve()


def carve_chunk_to_file(carve_path: Path, file: io.BufferedIOBase, chunk: Chunk):
    """Extract valid chunk to a file, which we then pass to another tool to extract it."""
    with carve_path.open("wb") as f:
        os.sendfile(f.fileno(), file.fileno(), chunk.start_offset, chunk.size)


def fix_permission(path: Path):
    if path.is_file():
        path.chmod(0o644)
    elif path.is_dir():
        path.chmod(0o775)


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


def fix_symlink(path: Path, outdir: Path, task_result: TaskResult) -> Path:
    """Fix symlinks by rewriting absolute symlinks to make them point within
    the extraction directory (outdir), if it's not a relative symlink it is
    either removed it it attempts to traverse outside of the extraction directory
    or rewritten to be fully portable (no mention of the extraction directory
    in the link value)."""

    if is_recursive_link(path):
        logger.error(f"Symlink loop identified, removing {path}.")
        error_report = MaliciousSymlinkRemoved(
            link=path.as_posix(), target=os.readlink(path)
        )
        task_result.add_report(error_report)
        path.unlink()
        return path

    target = Path(os.readlink(path))

    if target.is_absolute():
        target = Path(target.as_posix().lstrip("/"))
    else:
        target = path.resolve()

    safe = is_safe_path(outdir, target)

    if not safe:
        logger.error(f"Path traversal attempt through symlink, removing {target}.")
        error_report = MaliciousSymlinkRemoved(
            link=path.as_posix(), target=target.as_posix()
        )
        task_result.add_report(error_report)
        path.unlink()
    else:
        relative_target = os.path.relpath(outdir.joinpath(target), start=path.parent)
        path.unlink()
        path.symlink_to(relative_target)
    return path


def fix_extracted_directory(outdir: Path, task_result: TaskResult):
    fix_permission(outdir)
    for path in outdir.rglob("*"):
        if path.is_symlink():
            fix_symlink(path, outdir, task_result)
        else:
            fix_permission(path)


def get_extract_paths(extract_dir: Path, carved_path: Path) -> Tuple[Path, Path]:
    content_dir = extract_dir / (carved_path.name + APPEND_NAME)
    inpath = carved_path.expanduser().resolve()
    outdir = content_dir.expanduser().resolve()
    return inpath, outdir


def carve_unknown_chunks(
    extract_dir: Path, file: io.BufferedIOBase, unknown_chunks: List[UnknownChunk]
) -> List[Path]:
    if not unknown_chunks:
        return []

    carved_paths = []
    logger.warning("Found unknown Chunks", chunks=unknown_chunks)

    for chunk in unknown_chunks:
        filename = f"{chunk.start_offset}-{chunk.end_offset}.unknown"
        carve_path = extract_dir / filename
        logger.info("Extracting unknown chunk", path=carve_path, chunk=chunk)
        carve_chunk_to_file(carve_path, file, chunk)
        carved_paths.append(carve_path)

    return carved_paths


def carve_valid_chunk(
    extract_dir: Path, file: io.BufferedIOBase, chunk: ValidChunk
) -> Path:
    filename = f"{chunk.start_offset}-{chunk.end_offset}.{chunk.handler.NAME}"
    carve_path = extract_dir / filename
    logger.info("Extracting valid chunk", path=carve_path, chunk=chunk)
    carve_chunk_to_file(carve_path, file, chunk)
    return carve_path
