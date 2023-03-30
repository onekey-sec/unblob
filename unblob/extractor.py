"""File extraction related functions."""
import os
from pathlib import Path

from structlog import get_logger

from .file_utils import iterate_file
from .models import Chunk, File, TaskResult, UnknownChunk, ValidChunk
from .report import MaliciousSymlinkRemoved

logger = get_logger()


def carve_chunk_to_file(carve_path: Path, file: File, chunk: Chunk):
    """Extract valid chunk to a file, which we then pass to another tool to extract it."""
    carve_path.parent.mkdir(parents=True, exist_ok=True)
    logger.debug("Carving chunk", path=carve_path)

    with carve_path.open("xb") as f:
        for data in iterate_file(file, chunk.start_offset, chunk.size):
            f.write(data)


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
    except RuntimeError:
        return True
    return False


def fix_symlink(path: Path, outdir: Path, task_result: TaskResult) -> Path:
    """Rewrites absolute symlinks to point within the extraction directory (outdir).

    If it's not a relative symlink it is either removed it it attempts
    to traverse outside of the extraction directory or rewritten to be
    fully portable (no mention of the extraction directory in the link
    value).
    """
    if is_recursive_link(path):
        logger.error("Symlink loop identified, removing", path=path)
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
        logger.error("Path traversal attempt through symlink, removing", target=target)
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
