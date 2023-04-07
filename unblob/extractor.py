"""File extraction related functions."""
import errno
import os
from pathlib import Path
from typing import Union

from structlog import get_logger

from .file_utils import carve, is_safe_path
from .models import Chunk, File, PaddingChunk, TaskResult, UnknownChunk, ValidChunk
from .report import MaliciousSymlinkRemoved

logger = get_logger()

FILE_PERMISSION_MASK = 0o644
DIR_PERMISSION_MASK = 0o775


def carve_chunk_to_file(carve_path: Path, file: File, chunk: Chunk):
    """Extract valid chunk to a file, which we then pass to another tool to extract it."""
    logger.debug("Carving chunk", path=carve_path)
    carve(carve_path, file, chunk.start_offset, chunk.size)


def fix_permission(path: Path):
    if not path.exists():
        return

    if path.is_symlink():
        return

    mode = path.stat().st_mode

    if path.is_file():
        mode |= FILE_PERMISSION_MASK
    elif path.is_dir():
        mode |= DIR_PERMISSION_MASK

    path.chmod(mode)


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

    raw_target = os.readlink(path)
    if not raw_target:
        logger.error("Symlink with empty target, removing.")
        path.unlink()
        return path

    target = Path(raw_target)

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
    def _fix_extracted_directory(directory: Path):
        if not directory.exists():
            return
        for path in (directory / p for p in os.listdir(directory)):
            try:
                fix_permission(path)
                if path.is_symlink():
                    fix_symlink(path, outdir, task_result)
                    continue
                if path.is_dir():
                    _fix_extracted_directory(path)
            except OSError as e:
                if e.errno == errno.ENAMETOOLONG:
                    continue
                raise e from None

    fix_permission(outdir)
    _fix_extracted_directory(outdir)


def carve_unknown_chunk(
    extract_dir: Path, file: File, chunk: Union[UnknownChunk, PaddingChunk]
) -> Path:
    extension = "unknown"
    if isinstance(chunk, PaddingChunk):
        extension = "padding"

    filename = f"{chunk.start_offset}-{chunk.end_offset}.{extension}"
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
