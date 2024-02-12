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


def sanitize_symlink_target(base_dir, current_dir, target):
    # Normalize all paths to their absolute forms
    base_dir_abs = os.path.abspath(base_dir)
    current_dir_abs = os.path.abspath(current_dir)
    target_abs = os.path.abspath(os.path.join(current_dir, target)) \
                    if not os.path.isabs(target) else os.path.abspath(target)

    # Check if the target is absolute and within the base_dir
    if os.path.isabs(target):
        if target_abs.startswith(base_dir_abs):
            return os.path.relpath(target_abs, current_dir_abs)
        else:
            # Target is absolute but outside base_dir - we'll pretend base_dir is our root
            # and adjust the target to be within base_dir
            abs = base_dir + "/" + os.path.relpath(target_abs, os.path.commonpath([target_abs, base_dir_abs]))
            # We want to return the relative path from current_dir to the adjusted target
            return os.path.relpath(abs, current_dir_abs)
    else:
        # Target is relative
        if target_abs.startswith(base_dir_abs):
            # Target is relative and does not escape base_dir
            return os.path.relpath(target_abs, current_dir_abs)
        else:
            # Target is relative and escapes base_dir
            # Say we have foo/passwd -> ../../../etc/passwd with root at /host/test_archive
            # from /host/test_archive/foo/passwd, we want to return ../etc/passwd which is the
            # relative path from /host/test_archive/foo to /host/test_archive/etc/passwd
            # without escaping /host/test_archive

            for drop_count in range(0, len(target.split('/'))):
                # We drop '..'s from the target by prepending placeholder directories until we get something valid
                abs = current_dir + "/" + "/".join(["foo"] * drop_count) + target
                resolved = os.path.abspath(abs)
                if resolved.startswith(base_dir_abs):
                    break
            else:
                raise ValueError(f"Could not resolve symlink target {target} within base_dir {base_dir}")

            # We need to add the /placeholder to the relative path because we need
            # to act like a file within base_dir is our root (as opposed to base_dir itself)
            return os.path.relpath(resolved, base_dir_abs + '/placeholder')

def fix_extracted_directory(outdir: Path, task_result: TaskResult):
    def _fix_extracted_directory(directory: Path):
        if not directory.exists():
            return

        base_dir = os.path.abspath(outdir)
        for root, dirs, files in os.walk(base_dir, topdown=True):
            fix_permission(Path(root))
            for name in dirs+files:
                try:
                    full_path = os.path.join(root, name)
                    if os.path.islink(full_path):
                        # Make symlinks relative and constrain them to the base_dir
                        target = os.readlink(full_path)
                        new_target = sanitize_symlink_target(base_dir, root, target)
                        if new_target != target:
                            os.remove(full_path)
                            os.symlink(new_target, full_path)
                            logger.info("Updated symlink", path=full_path, target=new_target)
                        else:
                            logger.debug("Symlink is already sanitized", path=full_path, target=new_target)
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
