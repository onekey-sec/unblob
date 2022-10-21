import os
from pathlib import Path

from structlog import get_logger

from .extractor import is_recursive_link, is_safe_path
from .report import MaliciousSymlinkRemoved
from .tasks import TaskResult

logger = get_logger()


def fix_permission(path: Path):
    if path.is_file():
        path.chmod(0o644)
    elif path.is_dir():
        path.chmod(0o775)


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
