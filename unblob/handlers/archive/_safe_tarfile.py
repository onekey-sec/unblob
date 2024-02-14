import os
import tarfile
from pathlib import Path

from structlog import get_logger

from unblob.extractor import is_safe_path
from unblob.report import ExtractionProblem

logger = get_logger()

RUNNING_AS_ROOT = os.getuid() == 0
MAX_PATH_LEN = 255


class SafeTarFile:
    def __init__(self, inpath: Path):
        self.inpath = inpath
        self.reports = []
        self.tarfile = tarfile.open(inpath)
        self.directories = {}

    def close(self):
        self.tarfile.close()

    def extractall(self, extract_root: Path):
        for member in self.tarfile.getmembers():
            try:
                self.extract(member, extract_root)
            except Exception as e:
                self.record_problem(member, str(e), "Ignored.")
        self.fix_directories(extract_root)

    def extract(self, tarinfo: tarfile.TarInfo, extract_root: Path):  # noqa: C901
        if not tarinfo.name:
            self.record_problem(
                tarinfo,
                "File with empty filename in tar archive.",
                "Skipped.",
            )
            return

        if len(tarinfo.name) > MAX_PATH_LEN:
            self.record_problem(
                tarinfo,
                "File with filename too long in tar archive.",
                "Skipped.",
            )
            return

        if not RUNNING_AS_ROOT and (tarinfo.ischr() or tarinfo.isblk()):
            self.record_problem(
                tarinfo,
                "Missing elevated permissions for block and character device creation.",
                "Skipped.",
            )
            return

        # we do want to extract absolute paths, but they must be changed to prevent path traversal
        if Path(tarinfo.name).is_absolute():
            self.record_problem(
                tarinfo,
                "Absolute path.",
                "Converted to extraction relative path.",
            )
            tarinfo.name = f"./{tarinfo.name}"

        # prevent traversal attempts through file name
        if not is_safe_path(basedir=extract_root, path=extract_root / tarinfo.name):
            self.record_problem(
                tarinfo,
                "Traversal attempt.",
                "Skipped.",
            )
            return

        # prevent traversal attempts through links
        if tarinfo.islnk() or tarinfo.issym():
            rel_target = Path(tarinfo.linkname)
            if rel_target.is_absolute():
                # If target is absolute, we'll rewrite to be relative to the symlink

                # Strip leading '/' to make the path relative to extract directory
                rel_target = (extract_root / rel_target.relative_to("/")).relative_to(
                    extract_root
                )

                # Now we need to find the path from the symlink to the target
                # If the symlink is in a directory like /foo/bar and the target is at /target
                # we need to make rel_target ../target (relative to /foo) instead of just being /target (relative to /)

                # Let's calculate depth of the symlink itself and the depth of the target
                symlink_depth = len(tarinfo.name.split("/"))
                target_depth = len(rel_target.parts)

                # If the symlink is deeper than the target, we need to go up by the difference in depth
                if symlink_depth > target_depth:
                    # We need to go up by the difference in depth
                    rel_target = (
                        Path(
                            "/".join(
                                [".." for _ in range(symlink_depth - target_depth)]
                            )
                        )
                        / rel_target
                    )

                self.record_problem(
                    tarinfo,
                    "Absolute path as link target.",
                    "Converted to extraction relative path.",
                )

            # The symlink will point to our relative target (may be updated below if unsafe)
            tarinfo.linkname = rel_target
            logger.info(
                "Link target is relative", linkname=tarinfo.linkname, name=tarinfo.name
            )

            # Resolve the link target to an absolute path
            resolved_path = (extract_root / tarinfo.name).parent / rel_target

            # If the resolved path points outside of extract_root, we need to fix it!
            if not is_safe_path(extract_root, resolved_path):
                logger.warning(
                    "Traversal attempt through link path.",
                    src=tarinfo.name,
                    dest=tarinfo.linkname,
                    basedir=extract_root,
                    resovled_path=resolved_path,
                )

                for drop_count in range(len(str(rel_target).split("/"))):
                    new_path = (
                        (extract_root / tarinfo.name).parent
                        / Path("/".join(["placeholder"] * drop_count))
                        / rel_target
                    )
                    resolved_path = new_path.resolve()
                    if str(resolved_path).startswith(str(extract_root)):
                        break
                else:
                    # We didn't hit the break, we couldn't resolve the path safely
                    self.record_problem(
                        tarinfo,
                        "Traversal attempt through link path.",
                        "Skipped.",
                    )
                    return

                # Double check that it's safe now
                if not is_safe_path(extract_root, resolved_path):
                    self.record_problem(
                        tarinfo,
                        "Traversal attempt through link path.",
                        "Skipped.",
                    )
                    return

                # Prepend placeholder directories before rel_target to get a valid path
                # within extract_root. This is the relative version of resolved_path.
                rel_target = Path("/".join(["placeholder"] * drop_count)) / rel_target
                tarinfo.linkname = rel_target

            logger.debug("Creating symlink", points_to=resolved_path, name=tarinfo.name)

        target_path = extract_root / tarinfo.name
        # directories are special: we can not set their metadata now + they might also be already existing
        if tarinfo.isdir():
            # save (potentially duplicate) dir metadata for applying at the end of the extraction
            self.directories[tarinfo.name] = tarinfo
            target_path.mkdir(parents=True, exist_ok=True)
            return

        if target_path.exists():
            self.record_problem(
                tarinfo,
                "Duplicate tar entry.",
                "Removed older version.",
            )
            target_path.unlink()

        self.tarfile.extract(tarinfo, extract_root)

    def fix_directories(self, extract_root):
        """Complete directory extraction.

        When extracting directories, setting metadata was intentionally skipped,
        so that entries under the directory can be extracted, even if the directory
        is write protected.
        """
        # need to set the permissions from leafs to root
        directories = sorted(
            self.directories.values(), key=lambda d: d.name, reverse=True
        )

        # copied from tarfile.extractall(), it is somewhat ugly, as uses private helpers!
        for tarinfo in directories:
            dirpath = str(extract_root / tarinfo.name)
            try:
                self.tarfile.chown(tarinfo, dirpath, numeric_owner=True)
                self.tarfile.utime(tarinfo, dirpath)
                self.tarfile.chmod(tarinfo, dirpath)
            except tarfile.ExtractError as e:
                self.record_problem(tarinfo, str(e), "Ignored.")

    def record_problem(self, tarinfo, problem, resolution):
        logger.warning(f"{problem} {resolution}", path=tarinfo.name)  # noqa: G004
        self.reports.append(
            ExtractionProblem(
                path=tarinfo.name,
                problem=problem,
                resolution=resolution,
            )
        )
