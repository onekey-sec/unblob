import os
from pathlib import Path
from tarfile import TarFile

from structlog import get_logger

from unblob.extractor import is_safe_path

logger = get_logger()

RUNNING_AS_ROOT = os.getuid() == 0
MAX_PATH_LEN = 255


class SafeTarFile(TarFile):
    def extract(
        self, member, path="", set_attrs=True, *, numeric_owner=False  # noqa: FBT002
    ):
        path_as_path = Path(str(path))
        member_name_path = Path(str(member.name))

        if not member.name:
            logger.warning("File with empty filename in tar archive. Skipping")
            return

        if len(member.name) > MAX_PATH_LEN:
            logger.warning("File with filename too long in tar archive. Skipping")
            return

        if not RUNNING_AS_ROOT and (member.ischr() or member.isblk()):
            logger.warning(
                "missing elevated permissions, skipping block and character device creation",
                path=member_name_path,
            )
            return
        if not is_safe_path(path_as_path, member_name_path):
            logger.warning("traversal attempt", path=member_name_path)
            return

        super().extract(member, path, set_attrs, numeric_owner=numeric_owner)
