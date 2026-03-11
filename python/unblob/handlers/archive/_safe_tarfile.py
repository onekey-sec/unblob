import os
import tarfile
from pathlib import Path
from typing import Literal

from structlog import get_logger

from unblob.file_utils import is_safe_path
from unblob.report import ExtractionProblem

logger = get_logger()

RUNNING_AS_ROOT = os.getuid() == 0
MAX_PATH_LEN = 255


class UnblobTarInfo(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buf, encoding, errors):  # noqa: C901
        """Parse GNU headers without treating the prefix field as a pathname."""
        if len(buf) == 0:
            raise tarfile.EmptyHeaderError("empty header")  # pyright: ignore[reportAttributeAccessIssue]
        if len(buf) != tarfile.BLOCKSIZE:
            raise tarfile.TruncatedHeaderError("truncated header")  # pyright: ignore[reportAttributeAccessIssue]
        if buf.count(tarfile.NUL) == tarfile.BLOCKSIZE:
            raise tarfile.EOFHeaderError("end of file header")  # pyright: ignore[reportAttributeAccessIssue]

        chksum = tarfile.nti(buf[148:156])  # pyright: ignore[reportAttributeAccessIssue]
        if chksum not in tarfile.calc_chksums(buf):  # pyright: ignore[reportAttributeAccessIssue]
            raise tarfile.InvalidHeaderError("bad checksum")  # pyright: ignore[reportAttributeAccessIssue]

        obj = cls()
        obj.name = tarfile.nts(buf[0:100], encoding, errors)  # pyright: ignore[reportAttributeAccessIssue]
        obj.mode = tarfile.nti(buf[100:108])  # pyright: ignore[reportAttributeAccessIssue]
        obj.uid = tarfile.nti(buf[108:116])  # pyright: ignore[reportAttributeAccessIssue]
        obj.gid = tarfile.nti(buf[116:124])  # pyright: ignore[reportAttributeAccessIssue]
        obj.size = tarfile.nti(buf[124:136])  # pyright: ignore[reportAttributeAccessIssue]
        obj.mtime = tarfile.nti(buf[136:148])  # pyright: ignore[reportAttributeAccessIssue]
        obj.chksum = chksum
        obj.type = bytes(buf[156:157])
        obj.linkname = tarfile.nts(buf[157:257], encoding, errors)  # pyright: ignore[reportAttributeAccessIssue]
        obj.uname = tarfile.nts(buf[265:297], encoding, errors)  # pyright: ignore[reportAttributeAccessIssue]
        obj.gname = tarfile.nts(buf[297:329], encoding, errors)  # pyright: ignore[reportAttributeAccessIssue]
        obj.devmajor = tarfile.nti(buf[329:337])  # pyright: ignore[reportAttributeAccessIssue]
        obj.devminor = tarfile.nti(buf[337:345])  # pyright: ignore[reportAttributeAccessIssue]
        prefix = tarfile.nts(buf[345:500], encoding, errors)  # pyright: ignore[reportAttributeAccessIssue]
        magic = buf[257:265]

        if obj.type == tarfile.AREGTYPE and obj.name.endswith("/"):
            obj.type = tarfile.DIRTYPE

        if obj.type == tarfile.GNUTYPE_SPARSE:
            pos = 386
            structs = []
            for _ in range(4):
                try:
                    offset = tarfile.nti(buf[pos : pos + 12])  # pyright: ignore[reportAttributeAccessIssue]
                    numbytes = tarfile.nti(buf[pos + 12 : pos + 24])  # pyright: ignore[reportAttributeAccessIssue]
                except ValueError:
                    break
                structs.append((offset, numbytes))
                pos += 24
            isextended = bool(buf[482])
            origsize = tarfile.nti(buf[483:495])  # pyright: ignore[reportAttributeAccessIssue]
            obj._sparse_structs = (structs, isextended, origsize)

        if obj.isdir():
            obj.name = obj.name.rstrip("/")

        if (
            prefix
            and magic == tarfile.POSIX_MAGIC
            and obj.type not in tarfile.GNU_TYPES
        ):
            obj.name = prefix + "/" + obj.name
        return obj


def open_safe_tarfile(
    name=None,
    mode: Literal["r", "r:*", "r:", "r:gz", "r:bz2", "r:xz"] = "r",
    fileobj=None,
    **kwargs,
) -> tarfile.TarFile:
    return tarfile.open(  # pyright: ignore[reportCallIssue]
        name=name,
        mode=mode,
        fileobj=fileobj,
        tarinfo=UnblobTarInfo,
        **kwargs,
    )


class SafeTarFile:
    def __init__(self, inpath: Path):
        self.inpath = inpath
        self.reports = []
        self.tarfile = open_safe_tarfile(inpath)
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
            tarinfo.name = str(Path(tarinfo.name).relative_to("/"))

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
            if Path(tarinfo.linkname).is_absolute():

                def calculate_linkname():
                    root = extract_root.resolve()
                    path = (extract_root / tarinfo.name).resolve()

                    if path.parts[: len(root.parts)] != root.parts:
                        return None

                    depth = max(0, len(path.parts) - len(root.parts) - 1)
                    return ("/".join([".."] * depth) or ".") + tarinfo.linkname

                relative_linkname = calculate_linkname()
                if relative_linkname is None:
                    self.record_problem(
                        tarinfo,
                        "Absolute path conversion to extraction relative failed - would escape root.",
                        "Skipped.",
                    )
                    return

                assert not Path(relative_linkname).is_absolute()
                self.record_problem(
                    tarinfo,
                    "Absolute path as link target.",
                    "Converted to extraction relative path.",
                )
                tarinfo.linkname = relative_linkname

            resolved_path = (extract_root / tarinfo.name).parent / tarinfo.linkname
            if not is_safe_path(basedir=extract_root, path=resolved_path):
                self.record_problem(
                    tarinfo,
                    "Traversal attempt through link path.",
                    "Skipped.",
                )
                return

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
