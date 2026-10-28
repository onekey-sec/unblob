"""InstallShield cabinet files (data1.hdr / data1.cab), extracted with unshield.

Format: as read by unshield (https://github.com/twogood/unshield, MIT): a
common header, a cabinet descriptor with a file table, and file data. The
file handler takes self-contained cabinets of the version 5 layout (header
version 0x01xxxxxx, major 0 or 5). From version 6 on, the file table is in
data1.hdr and the data in data1.cab ... dataN.cab, so a set (data1.hdr and/or
data1.cab ... dataN.cab in one directory) is taken by the directory handler
and given to unshield whole, whatever its version.
"""

import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from unblob.file_utils import InvalidInputFormat
from unblob.models import (
    DirectoryExtractor,
    DirectoryHandler,
    ExtractError,
    Extractor,
    ExtractResult,
    File,
    Glob,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    MultiFile,
    Reference,
    ValidChunk,
)
from unblob.report import (
    ExtractCommandFailedReport,
    ExtractorDependencyNotFoundReport,
)

COMMON = struct.Struct(
    "<4sIIII"
)  # signature, version, volume info, descriptor offset, size
VOLUME_V5 = struct.Struct(
    "<10I"
)  # data offset, unknown, first/last index, first/last file
FILE_INVALID = 0x8
FD_FLAGS, FD_SIZES, FD_DATA_OFFSET = 8, 10, 0x26  # within a v5 file descriptor


def _unpack(fmt: str | struct.Struct, buf, offset: int) -> tuple:
    layout = fmt if isinstance(fmt, struct.Struct) else struct.Struct(fmt)
    if offset < 0 or offset + layout.size > len(buf):
        raise InvalidInputFormat(
            "InstallShield structure runs past the end of the data"
        )
    return layout.unpack_from(buf, offset)


def major_version(version: int) -> int:
    """Major format version, as unshield derives it (minimum 5)."""
    if version >> 24 == 1:
        major = (version >> 12) & 0xF
    elif version >> 24 in (2, 4):
        major = (version & 0xFFFF) // 100
    else:
        raise InvalidInputFormat(
            f"unknown InstallShield header version 0x{version:08x}"
        )
    return max(major, 5)


def _file_table_end(buf, start: int, descriptor: int) -> int:
    """Furthest data offset + compressed size over the v5 file table."""
    (table_offset,) = _unpack("<I", buf, descriptor + 0x0C)
    (directories,) = _unpack("<I", buf, descriptor + 0x1C)
    (files,) = _unpack("<I", buf, descriptor + 0x28)
    table = descriptor + table_offset
    offsets = _unpack(f"<{directories + files}I", buf, table)
    end = 0
    for entry in offsets[directories:]:
        fd = table + entry
        (flags,) = _unpack("<H", buf, fd + FD_FLAGS)
        _expanded, compressed = _unpack("<II", buf, fd + FD_SIZES)
        (data_offset,) = _unpack("<I", buf, fd + FD_DATA_OFFSET)
        if flags & FILE_INVALID or not data_offset:
            continue
        end = max(end, start + data_offset + compressed)
    return end


def cabinet_end(buf, start: int) -> int:
    """End offset of the self-contained cabinet at start."""
    signature, version, _info, desc_offset, desc_size = _unpack(COMMON, buf, start)
    if signature != b"ISc(":
        raise InvalidInputFormat("no ISc( signature")
    if major_version(version) != 5:
        raise InvalidInputFormat("only the version 5 cabinet layout is handled")
    if desc_size == 0:
        raise InvalidInputFormat("continuation volume without a descriptor")
    end = start + desc_offset + desc_size
    volume = _unpack(VOLUME_V5, buf, start + COMMON.size)
    last_offset, last_compressed = volume[7], volume[9]
    if last_offset:  # a spanned volume records where its data ends
        end = max(end, start + last_offset + last_compressed)
    else:
        end = max(end, _file_table_end(buf, start, start + desc_offset))
    if end > len(buf):
        raise InvalidInputFormat("file data lies beyond the data (a multi-volume set)")
    return end


def run_tool(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    """Run unshield; a missing command is a dependency report."""
    try:
        return subprocess.run(command, capture_output=True, check=False)
    except FileNotFoundError:
        raise ExtractError(
            ExtractorDependencyNotFoundReport(dependencies=[command[0]])
        ) from None


def run_unshield(target: Path, outdir: Path) -> None:
    """Extract with unshield into outdir, only if it succeeds.

    Some cabinets need unshield's old-compression mode (-O); unshield's own
    tests mark the Avigo Manager set so. A failed run (a missing volume,
    say) leaves nothing in outdir.
    """
    result = None
    for options in ([], ["-O"]):
        with tempfile.TemporaryDirectory() as tmp:
            command = ["unshield", *options, "-d", tmp, "x", str(target)]
            result = run_tool(command)
            if result.returncode == 0:
                for item in Path(tmp).iterdir():
                    shutil.move(item, outdir / item.name)
                return
    assert result is not None
    raise ExtractError(
        ExtractCommandFailedReport(
            command=" ".join(result.args),
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.returncode,
        )
    )


class UnshieldExtractor(Extractor):
    def get_dependencies(self) -> list[str]:
        return ["unshield"]

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        # unshield derives sibling volume names from "data1.cab".
        with tempfile.TemporaryDirectory() as tmp:
            cab = Path(tmp) / "data1.cab"
            shutil.copyfile(inpath, cab)
            run_unshield(cab, outdir)
        return ExtractResult(reports=[])


class InstallShieldHandler(Handler):
    NAME = "installshield"
    PATTERNS = [HexString("49 53 63 28")]  # "ISc("
    EXTRACTOR = UnshieldExtractor()
    DOC = HandlerDoc(
        name="InstallShield cabinet",
        description="InstallShield cabinet (data1.cab) holding an installer's files, extracted with unshield.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Flexera (InstallShield)",
        references=[
            Reference(title="unshield", url="https://github.com/twogood/unshield"),
            Reference(
                title="InstallScript .cab and .hdr files",
                url="https://docs.revenera.com/installshield/helplibrary/IsCabViewOverview.htm",
            ),
        ],
        limitations=[
            "Only the version 5 cabinet layout as a single file",
            "Multi-volume sets are taken by installshield_set",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        return ValidChunk(
            start_offset=start_offset, end_offset=cabinet_end(file, start_offset)
        )


def _volume_number(path: Path) -> int | None:
    """N for dataN.cab (any case), else None."""
    name = path.name.lower()
    if name.startswith("data") and name.endswith(".cab") and name[4:-4].isdigit():
        return int(name[4:-4])
    return None


def _is_cabinet(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(4) == b"ISc("


class UnshieldSetExtractor(DirectoryExtractor):
    def get_dependencies(self) -> list[str]:
        return ["unshield"]

    def extract(self, paths: list[Path], outdir: Path) -> ExtractResult | None:
        # unshield finds the volumes by their lower-case names beside data1.
        with tempfile.TemporaryDirectory() as tmp:
            for path in paths:
                shutil.copyfile(path, Path(tmp) / path.name.lower())
            header = Path(tmp) / "data1.hdr"
            run_unshield(header if header.exists() else Path(tmp) / "data1.cab", outdir)
        return ExtractResult(reports=[])


class InstallShieldSetHandler(DirectoryHandler):
    NAME = "installshield_set"
    PATTERN = Glob("[dD][aA][tT][aA]1.[hH][dD][rR]", "[dD][aA][tT][aA]1.[cC][aA][bB]")
    EXTRACTOR = UnshieldSetExtractor()
    DOC = HandlerDoc(
        name="InstallShield multi-volume set",
        description="InstallShield cabinet set: data1.hdr and/or data1.cab ... dataN.cab in one directory, extracted as one set with unshield.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Flexera (InstallShield)",
        references=[
            Reference(title="unshield", url="https://github.com/twogood/unshield"),
        ],
        limitations=["Volumes must be named dataN.cab and numbered without gaps"],
    )

    def calculate_multifile(self, file: Path) -> MultiFile | None:
        siblings = {p.name.lower(): p for p in file.parent.iterdir() if p.is_file()}
        header = siblings.get("data1.hdr")
        if file.name.lower() == "data1.cab" and header is not None:
            return None  # the set starts at data1.hdr
        if not _is_cabinet(file):
            return None
        volumes = []
        for n in range(1, len(siblings) + 1):
            volume = siblings.get(f"data{n}.cab")
            if volume is None or not _is_cabinet(volume):
                break
            volumes.append(volume)
        if header is None and len(volumes) < 2:
            return None
        paths = ([header] if header is not None else []) + volumes
        return MultiFile(name=file.stem, paths=paths)
