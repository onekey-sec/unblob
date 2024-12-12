"""Handler for gzip compression format.

It is based on standard documented at
https://datatracker.ietf.org/doc/html/rfc1952.

The handler will create valid chunks for each gzip compressed stream
instead of concatenating sequential streams into an overall
ValidChunk.

We monkey patched Python builtin gzip's _GzipReader read() function to
stop reading as soon as it reach the EOF marker of the current gzip
stream.  This is a requirement for unblob given that streams can be
malformed and followed by garbage/random content that triggers
BadGzipFile errors when gzip library tries to read the next stream
header.
"""

import gzip
import io
import struct
import zlib
from pathlib import Path
from typing import Optional

from structlog import get_logger

from unblob.extractors import Command
from unblob.extractors.command import MultiFileCommand
from unblob.models import Extractor

from ...file_utils import InvalidInputFormat
from ...models import (
    DirectoryExtractor,
    DirectoryHandler,
    ExtractResult,
    File,
    Glob,
    Handler,
    HexString,
    MultiFile,
    ValidChunk,
)
from ._gzip_reader import SingleMemberGzipReader

logger = get_logger()

GZIP2_CRC_LEN = 4
GZIP2_SIZE_LEN = 4
GZIP2_FOOTER_LEN = GZIP2_CRC_LEN + GZIP2_SIZE_LEN

FLAG_EXTRA = 4
FLAG_NAME = 8


def get_gzip_embedded_name(path: Path) -> str:
    name = b""
    with path.open("rb") as file:
        # skip magic bytes and method
        file.read(2)
        (_method, flag, _last_mtime) = struct.unpack("<BBIxx", file.read(8))

        if flag & FLAG_EXTRA:
            # Read & discard the extra field, if present
            [extra_len] = struct.unpack("<H", file.read(2))
            file.seek(extra_len, io.SEEK_CUR)

        if flag & FLAG_NAME:
            # Read and discard a null-terminated string containing the filename
            while True:
                s = file.read(1)
                if not s or s == b"\000":
                    break
                name += s

    # return a valid, safe name without directories!
    try:
        return Path(name.decode("utf-8")).name
    except UnicodeDecodeError:
        return ""


class GZIPExtractor(Extractor):
    def get_dependencies(self) -> list[str]:
        return ["7z"]

    def extract(self, inpath: Path, outdir: Path) -> Optional[ExtractResult]:
        name = get_gzip_embedded_name(inpath) or "gzip.uncompressed"
        extractor = Command("7z", "x", "-y", "{inpath}", "-so", stdout=name)
        return extractor.extract(inpath, outdir)


class MultiGZIPExtractor(DirectoryExtractor):
    def get_dependencies(self) -> list[str]:
        return ["7z"]

    def extract(self, paths: list[Path], outdir: Path) -> Optional[ExtractResult]:
        name = get_gzip_embedded_name(paths[0]) or "gzip.uncompressed"
        extractor = MultiFileCommand(
            "7z", "x", "-p", "-y", "{inpath}", "-so", stdout=name
        )
        return extractor.extract(paths, outdir)


class GZIPHandler(Handler):
    NAME = "gzip"

    EXTRACTOR = GZIPExtractor()

    PATTERNS = [
        HexString(
            """
            // ID1
            1F
            // ID2
            8B
            // compression method (0x8 = DEFLATE)
            08
            // flags, 00011111 (0x1f) is the highest since the first 3 bits are reserved
            (
                00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 |
                0A | 0B | 0C | 0D | 0E | 0F | 10 | 11 | 12 | 13 |
                14 | 15 | 16 | 17 | 18 | 19 | 1A | 1B | 1C | 1D | 1E
            )
            // unix time (uint32) + eXtra FLags (2 or 4 per RFC1952 2.3.1)
            // we accept any value because the RFC is not followed by some samples
            [5]
            // Operating System (0-13, or 255 per RFC1952 2.3.1)
            (
                00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 0A | 0B | 0C | 0D | FF
            )
        """
        )
    ]

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        fp = SingleMemberGzipReader(file)
        if not fp.read_header():
            return None

        try:
            fp.read_until_eof()
        except (gzip.BadGzipFile, zlib.error) as e:
            raise InvalidInputFormat from e

        file.seek(GZIP2_FOOTER_LEN - len(fp.unused_data), io.SEEK_CUR)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.tell(),
        )


class MultiVolumeGzipHandler(DirectoryHandler):
    NAME = "multi-gzip"
    EXTRACTOR = MultiGZIPExtractor()

    PATTERN = Glob("*.gz.*")

    def is_valid_gzip(self, path: Path) -> bool:
        try:
            file = File.from_path(path)
        except ValueError:
            return False

        with file as f:
            try:
                fp = SingleMemberGzipReader(f)
                if not fp.read_header():
                    return False
            except gzip.BadGzipFile:
                return False
        return True

    def calculate_multifile(self, file: Path) -> Optional[MultiFile]:
        paths = sorted(
            [p for p in file.parent.glob(f"{file.stem}.*") if p.resolve().exists()]
        )

        # we 'discard' paths that are not the first in the ordered list,
        # otherwise we will end up with colliding reports, one for every
        # path in the list.
        if not paths or file != paths[0]:
            return None

        if self.is_valid_gzip(file):
            files_size = sum(path.stat().st_size for path in paths)
            logger.debug(
                "Multi-volume files", paths=paths, files_size=files_size, _verbosity=2
            )

            return MultiFile(
                name=paths[0].stem,
                paths=paths,
            )
        return None
