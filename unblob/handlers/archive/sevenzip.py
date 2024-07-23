"""7-zip handlers.

7-zip archive file format SHALL consist of three part.  7-zip archive
file SHALL start with signature header.  The data block SHOULD placed
after the signature header.  The data block is shown as Packed
Streams.  A header database SHOULD be placed after the data block.
The data block MAY be empty when no archived contents exists.  So
Packed Streams is optional.  Since Header database CAN be encoded then
it SHOULD place after data block, that is Packed Streams for Headers.
When Header database is encoded, Header encode Information SHALL
placed instead of Header.

[Signature Header] [Data] [Header Database]

https://fastapi.metacpan.org/source/BJOERN/Compress-Deflate7-1.0/7zip/DOC/7zFormat.txt
"7z uses little endian encoding."

https://py7zr.readthedocs.io/en/latest/archive_format.html
"""

import binascii
from pathlib import Path
from typing import Optional

from structlog import get_logger

from unblob.extractors import Command

from ...extractors.command import MultiFileCommand
from ...file_utils import Endian, InvalidInputFormat, StructParser
from ...models import (
    DirectoryHandler,
    File,
    Glob,
    HexString,
    MultiFile,
    StructHandler,
    ValidChunk,
)

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct sevenzip_header {
        char magic[6];
        uint8 version_maj;
        uint8 version_min;
        uint32 crc;
        uint64 next_header_offset;
        uint64 next_header_size;
        uint32 next_header_crc;
    } sevenzip_header_t;
"""
HEADER_STRUCT = "sevenzip_header_t"
HEADER_SIZE = 6 + 1 + 1 + 4 + 8 + 8 + 4

HEADER_PARSER = StructParser(C_DEFINITIONS)

# StartHeader (next_header_offset, next_header_size, next_header_crc)
START_HEADER_SIZE = 8 + 8 + 4


SEVENZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"


def check_header_crc(header):
    # CRC includes the StartHeader (next_header_offset, next_header_size, next_header_crc)
    # CPP/7zip/Archive/7z/7zOut.cpp COutArchive::WriteStartHeader
    calculated_crc = binascii.crc32(header.dumps()[-START_HEADER_SIZE:])
    if header.crc != calculated_crc:
        raise InvalidInputFormat("Invalid sevenzip header CRC")


def calculate_sevenzip_size(header) -> int:
    return len(header) + header.next_header_offset + header.next_header_size


class SevenZipHandler(StructHandler):
    NAME = "sevenzip"

    PATTERNS = [
        HexString(
            """
            // '7', 'z', 0xBC, 0xAF, 0x27, 0x1C
            37 7A BC AF 27 1C
        """
        )
    ]
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = HEADER_STRUCT
    EXTRACTOR = Command("7z", "x", "-p", "-y", "{inpath}", "-o{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file)

        check_header_crc(header)

        size = calculate_sevenzip_size(header)

        return ValidChunk(start_offset=start_offset, end_offset=start_offset + size)


class MultiVolumeSevenZipHandler(DirectoryHandler):
    NAME = "multi-sevenzip"
    EXTRACTOR = MultiFileCommand("7z", "x", "-p", "-y", "{inpath}", "-o{outdir}")

    PATTERN = Glob("*.7z.001")

    def calculate_multifile(self, file: Path) -> Optional[MultiFile]:
        paths = sorted(
            [p for p in file.parent.glob(f"{file.stem}.*") if p.resolve().exists()]
        )
        if not paths:
            return None

        with file.open("rb") as f:
            header_data = f.read(HEADER_SIZE)

        header = HEADER_PARSER.parse(HEADER_STRUCT, header_data, Endian.LITTLE)
        if header.magic != SEVENZIP_MAGIC:
            return None

        check_header_crc(header)
        size = calculate_sevenzip_size(header)
        logger.debug("Sevenzip header", header=header, size=size, _verbosity=3)

        files_size = sum(path.stat().st_size for path in paths)
        logger.debug(
            "Multi-volume files", paths=paths, files_size=files_size, _verbosity=2
        )
        if files_size != size:
            return None

        return MultiFile(
            name=file.stem,
            paths=paths,
        )
