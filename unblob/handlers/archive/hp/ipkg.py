import io
from pathlib import Path
from typing import Optional

from structlog import get_logger

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    snull,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    HexString,
    StructHandler,
    ValidChunk,
)

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct ipkg_file_entry {
        char name[256];
        uint64 offset;
        uint64 size;
        uint32 crc32;
    } ipkg_toc_entry_t;

    typedef struct ipkg_header {
        char magic[4];
        uint16 major;
        uint16 minor;
        uint32 toc_offset;
        uint32 unknown_1;
        uint32 toc_entries;
        uint32 unknown_2[2];
        uint32 always_null;
        char file_version[256];
        char product_name[256];
        char ipkg_name[256];
        char signature[256];
    } ipkg_header_t;
"""


def is_valid_header(header) -> bool:
    if header.toc_offset == 0 or header.toc_entries == 0:
        return False
    try:
        snull(header.ipkg_name).decode("utf-8")
        snull(header.file_version).decode("utf-8")
        snull(header.product_name).decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


class HPIPKGExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        entries = []
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("ipkg_header_t", file, Endian.LITTLE)
            file.seek(header.toc_offset, io.SEEK_SET)
            for _ in range(header.toc_entries):
                entry = self._struct_parser.parse(
                    "ipkg_toc_entry_t", file, Endian.LITTLE
                )
                entry_path = Path(snull(entry.name).decode("utf-8"))
                if entry_path.parent.name:
                    raise InvalidInputFormat("Entry name contains directories.")
                entries.append(
                    (
                        Path(entry_path.name),
                        entry.offset,
                        entry.size,
                    )
                )

            for carve_path, start_offset, size in entries:
                fs.carve(carve_path, file, start_offset, size)

            return ExtractResult(reports=fs.problems)


class HPIPKGHandler(StructHandler):
    NAME = "ipkg"

    PATTERNS = [HexString("69 70 6B 67 01 00 03 00")]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "ipkg_header_t"
    EXTRACTOR = HPIPKGExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.LITTLE)

        if not is_valid_header(header):
            raise InvalidInputFormat("Invalid IPKG header.")

        file.seek(start_offset + header.toc_offset, io.SEEK_SET)
        end_offset = -1
        for _ in range(header.toc_entries):
            entry = self._struct_parser.parse("ipkg_toc_entry_t", file, Endian.LITTLE)
            end_offset = max(end_offset, start_offset + entry.offset + entry.size)

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
