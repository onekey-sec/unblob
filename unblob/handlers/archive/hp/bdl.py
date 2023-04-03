import io
from pathlib import Path
from typing import Optional

from dissect.cstruct import Instance
from structlog import get_logger

from unblob.extractor import carve_chunk_to_file
from unblob.file_utils import Endian, File, InvalidInputFormat, StructParser, snull
from unblob.models import Chunk, Extractor, HexString, StructHandler, ValidChunk

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct bdl_toc_entry {
        uint64 offset;
        uint64 size;
    } bdl_toc_entry_t;

    typedef struct bdl_header {
        char magic[4];
        uint16 major;
        uint16 minor;
        uint32 toc_offset;
        char unknown[4];
        uint32 toc_entries;
        uint32 unknowns_2[3];
        char release[256];
        char brand[256];
        char device_id[256];
        char unknown_3[9];
        char version[256];
        char revision[256];
    } bdl_header_t;
"""


def is_valid_header(header: Instance) -> bool:
    if header.toc_offset == 0 or header.toc_entries == 0:
        return False
    try:
        snull(header.release).decode("utf-8")
        snull(header.brand).decode("utf-8")
        snull(header.device_id).decode("utf-8")
        snull(header.version).decode("utf-8")
        snull(header.revision).decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


class HPBDLExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        entries = []
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("bdl_header_t", file, Endian.LITTLE)
            file.seek(header.toc_offset, io.SEEK_SET)
            for i in range(header.toc_entries):
                entry = self._struct_parser.parse(
                    "bdl_toc_entry_t", file, Endian.LITTLE
                )
                entries.append(
                    (
                        outdir.joinpath(outdir.joinpath(Path(f"ipkg{i:03}"))),
                        Chunk(
                            start_offset=entry.offset,
                            end_offset=entry.offset + entry.size,
                        ),
                    )
                )

            for carve_path, chunk in entries:
                carve_chunk_to_file(
                    file=file,
                    chunk=chunk,
                    carve_path=carve_path,
                )


class HPBDLHandler(StructHandler):
    NAME = "bdl"

    PATTERNS = [HexString("69 62 64 6C 01 00 01 00")]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "bdl_header_t"
    EXTRACTOR = HPBDLExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.LITTLE)

        if not is_valid_header(header):
            raise InvalidInputFormat("Invalid BDL header.")

        file.seek(start_offset + header.toc_offset, io.SEEK_SET)
        end_offset = -1
        for _ in range(header.toc_entries):
            entry = self._struct_parser.parse("bdl_toc_entry_t", file, Endian.LITTLE)
            end_offset = max(end_offset, start_offset + entry.offset + entry.size)

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
