import io
from pathlib import Path
from typing import Optional

from structlog import get_logger

from unblob.extractor import carve_chunk_to_file
from unblob.file_utils import Endian, File, InvalidInputFormat, StructParser
from unblob.models import Chunk, Extractor, HexString, StructHandler, ValidChunk

logger = get_logger()

C_DEFINITIONS = r"""
    #define FIXED_HEADER_LEN 40
    typedef struct chk_header {
        uint32 magic;           /* "2A 23 24 5E" */
        uint32 header_len;
        uint8  reserved[8];
        uint32 kernel_chksum;
        uint32 rootfs_chksum;
        uint32 kernel_len;
        uint32 rootfs_len;
        uint32 image_chksum;
        uint32 header_chksum;
        char board_id[header_len - FIXED_HEADER_LEN]; /* upto MAX_BOARD_ID_LEN */
    } chk_header_t;
"""


class CHKExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("chk_header_t", file, Endian.BIG)

            file.seek(header.header_len, io.SEEK_SET)

            self._dump_file(file, outdir, Path("kernel"), header.kernel_len)
            self._dump_file(file, outdir, Path("rootfs"), header.rootfs_len)

    def _dump_file(self, file: File, outdir: Path, path: Path, length: int):
        if not length:
            return

        start = file.tell()
        chunk = Chunk(start_offset=start, end_offset=start + length)
        carve_chunk_to_file(outdir.joinpath(path), file, chunk)


class NetgearCHKHandler(StructHandler):
    NAME = "chk"

    PATTERNS = [HexString("2a 23 24 5e")]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "chk_header_t"
    EXTRACTOR = CHKExtractor()

    def is_valid_header(self, header) -> bool:
        if header.header_len != len(header):
            return False
        try:
            header.board_id.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.BIG)

        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid CHK header.")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset
            + header.header_len
            + header.kernel_len
            + header.rootfs_len,
        )
