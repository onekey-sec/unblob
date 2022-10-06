import io
from pathlib import Path
from typing import Optional

from structlog import get_logger

from unblob.extractor import carve_chunk_to_file
from unblob.file_utils import Endian, File, StructParser
from unblob.models import Chunk, Extractor, HexString, StructHandler, ValidChunk

logger = get_logger()

TRX_HEADER = r"""
    typedef struct trx_header {
        uint32 magic;              /* "HDR0" */
        uint32 len;                /* Length of file including header */
        uint32 crc32;              /* 32-bit CRC from flag_version to end of file */
        uint32 flag_version;       /* 0:15 flags, 16:31 version */
        uint32 offsets[3]; /* Offsets of partitions from start of header */
    } trx_header_t;
"""


CHK_HEADER = r"""
        typedef struct chk_header {
            uint32 magic;
            uint32 header_len;
            uint8  reserved[8];
            uint32 kernel_chksum;
            uint32 rootfs_chksum;
            uint32 kernel_len;
            uint32 rootfs_len;
            uint32 image_chksum;
            uint32 header_chksum;
            /* char board_id[] - upto MAX_BOARD_ID_LEN */
        } chk_header_t;
    """


class CHKExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(CHK_HEADER)

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


class TRXExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(TRX_HEADER)

    def extract(self, inpath: Path, outdir: Path):
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("trx_header_t", file, Endian.LITTLE)
            file.seek(0, io.SEEK_END)
            eof = file.tell()

            self._dump_file(
                file, outdir, Path("part0"), header.offsets[0], header.offsets[1], eof
            )
            self._dump_file(
                file, outdir, Path("part1"), header.offsets[1], header.offsets[2], eof
            )
            self._dump_file(file, outdir, Path("part2"), header.offsets[2], 0, eof)

    def _dump_file(
        self, file: File, outdir: Path, path: Path, start: int, end: int, eof: int
    ):
        if not start:
            return

        if not end:
            end = eof

        chunk = Chunk(start_offset=start, end_offset=end)
        carve_chunk_to_file(outdir.joinpath(path), file, chunk)


class NetgearCHKHandler(StructHandler):

    NAME = "chk"

    PATTERNS = [HexString("2a 23 24 5e")]

    C_DEFINITIONS = CHK_HEADER
    HEADER_STRUCT = "chk_header_t"
    EXTRACTOR = CHKExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.BIG)
        header_len = len(header)
        if header_len < header.header_len:
            board_id = file.read(header.header_len - len(header))
        else:
            board_id = None
        logger.debug("CHK header", header=header, board_id=board_id)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset
            + header.header_len
            + header.kernel_len
            + header.rootfs_len,
        )


class NetgearTRXHandler(StructHandler):

    NAME = "trx"

    PATTERNS = [HexString("48 44 52 30")]

    C_DEFINITIONS = TRX_HEADER
    HEADER_STRUCT = "trx_header_t"
    EXTRACTOR = TRXExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.LITTLE)
        logger.debug("TRX header", header=header)

        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + header.len
        )
