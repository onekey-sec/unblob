import binascii
import io
from collections.abc import Iterable
from pathlib import Path
from typing import Optional, cast

from structlog import get_logger

from unblob.extractor import carve_chunk_to_file
from unblob.file_utils import Endian, File, InvalidInputFormat, StructParser
from unblob.models import Chunk, Extractor, HexString, StructHandler, ValidChunk

logger = get_logger()
CRC_CONTENT_OFFSET = 12

TRX_V1_C_DEFINITION = r"""
    typedef struct trx_header {
        uint32 magic;              /* "HDR0" */
        uint32 len;                /* header size + data */
        uint32 crc32;              /* 32-bit CRC from flag_version to end of file */
        uint16 flags;
        uint16 version;
        uint32 offsets[3];         /* Offsets of partitions from start of header */
    } trx_header_t;
"""

TRX_V2_C_DEFINITION = r"""
    typedef struct trx_header {
        uint32 magic;              /* "HDR0" */
        uint32 len;                /* header size + data */
        uint32 crc32;              /* 32-bit CRC from flag_version to end of file */
        uint16 flags;
        uint16 version;
        uint32 offsets[4];         /* Offsets of partitions from start of header */
    } trx_header_t;
"""


class TRXExtractor(Extractor):
    def __init__(self, c_definitions: str):
        self._struct_parser = StructParser(c_definitions)

    def extract(self, inpath: Path, outdir: Path):
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("trx_header_t", file, Endian.LITTLE)
            file.seek(0, io.SEEK_END)
            eof = file.tell()
            offsets = sorted(
                [
                    offset
                    for offset in [*cast(Iterable, header.offsets), eof]
                    if offset > 0
                ]
            )
            for i, (start_offset, end_offset) in enumerate(zip(offsets, offsets[1:])):
                chunk = Chunk(start_offset=start_offset, end_offset=end_offset)
                carve_chunk_to_file(outdir.joinpath(Path(f"part{i}")), file, chunk)


class NetgearTRXBase(StructHandler):
    HEADER_STRUCT = "trx_header_t"

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.LITTLE)

        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid TRX header.")

        if not self._is_crc_valid(file, start_offset, header):
            raise InvalidInputFormat("Invalid CRC32.")

        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + header.len
        )

    def is_valid_header(self, header) -> bool:
        return header.len >= len(header)

    def _is_crc_valid(self, file: File, start_offset: int, header) -> bool:
        file.seek(start_offset + CRC_CONTENT_OFFSET)
        content = bytearray(file.read(header.len - CRC_CONTENT_OFFSET))
        computed_crc = (binascii.crc32(content) ^ -1) & 0xFFFFFFFF
        return header.crc32 == computed_crc


class NetgearTRXv1Handler(NetgearTRXBase):
    NAME = "trx_v1"
    PATTERNS = [
        HexString(
            """
            // 00000000: 4844 5230 0010 0000 33b9 d625 0000 0100  HDR0....3..%....
            // 00000010: 1c00 0000 3000 0000 4400 0000 7361 6d70  ....0...D...
            48 44 52 30 [10] 01 00
        """
        ),
    ]
    C_DEFINITIONS = TRX_V1_C_DEFINITION
    EXTRACTOR = TRXExtractor(TRX_V1_C_DEFINITION)


class NetgearTRXv2Handler(NetgearTRXBase):
    NAME = "trx_v2"
    PATTERNS = [
        HexString(
            """
            // 00000000: 4844 5230 0010 0000 0a3d 4b05 0000 0200  HDR0.....=K.....
            // 00000010: 2000 0000 3400 ffff ffff ffff ffff 0000   ...4...........
            48 44 52 30 [10] 02 00
        """
        ),
    ]
    C_DEFINITIONS = TRX_V2_C_DEFINITION
    EXTRACTOR = TRXExtractor(TRX_V2_C_DEFINITION)
