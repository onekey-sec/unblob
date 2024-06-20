import io
from typing import Optional

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import Endian, InvalidInputFormat, convert_int8
from ...models import File, Handler, HexString, ValidChunk

logger = get_logger()

MAGIC_LEN = 4
BLOCK_HEADER_LEN = 3
RAW_BLOCK = 0
RLE_BLOCK = 1
COMPRESSED_BLOCK = 2
DICT_ID_FIELDSIZE_MAP = [0, 1, 2, 4]
FRAME_CONTENT_FIELDSIZE_MAP = [0, 2, 4, 8]


class ZSTDHandler(Handler):
    NAME = "zstd"

    PATTERNS = [HexString("28 B5 2F FD")]

    EXTRACTOR = Command("zstd", "-d", "{inpath}", "-o", "{outdir}/zstd.uncompressed")

    def get_frame_header_size(self, frame_header_descriptor: int) -> int:
        single_segment = (frame_header_descriptor >> 5 & 1) & 0b1
        dictionary_id = frame_header_descriptor >> 0 & 0b11
        frame_content_size = (frame_header_descriptor >> 6) & 0b11
        return (
            int(not single_segment)
            + DICT_ID_FIELDSIZE_MAP[dictionary_id]
            + FRAME_CONTENT_FIELDSIZE_MAP[frame_content_size]
            + (single_segment and not frame_content_size)
        )

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(start_offset, io.SEEK_SET)
        file.seek(MAGIC_LEN, io.SEEK_CUR)

        frame_header_descriptor = convert_int8(file.read(1), Endian.LITTLE)
        frame_header_size = self.get_frame_header_size(frame_header_descriptor)

        content_checksum_flag = frame_header_descriptor >> 2 & 1
        content_checksum_size = 4 if content_checksum_flag else 0

        unused_bit = frame_header_descriptor >> 4 & 1
        reserved_bit = frame_header_descriptor >> 3 & 1

        # these values MUST be zero per the standard
        if unused_bit != 0x00 or reserved_bit != 0x0:
            raise InvalidInputFormat("Invalid frame header format.")

        file.seek(frame_header_size, io.SEEK_CUR)

        last_block = False
        while not last_block:
            block_header_val = file.read(BLOCK_HEADER_LEN)
            # EOF
            if not block_header_val:
                raise InvalidInputFormat("Premature end of ZSTD stream.")
            block_header = int.from_bytes(block_header_val, byteorder="little")
            last_block = block_header >> 0 & 0b1
            block_type = block_header >> 1 & 0b11

            if block_type in [RAW_BLOCK, COMPRESSED_BLOCK]:
                block_size = block_header >> 3
            elif block_type == RLE_BLOCK:
                block_size = 1
            else:
                raise InvalidInputFormat("Invalid block type")
            file.seek(block_size, io.SEEK_CUR)

        file.seek(content_checksum_size, io.SEEK_CUR)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.tell(),
        )
