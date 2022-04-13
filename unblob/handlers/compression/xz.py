import io
from typing import Optional, Tuple

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import (
    Endian,
    convert_int8,
    convert_int32,
    decode_multibyte_integer,
    iterate_patterns,
    round_up,
)
from ...models import File, Handler, HexString, ValidChunk

logger = get_logger()

# The .xz file format definition: https://tukaani.org/xz/xz-file-format-1.0.4.txt

XZ_PADDING = 4  # XZ format byte alignment
MAX_MBI_LEN = 9  # maximum multi-byte integer size is 9, per XZ standard
STREAM_HEADER_SIZE = 12  # magic bytes (6) + flags (2) + CRC32 (4)
STREAM_FOOTER_SIZE = 12  # CRC32 (4) + backward size (4) + flags (2) + magic bytes (2)
STREAM_FOOTER_MAGIC = b"YZ"

MAGIC_BYTES_SIZE = 6
BACKWARD_SIZE_LEN = 4
CRC32_LEN = 4
FLAG_LEN = 2


def read_multibyte_int(file: File) -> Tuple[int, int]:
    """Read a multibyte integer and return the number of bytes read and the integer itself."""
    data = bytearray(file.read(MAX_MBI_LEN))
    file.seek(-MAX_MBI_LEN, io.SEEK_CUR)
    size, mbi = decode_multibyte_integer(data)
    file.seek(size, io.SEEK_CUR)
    return size, mbi


class XZHandler(Handler):
    NAME = "xz"

    PATTERNS = [HexString("FD 37 7A 58 5A 00")]

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:

        file.seek(MAGIC_BYTES_SIZE, io.SEEK_CUR)
        stream_flags = file.read(FLAG_LEN)
        file.seek(start_offset)

        for footer_offset in iterate_patterns(file, stream_flags + STREAM_FOOTER_MAGIC):
            # make sure it's byte aligned
            if (footer_offset - start_offset) % 4 != 0:
                continue

            end_offset = footer_offset + CRC32_LEN

            file.seek(footer_offset - BACKWARD_SIZE_LEN)

            backward_bytes = file.read(BACKWARD_SIZE_LEN)
            stored_backward_size = convert_int32(backward_bytes, Endian.LITTLE)
            real_backward_size = (stored_backward_size + 1) * 4

            if real_backward_size > file.tell():
                continue

            file.seek(-CRC32_LEN - BACKWARD_SIZE_LEN, io.SEEK_CUR)
            # skip backwards of backward size to the start of index
            file.seek(-real_backward_size, io.SEEK_CUR)

            index_size = 0
            index_indicator = convert_int8(file.read(1), Endian.LITTLE)
            # index indicator must be 0, per xz standard
            if index_indicator != 0:
                continue

            index_size += 1

            # read Index 'Number of Records'
            size, num_records = read_multibyte_int(file)
            index_size += size

            # read Record 'Unpadded Size' and 'Uncompressed Size' for every Record
            blocks_size = 0
            for _ in range(0, num_records):
                size, unpadded_size = read_multibyte_int(file)
                index_size += size

                size, _ = read_multibyte_int(file)
                index_size += size

                blocks_size += round_up(unpadded_size, XZ_PADDING)

            index_size += CRC32_LEN

            overall_size = round_up(
                (STREAM_HEADER_SIZE + blocks_size + index_size + STREAM_FOOTER_SIZE),
                XZ_PADDING,
            )

            # if the identified chunk size is equal to the size calculated from
            # the Index's records, that means we matched on the right footer and
            # we can return
            if (end_offset - start_offset) == overall_size:
                return ValidChunk(start_offset=start_offset, end_offset=end_offset)
