import io
import lzma
from typing import Optional

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import (
    DEFAULT_BUFSIZE,
    Endian,
    InvalidInputFormat,
    convert_int32,
    convert_int64,
)
from ...models import File, Handler, HexString, ValidChunk

logger = get_logger()

# 256GB
MAX_UNCOMPRESSED_SIZE = 256 * 1024 * 1024 * 1024

# This an arbitrary value
MIN_COMPRESSED_SIZE = 256

MIN_READ_RATIO = 0.1


class LZMAHandler(Handler):
    NAME = "lzma"

    PATTERNS = [
        HexString(
            """
                // pre-computed valid properties bytes
                (
                    51 | 5A | 5B | 5C | 5D | 5E | 63 | 64 | 65 | 66 | 6C | 6D | 6E | 75 | 76 | 7E |
                    87 | 88 | 89 | 8A | 8B | 90 | 91 | 92 | 93 | 99 | 9A | 9B | A2 | A3 | AB | B4 |
                    B5 | B6 | B7 | B8 | BD | BE | BF | C0 | C6 | C7 | C8 | CF | D0 | D8
                )
                // dictionary size
                00 00 ( 00 | 01 | 04 | 08 | 10 | 20 | 40 | 80) ( 00 | 01 | 02 | 04 | 08 )
        """
        )
    ]

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-so", stdout="lzma.uncompressed")

    def is_valid_stream(self, dictionary_size: int, uncompressed_size: int) -> bool:
        # dictionary size is non-zero (section 1.1.2 of format definition)
        # dictionary size is a power of two  (section 1.1.2 of format definition)
        if dictionary_size == 0 or (dictionary_size & (dictionary_size - 1)) != 0:
            return False
        # uncompressed size is either unknown (0xFFFFFFFFFFFFFFFF) or
        # smaller than 256GB  (section 1.1.3 of format definition)
        if not (
            uncompressed_size == 0xFFFFFFFFFFFFFFFF
            or uncompressed_size < MAX_UNCOMPRESSED_SIZE
        ):
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        read_size = 0
        file.seek(start_offset + 1)
        dictionary_size = convert_int32(file.read(4), Endian.LITTLE)
        uncompressed_size = convert_int64(file.read(8), Endian.LITTLE)

        if not self.is_valid_stream(dictionary_size, uncompressed_size):
            raise InvalidInputFormat

        file.seek(start_offset, io.SEEK_SET)
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)

        try:
            while read_size < uncompressed_size and not decompressor.eof:
                data = file.read(DEFAULT_BUFSIZE)
                if not data:
                    if read_size < (uncompressed_size * MIN_READ_RATIO):
                        raise InvalidInputFormat("Very early truncated LZMA stream")

                    logger.debug(
                        "LZMA stream is truncated.",
                        read_size=read_size,
                        uncompressed_size=uncompressed_size,
                    )
                    break
                read_size += len(decompressor.decompress(data))

        except lzma.LZMAError as exc:
            raise InvalidInputFormat from exc

        end_offset = file.tell() - len(decompressor.unused_data)
        compressed_size = end_offset - start_offset

        if (read_size < compressed_size) or (compressed_size < MIN_COMPRESSED_SIZE):
            raise InvalidInputFormat

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
