import io

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import Endian, convert_int64
from ...models import (
    File,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    ValidChunk,
)

logger = get_logger()

# magic (4 bytes) + VN (1 byte) + DS (1 byte)
HEADER_LEN = 4 + 1 + 1
# lzip does not pad the LZMA stream, so a member's total length can be odd;
# scan byte-by-byte so the member_size trailer is found at any offset
LZMA_ALIGNMENT = 1


class LZipHandler(Handler):
    NAME = "lzip"

    PATTERNS = [HexString("4C 5A 49 50 01")]

    EXTRACTOR = Command(
        "lziprecover", "-k", "-D0", "-i", "{inpath}", "-o", "{outdir}/lz.uncompressed"
    )

    DOC = HandlerDoc(
        name="Lzip",
        description="Lzip is a lossless compressed file format based on the LZMA algorithm. It features a simple header, CRC-checked integrity, and efficient compression for large files.",
        handler_type=HandlerType.COMPRESSION,
        vendor=None,
        references=[
            Reference(
                title="Lzip File Format Documentation",
                url="https://www.nongnu.org/lzip/manual/lzip_manual.html",
            ),
            Reference(
                title="Lzip Wikipedia",
                url="https://en.wikipedia.org/wiki/Lzip",
            ),
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(HEADER_LEN, io.SEEK_CUR)
        # quite the naive idea but it works
        # the idea is to read 8 bytes uint64 at every byte offset
        # until we end up reading the Member Size field which corresponds
        # to "the total size of the member, including header and trailer".
        # We either find it or reach EOF, which will be caught by finder.

        while True:
            file.seek(LZMA_ALIGNMENT, io.SEEK_CUR)
            member_size = convert_int64(file.read(8), Endian.LITTLE)
            if member_size == (file.tell() - start_offset):
                end_offset = file.tell()
                break
            file.seek(-8, io.SEEK_CUR)

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
