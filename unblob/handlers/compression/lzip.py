import io
from typing import Optional

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import Endian, convert_int64
from ...models import File, Handler, HexString, ValidChunk

logger = get_logger()

# magic (4 bytes) + VN (1 byte) + DS (1 byte)
HEADER_LEN = 4 + 1 + 1
# LZMA stream is 2 bytes aligned
LZMA_ALIGNMENT = 2


class LZipHandler(Handler):
    NAME = "lzip"

    PATTERNS = [HexString("4C 5A 49 50 01")]

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(HEADER_LEN, io.SEEK_CUR)
        # quite the naive idea but it works
        # the idea is to read 8 bytes uint64 every 2 bytes alignment
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

    EXTRACTOR = Command(
        "lziprecover", "-k", "-D0", "-i", "{inpath}", "-o", "{outdir}/lz.uncompressed"
    )
