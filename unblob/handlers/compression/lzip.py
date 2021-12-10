import io
from pathlib import Path
from typing import List, Optional

from structlog import get_logger

from ...file_utils import Endian, convert_int64
from ...models import Handler, ValidChunk

logger = get_logger()

# magic (4 bytes) + VN (1 byte) + DS (1 byte)
HEADER_LEN = 4 + 1 + 1
# LZMA stream is 2 bytes aligned
LZMA_ALIGNMENT = 2


class LZipHandler(Handler):
    NAME = "lzip"

    YARA_RULE = r"""
        strings:
            $lzip_magic = { 4C 5A 49 50 01 }
        condition:
            $lzip_magic
    """

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        file.read(HEADER_LEN)
        # quite the naive idea but it works
        # the idea is to read 8 bytes uint64 every 2 bytes alignment
        # until we end up reading the Member Size field which corresponds
        # to "the total size of the member, including header and trailer".
        # We either find it or reach EOF, which will be caught by finder.

        while True:
            file.seek(LZMA_ALIGNMENT, io.SEEK_CUR)
            try:
                member_size = convert_int64(file.read(8), Endian.LITTLE)
            except ValueError:
                return
            if member_size == (file.tell() - start_offset):
                end_offset = file.tell()
                break
            file.seek(-8, io.SEEK_CUR)

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        outfile = Path(inpath).stem
        return ["lziprecover", "-k", "-D0", "-i", inpath, "-o", f"{outdir}/{outfile}"]
