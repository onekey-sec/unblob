import io
import lzma
from typing import List, Optional

from structlog import get_logger

from ...file_utils import DEFAULT_BUFSIZE
from ...models import Handler, ValidChunk

logger = get_logger()


class LZMAHandler(Handler):
    NAME = "lzma"

    YARA_RULE = r"""
        strings:
            $lzma_magic = { 5d 00 00 ( 00 | 01 | 04 | 08 | 10 | 20 | 40 | 80) ( 00 | 01 | 02 | 04 | 08 ) }
        condition:
            $lzma_magic
    """

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)

        try:
            while not decompressor.eof:
                decompressor.decompress(file.read(DEFAULT_BUFSIZE))
        except lzma.LZMAError:
            return

        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.tell() - len(decompressor.unused_data),
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
