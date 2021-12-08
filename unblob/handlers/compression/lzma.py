import io
import lzma
from typing import List, Optional

from structlog import get_logger

from unblob.file_utils import find_first

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
            decompressor.decompress(file.read())
        except lzma.LZMAError:
            return

        # unused_data contains data found after the end of the compressed stream, if any.
        # we can search for that needle within the file to find the end offset :)
        if decompressor.unused_data != b"":
            file.seek(start_offset)
            end_offset = find_first(
                file,
                decompressor.unused_data[0:16],
            )
        else:
            file.seek(0, io.SEEK_END)
            end_offset = file.tell()

        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + end_offset
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
