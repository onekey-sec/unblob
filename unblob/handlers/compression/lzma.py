import io
import lzma
from typing import List, Optional

from structlog import get_logger

from ...file_utils import DEFAULT_BUFSIZE, InvalidInputFormat
from ...models import Handler, ValidChunk

logger = get_logger()


class LZMAHandler(Handler):
    NAME = "lzma"

    YARA_RULE = r"""
        strings:
            $lzma_magic = { 5d 00 00 ( 00 | 01 | 04 | 08 | 10 | 20 | 40 | 80) ( 00 | 01 | 02 | 04 | 08 ) }
        condition:
            // LZMA file format: https://svn.python.org/projects/external/xz-5.0.3/doc/lzma-file-format.txt
            $lzma_magic and
            // dictionary size is non-zero (section 1.1.2 of format definition)
            uint32(@lzma_magic + 1) > 0 and
            // dictionary size is a power of two  (section 1.1.2 of format definition)
            (uint32(@lzma_magic + 1) & (uint32(@lzma_magic + 1) - 1)) == 0 and
            // uncompressed size is either unknown (0xFFFFFFFFFFFFFFFF) or smaller than 256GB  (section 1.1.3 of format definition)
            // yara does not support uint64 so we check it using uint32
            ((uint32(@lzma_magic + 5) == 0xFFFFFFFF and uint32(@lzma_magic + 9) == 0xFFFFFFFF) or uint32(@lzma_magic + 5) < 0x00000040)
    """

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)

        try:
            data = file.read(DEFAULT_BUFSIZE)
            while data and not decompressor.eof:
                decompressor.decompress(data)
                data = file.read(DEFAULT_BUFSIZE)
        except lzma.LZMAError as exc:
            raise InvalidInputFormat from exc

        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.tell() - len(decompressor.unused_data),
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
