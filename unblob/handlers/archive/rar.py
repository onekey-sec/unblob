"""
RAR Version 4.x
https://codedread.github.io/bitjs/docs/unrar.html

RAR Version 5.x
https://www.rarlab.com/technote.htm#rarsign
"""

import io
from typing import List, Optional

import rarfile
from structlog import get_logger

from ...models import Handler, ValidChunk

logger = get_logger()


class RarHandler(Handler):
    NAME = "rar"

    YARA_RULE = r"""
        strings:
            // RAR v4.x ends with 00, RAR v5.x ends with 01 00
            $rar_magic = { 52 61 72 21 1A 07 ( 00 | 01 00 ) }

        condition:
            $rar_magic
    """

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        try:
            rar_file = rarfile.RarFile(file)
        except (rarfile.Error, ValueError):
            return

        # RarFile have the side effect of moving the file pointer
        rar_end_offset = file.tell()

        if rar_file.needs_password():
            logger.warning("There are password protected files in the RAR file")

        return ValidChunk(start_offset=start_offset, end_offset=rar_end_offset)

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["unar", "-p", "", inpath, "-o", outdir]
