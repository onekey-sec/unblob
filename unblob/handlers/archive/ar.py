import io
import os
from typing import List, Union

import arpy
from structlog import get_logger

from ...models import Handler, UnknownChunk, ValidChunk

logger = get_logger()


HEADER_LENGTH = 0x3C


class ARHandler(Handler):
    NAME = "ar"

    YARA_RULE = r"""
        strings:
            // "!<arch>\\n", 58 chars of whatever, then the ARFMAG
            $ar_magic = { 21 3C 61 72 63 68 3E 0A [58] 60 0A }
        condition:
            $ar_magic
    """

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Union[ValidChunk, UnknownChunk]:

        ar = arpy.Archive(fileobj=file)  # type: ignore

        try:
            ar.read_all_headers()
        except arpy.ArchiveFormatError as exc:
            logger.debug(
                "Hit an ArchiveFormatError, we've probably hit some other kind of data",
                exc_info=exc,
            )
            # Since arpy has tried to read another file header, we need to wind the cursor back the
            # length of the header, so it points to the end of the AR chunk.
            ar.file.seek(-HEADER_LENGTH, os.SEEK_CUR)

        offset = ar.file.tell()

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + offset,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
