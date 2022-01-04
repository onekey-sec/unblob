import io
import os
from typing import List, Optional

import arpy
from structlog import get_logger

from ...models import Handler, ValidChunk

logger = get_logger()


HEADER_LENGTH = 0x44
SIGNATURE_LENGTH = 0x8


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
    ) -> Optional[ValidChunk]:

        ar = arpy.Archive(fileobj=file)  # type: ignore

        try:
            ar.read_all_headers()
        except arpy.ArchiveFormatError as exc:
            logger.debug(
                "Hit an ArchiveFormatError, we've probably hit some other kind of data",
                exc_info=exc,
            )

            # wind the cursor back the whole header length to check if we failed on
            # the first match, which means malformed AR archive
            ar.file.seek(-HEADER_LENGTH, os.SEEK_CUR)
            # we check if we failed on the first match
            if start_offset == ar.file.tell():
                return
            # otherwise we seek past the signature (failure on malformed AR archive
            # within the whole file, not at the start)
            ar.file.seek(SIGNATURE_LENGTH, os.SEEK_CUR)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=ar.file.tell(),
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
