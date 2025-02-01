import os
from typing import Optional

import arpy
from structlog import get_logger

from ...extractors import Command
from ...file_utils import OffsetFile
from ...models import File, Handler, HexString, ValidChunk

logger = get_logger()


HEADER_LENGTH = 0x44
SIGNATURE_LENGTH = 0x8


class ARHandler(Handler):
    NAME = "ar"

    PATTERNS = [
        HexString(
            """
            // "!<arch>\\n", 58 chars of whatever, then the ARFMAG
            21 3C 61 72 63 68 3E 0A [58] 60 0A
    """
        )
    ]

    EXTRACTOR = Command("unar", "-no-directory", "-o", "{outdir}", "{inpath}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        offset_file = OffsetFile(file, start_offset)
        ar = arpy.Archive(fileobj=offset_file)  # type: ignore

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
            if start_offset == file.tell():
                return None
            # otherwise we seek past the signature (failure on malformed AR archive
            # within the whole file, not at the start)
            ar.file.seek(SIGNATURE_LENGTH, os.SEEK_CUR)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.tell(),
        )
