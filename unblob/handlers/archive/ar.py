import io
import os
from typing import List, Union

import arpy
from structlog import get_logger

from ...models import UnknownChunk, ValidChunk

logger = get_logger()

NAME = "ar"

YARA_RULE = r"""
    strings:
        // "!<arch>\\n", 58 chars of whatever, then the ARFMAG
        $ar_magic = { 21 3C 61 72 63 68 3E 0A [58] 60 0A }
    condition:
        $ar_magic
"""


def calculate_chunk(
    file: io.BufferedReader, start_offset: int
) -> Union[ValidChunk, UnknownChunk]:

    file.seek(start_offset)

    # TODO: This is not the most efficient way to do it, but the Archive() always tries to wind
    # the cursor back to the start to read the signature, and ignores the cursor position of the
    # BufferedReader we pass it. For that reason, I'm just duplicating it into its own BytesIO
    # stream, starting at the AR start_offset. We need a better way to handle cases like this.

    ar_dup = io.BytesIO(file.read())
    ar = arpy.Archive(fileobj=ar_dup)

    try:
        _ = ar.read_all_headers()
    except arpy.ArchiveFormatError as afe:
        logger.debug(
            f"Hit an ArchiveFormatError, we've probably hit some other kind of data: {afe}"
        )
        # Since arpy has tried to read another file header, we need to wind the cursor back the
        # length of the header, so it points to the end of the AR chunk.
        ar.file.seek(-0x3C, os.SEEK_CUR)

    end_tell = ar.file.tell()

    return ValidChunk(
        start_offset=start_offset,
        end_offset=start_offset + end_tell,
    )


def make_extract_command(inpath: str, outdir: str) -> List[str]:
    return ["7z", "x", "-y", inpath, f"-o{outdir}"]
