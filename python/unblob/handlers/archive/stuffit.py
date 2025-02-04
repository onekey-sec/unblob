"""Stuffit handlers.

We currently support detecting two specific Stuffit file formats:

    - Stuffit SIT (with 'SIT!' magic)

    - Stuffit 5 (with 'StuffIt (c)1997-' magic)

Due to lack of access to sample files, source code, and really old
packing tools, we don't support the following Stuffit file formats at
the moment:

    - Stuffit X ('StuffIt!' or 'StuffIt?' magic)

    - Stuffit Delux ('SITD' magic)

If you have the resources to add support for these archive formats,
feel free to do so !
"""

from typing import Optional

from structlog import get_logger

from ...extractors import Command
from ...file_utils import Endian
from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()


class _StuffItHandlerBase(StructHandler):
    """A common base for all StuffIt formats."""

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.BIG)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.archive_length,
        )

    EXTRACTOR = Command("unar", "-no-directory", "-o", "{outdir}", "{inpath}")


class StuffItSITHandler(_StuffItHandlerBase):
    NAME = "stuffit"

    PATTERNS = [
        HexString(
            """
            // "SIT!\\x00", then 6 bytes (uint16 number of files and uint32 size), then "rLau".
            53 49 54 21 [6] 72 4C 61 75
        """
        )
    ]

    C_DEFINITIONS = r"""
        typedef struct sit_header
        {
            char signature[4];
            uint16 num_files;
            uint32 archive_length;
            char signature2[4];
        } sit_header_t;
    """
    HEADER_STRUCT = "sit_header_t"


class StuffIt5Handler(_StuffItHandlerBase):
    NAME = "stuffit5"

    PATTERNS = [
        HexString(
            """
            // "StuffIt (c)1997-"
            53 74 75 66 66 49 74 20 28 63 29 31 39 39 37 2D
    """
        )
    ]

    C_DEFINITIONS = r"""
        typedef struct stuffit5_header
        {
            char signature[80];
            uint32 unknown;
            uint32 archive_length;
            uint32 entry_offset;
            uint16 num_root_dir_entries;
            uint32 first_entry_offset;
        } stuffit5_header_t;
    """
    HEADER_STRUCT = "stuffit5_header_t"
