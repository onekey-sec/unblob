"""
We currently support detecting two specific Stuffit file formats:

- Stuffit SIT (with 'SIT!' magic)
- Stuffit 5 (with 'StuffIt (c)1997-' magic)

Due to lack of access to sample files, source code, and really old packing tools,
we don't support the following Stuffit file formats at the moment:

- Stuffit X ('StuffIt!' or 'StuffIt?' magic)
- Stuffit Delux ('SITD' magic)

If you have the resources to add support for these archive formats,
feel free to do so !
"""
import io
from typing import List, Optional

from structlog import get_logger

from ...file_utils import Endian
from ...models import StructHandler, ValidChunk

logger = get_logger()


class _StuffItHandlerBase(StructHandler):
    """A common base for all StuffIt formats."""

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        header = self.parse_header(file, endian=Endian.BIG)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.archive_length,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["unar", inpath, "-o", outdir]


class StuffItSITHandler(_StuffItHandlerBase):
    NAME = "stuffit"

    YARA_RULE = r"""
        strings:
            // "SIT!\\x00", then 6 bytes (uint16 number of files and uint32 size), then "rLau".
            $sit_magic = { 53 49 54 21 [6] 72 4C 61 75 }
        condition:
            $sit_magic
    """

    C_DEFINITIONS = r"""
        struct sit_header
        {
            char signature[4];
            uint16 num_files;
            uint32 archive_length;
            char signature2[4];
        };
    """
    HEADER_STRUCT = "sit_header"


class StuffIt5Handler(_StuffItHandlerBase):
    NAME = "stuffit5"

    YARA_RULE = r"""
        strings:
            // "StuffIt (c)1997-"
            $stuffit5_magic = { 53 74 75 66 66 49 74 20 28 63 29 31 39 39 37 2D }
        condition:
            $stuffit5_magic
    """

    C_DEFINITIONS = r"""
        struct stuffit5_header
        {
            char signature[80];
            uint32 unknown;
            uint32 archive_length;
            uint32 entry_offset;
            uint16 num_root_dir_entries;
            uint32 first_entry_offset;
        };
    """
    HEADER_STRUCT = "stuffit5_header"
