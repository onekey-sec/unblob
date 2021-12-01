import io
from typing import List, Optional

from structlog import get_logger

from ...models import StructHandler, ValidChunk

logger = get_logger()

END_HEADER = b"\x1a\x00"


class ARCHandler(StructHandler):
    NAME = "arc"

    YARA_RULE = r"""
        strings:
            /**
            Each entry in an archive begins with a one byte archive marker set to 0x1A.
            The marker is followed by a one byte header type code, from 0x0 to 0x7.
            Then a null-byte or unitialized-byte terminated filename string of 13 bytes, the
            uninitialized byte is always set between 0xf0 and 0xff.

            We use the YARA rule to match valid dates and times:
                - our date definition allows dates between the 1980 and 15/12/2050 (that should be enough).
                - our time definition allowes times between 00:00 and 24:60.
            */
            $arc_magic = /\x1A[\x00-\x07][\S]{12}[\x00|\xf0-\xff][\x00-\xff]{4}[\x00-\x8d][\x00-\x8f][\x00-\xc7][\x00-\x9f]/

        condition:
            $arc_magic
    """

    C_DEFINITIONS = r"""
    struct heads {			/* archive entry header format */
        int8 archive_marker;
        int8 header_type;
        char    name[13];		/* file name */
        long size;		/* size of file, in bytes */
        ushort date;	/* creation date */
        ushort time;	/* creation time */
        short crc;	/* cyclic redundancy check */
        long length;	/* true file length */
    };
    """

    HEADER_STRUCT = "heads"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        # we loop from header to header until we reach the end header
        offset = start_offset
        while True:
            file.seek(offset)
            try:
                read_bytes = file.read(2)
            except EOFError:
                logger.warning("Potential ARC header is missing")
                return

            if read_bytes == END_HEADER:
                offset += 2
                break
            file.seek(offset)
            header = self.parse_header(file)
            offset += len(header) + header.size

        return ValidChunk(
            start_offset=start_offset,
            end_offset=offset,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["unar", "-o", outdir, inpath]
