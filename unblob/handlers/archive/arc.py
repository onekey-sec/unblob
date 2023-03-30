from typing import Optional

from dissect.cstruct import Instance
from structlog import get_logger

from unblob.extractors.command import Command

from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()

END_HEADER = b"\x1a\x00"


class ARCHandler(StructHandler):
    NAME = "arc"

    PATTERNS = [
        HexString(
            """
            // Each entry in an archive begins with a one byte archive marker set to 0x1A.
            // The marker is followed by a one byte header type code, from 0x0 to 0x7.
            // Then a null-byte or unitialized-byte terminated filename string of 13 bytes, the
            // uninitialized byte is always set between 0xf0 and 0xff.
            1A (01 | 02 | 03 | 04 | 05 | 06 | 07) [12] (00 | F0 | F1 | F2 | F3 | F4 | F5 | F6 | F7 | F8 | F9 | FA | FB | FC | FD | FE | FF)
            """
        )
    ]

    C_DEFINITIONS = r"""
    typedef struct arc_head {			/* archive entry header format */
        int8 archive_marker;
        int8 header_type;
        char    name[13];		/* file name */
        ulong size;		/* size of file, in bytes */
        ushort date;	/* creation date */
        ushort time;	/* creation time */
        short crc;	/* cyclic redundancy check */
        ulong length;	/* true file length */
    } arc_head_t;
    """

    HEADER_STRUCT = "arc_head_t"
    EXTRACTOR = Command("unar", "-no-directory", "-o", "{outdir}", "{inpath}")

    def valid_name(self, name: bytes) -> bool:
        try:
            # we return False if the name is made out of an array of null bytes
            # or if name starts with null.
            return bool(
                not name.startswith(b"\x00")
                and name[:-1].strip(b"\x00").decode("utf-8")
            )
        except UnicodeDecodeError:
            return False

    def valid_header(self, header: Instance) -> bool:
        if header.archive_marker != 0x1A:
            return False
        if header.header_type > 0x07:
            return False
        if not self.valid_name(header.name):
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        # we loop from header to header until we reach the end header
        offset = start_offset
        while True:
            file.seek(offset)
            read_bytes = file.read(2)

            if read_bytes == END_HEADER:
                offset += 2
                break
            file.seek(offset)
            header = self.parse_header(file)
            if not self.valid_header(header):
                return None

            offset += len(header) + header.size

        return ValidChunk(
            start_offset=start_offset,
            end_offset=offset,
        )
