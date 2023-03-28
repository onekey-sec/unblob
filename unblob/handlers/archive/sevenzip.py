"""7-zip handlers.

7-zip archive file format SHALL consist of three part.  7-zip archive
file SHALL start with signature header.  The data block SHOULD placed
after the signature header.  The data block is shown as Packed
Streams.  A header database SHOULD be placed after the data block.
The data block MAY be empty when no archived contents exists.  So
Packed Streams is optional.  Since Header database CAN be encoded then
it SHOULD place after data block, that is Packed Streams for Headers.
When Header database is encoded, Header encode Information SHALL
placed instead of Header.

[Signature Header] [Data] [Header Database]

https://fastapi.metacpan.org/source/BJOERN/Compress-Deflate7-1.0/7zip/DOC/7zFormat.txt
"7z uses little endian encoding."

https://py7zr.readthedocs.io/en/latest/archive_format.html
"""
import binascii
from typing import Optional

from structlog import get_logger

from unblob.extractors import Command

from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()

# StartHeader (next_header_offset, next_header_size, next_header_crc)
START_HEADER_SIZE = 8 + 8 + 4


class SevenZipHandler(StructHandler):
    NAME = "sevenzip"

    PATTERNS = [
        HexString(
            """
            // '7', 'z', 0xBC, 0xAF, 0x27, 0x1C
            37 7A BC AF 27 1C
        """
        )
    ]
    C_DEFINITIONS = r"""
        typedef struct sevenzip_header {
            char magic[6];
            uint8 version_maj;
            uint8 version_min;
            uint32 crc;
            uint64 next_header_offset;
            uint64 next_header_size;
            uint32 next_header_crc;
        } sevenzip_header_t;
    """
    HEADER_STRUCT = "sevenzip_header_t"
    EXTRACTOR = Command("7z", "x", "-p", "-y", "{inpath}", "-o{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file)

        # CRC includes the StartHeader (next_header_offset, next_header_size, next_header_crc)
        # CPP/7zip/Archive/7z/7zOut.cpp COutArchive::WriteStartHeader
        calculated_crc = binascii.crc32(header.dumps()[-START_HEADER_SIZE:])
        if header.crc != calculated_crc:
            logger.debug("Invalid header CRC", _verbosity=2)
            return None

        # We read the signature header here to get the offset to the header database
        first_db_header = start_offset + len(header) + header.next_header_offset
        end_offset = first_db_header + header.next_header_size
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
