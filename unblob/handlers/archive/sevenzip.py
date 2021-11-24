"""
7-zip archive file format SHALL consist of three part. 7-zip archive file
SHALL start with signature header. The data block SHOULD placed after the
signature header. The data block is shown as Packed Streams.
A header database SHOULD be placed after the data block. The data block MAY
be empty when no archived contents exists. So Packed Streams is optional.
Since Header database CAN be encoded then it SHOULD place after data block,
that is Packed Streams for Headers. When Header database is encoded, Header
encode Information SHALL placed instead of Header.

[Signature Header]
[Data]
[Header Database]

https://fastapi.metacpan.org/source/BJOERN/Compress-Deflate7-1.0/7zip/DOC/7zFormat.txt
"7z uses little endian encoding."

https://py7zr.readthedocs.io/en/latest/archive_format.html
"""
import io
from typing import List, Optional

from structlog import get_logger

from ...models import StructHandler, ValidChunk

logger = get_logger()


class SevenZipHandler(StructHandler):
    NAME = "sevenzip"

    # Yara doesn't like the rule starting with a number
    # yara.SyntaxError: line 21: syntax error, unexpected integer number, expecting identifier
    YARA_RULE = r"""
        strings:
            // '7', 'z', 0xBC, 0xAF, 0x27, 0x1C
            $sevenzip_magic = { 37 7A BC AF 27 1C }

        condition:
            $sevenzip_magic
    """
    C_DEFINITIONS = r"""
        struct sevenzip_header {
            char magic[6];
            uint8 version_maj;
            uint8 version_min;
            uint32 crc;
            uint64 next_header_offset;
            uint64 next_header_size;
            uint32 next_header_crc;
        }

        struct header_db {
            char property_id;
        }
    """
    HEADER_STRUCT = "sevenzip_header"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        header = self.parse_header(file)
        # We read the signature header here to get the offset to the header database
        first_db_header = start_offset + len(header) + header.next_header_offset
        end_offset = first_db_header + header.next_header_size
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        # 7z needs the outdir to be directly after the -o, without any space.
        return ["7z", "x", "-p", "", "-y", inpath, f"-o{outdir}"]
