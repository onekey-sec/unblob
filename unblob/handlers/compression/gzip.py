"""
Handler for gzip compression format based on standard documented
at https://datatracker.ietf.org/doc/html/rfc1952.

The handler will create valid chunks for each gzip compressed stream instead of
concatenating sequential streams into an overall ValidChunk.

We monkey patched Python builtin gzip's _GzipReader read() function to stop
reading as soon as it reach the EOF marker of the current gzip stream. This
is a requirement for unblob given that streams can be malformed and followed
by garbage/random content that triggers BadGzipFile errors when gzip
library tries to read the next stream header.
"""
import gzip
import io
import zlib
from typing import Optional

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import InvalidInputFormat
from ...models import File, Handler, HexString, ValidChunk
from ._gzip_reader import SingleMemberGzipReader

logger = get_logger()

GZIP2_CRC_LEN = 4
GZIP2_SIZE_LEN = 4
GZIP2_FOOTER_LEN = GZIP2_CRC_LEN + GZIP2_SIZE_LEN


class GZIPHandler(Handler):
    NAME = "gzip"

    PATTERNS = [
        HexString(
            """
            // ID1
            1F
            // ID2
            8B
            // compression method (0x8 = DEFLATE)
            08
            // flags, 00011111 (0x1f) is the highest since the first 3 bits are reserved
            (
                00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 |
                0A | 0B | 0C | 0D | 0E | 0F | 10 | 11 | 12 | 13 |
                14 | 15 | 16 | 17 | 18 | 19 | 1A | 1B | 1C | 1D | 1E
            )
            // unix time (uint32) + eXtra FLags (2 or 4 per RFC1952 2.3.1)
            // we accept any value because the RFC is not followed by some samples
            [5]
            // Operating System (0-13, or 255 per RFC1952 2.3.1)
            (
                00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 0A | 0B | 0C | 0D | FF
            )
        """
        )
    ]

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        fp = SingleMemberGzipReader(file)
        if not fp.read_header():
            return

        try:
            fp.read_until_eof()
        except (gzip.BadGzipFile, zlib.error) as e:
            raise InvalidInputFormat from e

        file.seek(GZIP2_FOOTER_LEN - len(fp.unused_data), io.SEEK_CUR)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.tell(),
        )
