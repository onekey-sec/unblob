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
from typing import List, Optional

from structlog import get_logger

from ...file_utils import DEFAULT_BUFSIZE, read_until_past
from ...models import Handler, ValidChunk

logger = get_logger()

GZIP2_CRC_LEN = 4
GZIP2_SIZE_LEN = 4
GZIP2_FOOTER_LEN = GZIP2_CRC_LEN + GZIP2_SIZE_LEN


class SingleMemberGzipReader(gzip._GzipReader):
    def read(self):
        uncompress = b""

        while True:
            buf = self._fp.read(DEFAULT_BUFSIZE)

            uncompress = self._decompressor.decompress(buf, DEFAULT_BUFSIZE)
            self._fp.prepend(self._decompressor.unconsumed_tail)
            self._fp.prepend(self._decompressor.unused_data)

            if uncompress != b"":
                break
            if buf == b"":
                raise EOFError(
                    "Compressed file ended before the "
                    "end-of-stream marker was reached"
                )

        self._add_read_data(uncompress)
        self._pos += len(uncompress)

        return uncompress


class GZIPHandler(Handler):
    NAME = "gzip"

    YARA_RULE = r"""
    strings:
        // id1 & id2
        // compression method (0x8 = DEFLATE)
        // flags, 00011111 (0x1f) is the highest since the first 3 bits are reserved
        // unix time
        // eXtra FLags
        // Operating System (RFC1952 describes 0-13, or 255)
        $gzip_magic = /\x1f\x8b\x08[\x00-\x1f][\x00-\xff]{4}[\x00-\x04][\x00-\x0c\xff]/
    condition:
        $gzip_magic
    """

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        fp = SingleMemberGzipReader(file)
        fp._init_read()
        if not fp._read_gzip_header():
            return

        try:
            while not fp._decompressor.eof:
                fp.read()
        except gzip.BadGzipFile as e:
            logger.warn(e)
            return

        file.seek(GZIP2_FOOTER_LEN - len(fp._decompressor.unused_data), io.SEEK_CUR)

        # Gzip files can be padded with zeroes
        end_offset = read_until_past(file, b"\x00")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
