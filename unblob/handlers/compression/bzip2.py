import io
from typing import Optional

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import Endian, InvalidInputFormat, iterbits, round_up
from ...models import File, Regex, StructHandler, ValidChunk

logger = get_logger()


BLOCK_HEADER = 0x0000_3141_5926_5359
BLOCK_ENDMARK = 0x0000_1772_4538_5090
# BCD-encoded digits of BLOCK_HEADER
COMPRESSED_MAGIC = b"1AY&SY\x86\xc6"
COMPRESSED_MAGIC_LENGTH = 6 * 8

BLOCK_ENDMARK_SHIFTED = BLOCK_ENDMARK << COMPRESSED_MAGIC_LENGTH


FOOTER_SIZE = 4  # 4 bytes CRC


class BZip2Handler(StructHandler):

    NAME = "bzip2"

    # magic + version + block_size + compressed_magic
    PATTERNS = [Regex(r"\x42\x5a\x68[\x31-\x39]\x31\x41\x59\x26\x53\x59")]

    C_DEFINITIONS = r"""
        typedef struct bzip2_header {
            char magic[2];              // 'BZ' signature/magic number
            uint8 version;              // 'h' for Bzip2 ('H'uffman coding), '0' for Bzip1 (deprecated)
            uint8 hundred_k_blocksize;  // '1'..'9' block-size 100 kB-900 kB (uncompressed)
            char compressed_magic[8];   // 0x314159265359 (BCD (pi))
            uint32 crc;                 // checksum for this block
            uint8 randomised;           // 0=>normal, 1=>randomised (deprecated)
        } bzip2_header_t;
    """
    HEADER_STRUCT = "bzip2_header_t"

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:

        header = self.parse_header(file, Endian.BIG)
        end_block_offset = -1
        while header.compressed_magic == COMPRESSED_MAGIC:
            current_offset = file.tell() - len(header)
            end_block_offset = self.bzip2_recover(file, current_offset)
            try:
                file.seek(end_block_offset + FOOTER_SIZE, io.SEEK_SET)
                header = self.parse_header(file, Endian.BIG)
            except EOFError:
                break

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_block_offset + FOOTER_SIZE,
        )

    def bzip2_recover(self, file: File, start_offset: int) -> int:
        """Emulate the behavior of bzip2recover, matching on compressed magic and end of stream
        magic to identify the end offset of the whole bzip2 chunk.
        Count from absolute start_offset and returns absolute end_offset
        (first byte after the chunk ends).
        """

        bits_read = 0
        buff = 0
        current_block_end = 0
        start_block_found = False
        end_block_found = False

        file.seek(start_offset)

        for b in iterbits(file):
            bits_read += 1

            buff = (buff << 1 | b) & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF

            if buff & 0xFFFF_FFFF_FFFF == BLOCK_HEADER:
                start_block_found = True
            elif buff & 0xFFFF_FFFF_FFFF == BLOCK_ENDMARK:
                end_block_found = True
                current_block_end = bits_read
            elif buff & 0xFFFF_FFFF_FFFF_0000_0000_0000 == BLOCK_ENDMARK_SHIFTED:
                if buff & 0xFFFF_FFFF_FFFF == BLOCK_HEADER:
                    continue
                break

        if not (start_block_found and end_block_found):
            raise InvalidInputFormat("Couldn't find valid bzip2 content")

        # blocks are counted in bits but we need an offset in bytes
        end_block_offset = round_up(current_block_end, 8) // 8
        return start_offset + end_block_offset
