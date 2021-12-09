import io
from typing import List, Optional

from structlog import get_logger

from ...file_utils import Endian, iterbits, round_up
from ...models import StructHandler, ValidChunk

logger = get_logger()


BLOCK_HEADER = 0x0000_3141_5926_5359
BLOCK_ENDMARK = 0x0000_1772_4538_5090

COMPRESSED_MAGIC_LENGTH = 6 * 8


FOOTER_SIZE = 10  # 6 bytes magic + 4 bytes CRC


class BZip2Handler(StructHandler):

    NAME = "bzip2"

    YARA_RULE = r"""
        strings:
            // magic + version + block_size + compressed_magic
            $magic = /\x42\x5a\x68[\x31-\x39]\x31\x41\x59\x26\x53\x59/
        condition:
            $magic
    """

    C_DEFINITIONS = r"""
        struct bzip2_header {
            char magic[2];              // 'BZ' signature/magic number
            uint8 version;              // 'h' for Bzip2 ('H'uffman coding), '0' for Bzip1 (deprecated)
            uint8 hundred_k_blocksize;  // '1'..'9' block-size 100 kB-900 kB (uncompressed)
            char compressed_magic[8];   // 0x314159265359 (BCD (pi))
            uint32 crc;                 // checksum for this block
            uint8 randomised;           // 0=>normal, 1=>randomised (deprecated)
        };
    """
    HEADER_STRUCT = "bzip2_header"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        self.parse_header(file, Endian.BIG)
        end_block_offset = self.bzip2_recover(file, start_offset)
        if end_block_offset == -1:
            logger.warning("Couldn't find valid bzip2 content")
            return

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_block_offset + FOOTER_SIZE,
        )

    def bzip2_recover(self, file: io.BufferedIOBase, start_offset: int) -> int:
        """Emulate the behavior of bzip2recover, matching on compressed magic and end of stream
        magic to identify the end offset of the whole bzip2 chunk.
        Count from absolute start_offset and returns absolute end_offset.
        """

        bits_read = 0
        buff = 0
        curr_block = 0
        blocks_found = 0
        current_block_start = 0
        current_block_end = 0

        file.seek(start_offset)

        for b in iterbits(file):
            bits_read += 1

            buff = (buff << 1 | b) & 0xFFFF_FFFF_FFFF

            if buff == BLOCK_HEADER or buff == BLOCK_ENDMARK:
                blocks_found += 1

                if bits_read > COMPRESSED_MAGIC_LENGTH + 1:
                    current_block_end = bits_read - (COMPRESSED_MAGIC_LENGTH + 1)

                if curr_block > 0 and (current_block_end - current_block_start) >= 130:
                    logger.debug(
                        "bzip2_recover (complete block)",
                        block_id=curr_block,
                        block_start=current_block_start,
                        block_end=current_block_end,
                    )

                curr_block += 1
                current_block_start = bits_read

        if blocks_found < 2:
            return -1

        # blocks are counted in bits but we need an offset in bytes
        end_block_offset = round_up(current_block_end, 8) // 8
        return start_offset + end_block_offset

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
