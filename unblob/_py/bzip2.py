import io

from unblob.file_utils import iterbits, round_up


BLOCK_HEADER = 0x0000_3141_5926_5359
BLOCK_ENDMARK = 0x0000_1772_4538_5090

COMPRESSED_MAGIC_LENGTH = 6 * 8

BLOCK_ENDMARK_SHIFTED = BLOCK_ENDMARK << COMPRESSED_MAGIC_LENGTH


def bzip2_recover(file: io.BufferedIOBase, start_offset: int) -> int:
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
        return -1

    # blocks are counted in bits but we need an offset in bytes
    end_block_offset = round_up(current_block_end, 8) // 8
    return start_offset + end_block_offset
