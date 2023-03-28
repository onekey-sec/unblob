import io
from typing import Optional

from ...extractors import Command
from ...file_utils import Endian
from ...models import File, Regex, StructHandler, ValidChunk

PADDING_LEN = 2
# CPP/7zip/Archive/LzhHandler.cpp
HEADER_MIN_SIZE = 2 + 22


class LZHHandler(StructHandler):
    NAME = "lzh"

    PATTERNS = [
        Regex(r"-lh0-"),
        Regex(r"-lzs-"),
        Regex(r"-lz4-"),
        Regex(r"-lh1-"),
        Regex(r"-lh2-"),
        Regex(r"-lh3-"),
        Regex(r"-lh4-"),
        Regex(r"-lh5-"),
        Regex(r"-lh6-"),
        Regex(r"-lh7-"),
        Regex(r"-lh8-"),
        Regex(r"-lhd-"),
    ]

    PATTERN_MATCH_OFFSET = -2

    C_DEFINITIONS = r"""
        typedef struct lzh_default_header {
            uint8 header_size;          // excludes extended headers size
            uint8 header_checksum;
            char method_id[5];
            uint32 compressed_size;     // includes all extended headers size (if level 1)
            uint32 uncompressed_size;
            uint32 timestamp;
            uint8 fd_attribute;
            uint8 level_identifier;
        } lzh_default_header_t;

        typedef struct level_2_header {
            uint16 header_size; // includes all extended headers
            char method_id[5];
            uint32 compressed_size;     // excludes all extended headers
            uint32 uncompressed_size;
            uint32 timestamp;
            uint8 fd_attribute;
            uint8 level_identifier;
        } level_2_header_t;
    """
    HEADER_STRUCT = "lzh_default_header_t"

    EXTRACTOR = Command("7z", "x", "-p", "-y", "{inpath}", "-o{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, Endian.LITTLE)

        if header.level_identifier > 0x2:
            return None

        if header.level_identifier == 0x2:
            # with level 2, the header size is a uint16 rather than uint8 and there
            # is no checksum. We use this magic trick so we don't parse the header
            # again. See the level_2_header definition in C_DEFINITIONS
            header_size = header.header_size + (header.header_checksum << 8)
        else:
            header_size = header.header_size + PADDING_LEN

        if header_size < HEADER_MIN_SIZE:
            return None

        file.seek(-len(header), io.SEEK_CUR)
        file.seek(header_size + header.compressed_size, io.SEEK_CUR)
        end_offset = file.tell()

        # LZH files are null terminated, so we have to handle the case where
        # we matched the last LZH stream of a file and pad appropriately.
        file.seek(0, io.SEEK_END)
        end_pos = file.tell()

        if end_pos - end_offset == 1:
            end_offset = end_pos

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
