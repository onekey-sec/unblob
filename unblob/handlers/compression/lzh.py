import io
from typing import List, Optional

from ...file_utils import Endian
from ...models import StructHandler, ValidChunk

PADDING_LEN = 2
LEVEL_IDENTIFIERS = [0, 1, 2]
METHOD_IDS = [
    b"-lh0-",
    b"-lzs-",
    b"-lz4-",
    b"-lh1-",
    b"-lh2-",
    b"-lh3-",
    b"-lh4-",
    b"-lh5-",
    b"-lh6-",
    b"-lh7-",
    b"-lh8-",
    b"-lhd-",
]


class LZHHandler(StructHandler):

    NAME = "lzh"

    YARA_RULE = r"""
        strings:
            // 2 header bytes followed by method ID
            $lzh_magic = /[\x00-\xff][\x00-\xff]({magic_ids})/
        condition:
            $lzh_magic
    """.format(
        magic_ids="|".join([char.decode() for char in METHOD_IDS])
    )

    C_DEFINITIONS = r"""
        struct lzh_default_header {
            uint8 header_size;          // excludes extended headers size
            uint8 header_checksum;
            char method_id[5];
            uint32 compressed_size;     // includes all extended headers size (if level 1)
            uint32 uncompressed_size;
            uint32 timestamp;
            uint8 fd_attribute;
            uint8 level_identifier;
        };

        struct level_2_header {
            uint16 header_size; // includes all extended headers
            char method_id[5];
            uint32 compressed_size;     // excludes all extended headers
            uint32 uncompressed_size;
            uint32 timestamp;
            uint8 fd_attribute;
            uint8 level_identifier;
        };
    """
    HEADER_STRUCT = "lzh_default_header"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        header = self.parse_header(file, Endian.LITTLE)

        if (
            header.method_id not in METHOD_IDS
            or header.level_identifier not in LEVEL_IDENTIFIERS
        ):
            return

        if header.level_identifier == 0x2:
            # with level 2, the header size is a uint16 rather than uint8 and there
            # is no checksum. We use this magic trick so we don't parse the header
            # again. See the level_2_header definition in C_DEFINITIONS
            header_size = header.header_size + (header.header_checksum << 8)
        else:
            header_size = header.header_size + PADDING_LEN

        file.seek(-len(header), io.SEEK_CUR)
        file.read(header_size + header.compressed_size)
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

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
