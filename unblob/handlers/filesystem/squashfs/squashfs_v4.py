import io
from typing import List, Union

from dissect.cstruct import cstruct
from structlog import get_logger

from ....file_utils import round_up
from ....models import UnknownChunk, ValidChunk

logger = get_logger()

NAME = "squashfs_v4"

YARA_RULE = r"""
    strings:
        /**
        00000000  68 73 71 73 03 00 00 00  00 c1 9c 61 00 00 02 00  |hsqs.......a....|
        00000010  01 00 00 00 01 00 11 00  c0 00 01 00 04 00 00 00  |................|
        */
        $squashfs_v4_magic_le = { 68 73 71 73 [24] 04 00 }
    condition:
        $squashfs_v4_magic_le
"""
YARA_MATCH_OFFSET = 0

# Default endianness is LE
cparser = cstruct()
cparser.load(
    """
struct SQUASHFS4_SUPER_BLOCK
{
    char   s_magic[4];
    uint32 inodes;
    uint32 mkfs_time /* time of filesystem creation */;
    uint32 block_size;
    uint32 fragments;
    uint16 compression;
    uint16 block_log;
    uint16  flags;
    uint16  no_ids;
    uint16 s_major;
    uint16 s_minor;
    uint64 root_inode;
    int64  bytes_used;
    int64  id_table_start;
    int64  xattr_id_table_start;
    int64  inode_table_start;
    int64  directory_table_start;
    int64  fragment_table_start;
    int64  lookup_table_start;
};
"""
)

PAD_SIZE = 4096


def calculate_chunk(
    file: io.BufferedIOBase, start_offset: int
) -> Union[ValidChunk, UnknownChunk]:
    header = cparser.SQUASHFS4_SUPER_BLOCK(file)
    logger.debug("Header parsed", header=header)
    size = round_up(header.bytes_used, PAD_SIZE)
    end_offset = start_offset + size

    return ValidChunk(start_offset=start_offset, end_offset=end_offset)


def make_extract_command(inpath: str, outdir: str) -> List[str]:
    return ["unsquashfs", "-f", "-d", outdir, inpath]
