import io
import struct
from typing import List, Union

from dissect.cstruct import cstruct

from ....models import UnknownChunk, ValidChunk

NAME = "squashfs_v3"

YARA_RULE = r"""
    strings:
        /**
        00000000  73 71 73 68 00 00 00 03  00 00 00 00 00 00 00 00  |sqsh............|
        00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 03 00 00  |................|
        */
        $squashfs_v3_magic_be = { 73 71 73 68 [24] 00 03}
        /**
        00000000  68 73 71 73 03 00 00 00  00 00 00 00 00 00 00 00  |hsqs............|
        00000010  00 00 00 00 00 00 00 00  00 00 00 00 03 00 00 00  |................|
        */
        $squashfs_v3_magic_le = { 68 73 71 73 [24] 03 00}
    condition:
        $squashfs_v3_magic_le or $squashfs_v3_magic_be
"""
YARA_MATCH_OFFSET = 0

cparser = cstruct()
cparser.load(
    """
struct SQUASHFS3_SUPER_BLOCK
{
    char   s_magic[4];
    uint32 inodes;
    uint32 bytes_used_2;
    uint32 uid_start_2;
    uint32 guid_start_2;
    uint32 inode_table_start_2;
    uint32 directory_table_start_2;
    uint16 s_major;
    uint16 s_minor;
    uint16 block_size_1;
    uint16 block_log;
    uint8  flags;
    uint8  no_uids;
    uint8  no_guids;
    uint32 mkfs_time /* time of filesystem creation */;
    uint64 root_inode;
    uint32 block_size;
    uint32 fragments;
    uint32 fragment_table_start_2;
    int64  bytes_used;
    int64  uid_start;
    int64  guid_start;
    int64  inode_table_start;
    int64  directory_table_start;
    int64  fragment_table_start;
    int64  lookup_table_start;
};
"""
)

PAD_SIZE = 4096
BIG_ENDIAN_MAGIC = 0x73717368


def calculate_chunk(
    file: io.BufferedIOBase, start_offset: int
) -> Union[ValidChunk, UnknownChunk]:

    # read the magic and derive endianness from it
    magic_bytes = file.read(4)
    magic = struct.unpack(">I", magic_bytes)[0]

    is_big_endian = magic == BIG_ENDIAN_MAGIC
    cparser.endian = ">" if is_big_endian else "<"

    file.seek(start_offset)
    header = cparser.SQUASHFS3_SUPER_BLOCK(file)

    # the actual size is padded to 4KiB
    size = (1 + header.bytes_used // PAD_SIZE) * PAD_SIZE
    end_offset = start_offset + size

    return ValidChunk(start_offset=start_offset, end_offset=end_offset)


def make_extract_command(inpath: str, outdir: str) -> List[str]:
    return ["unsquashfs", "-f", "-d", outdir, inpath]
