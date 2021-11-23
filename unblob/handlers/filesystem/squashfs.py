import io
import struct
from typing import List, Union

from dissect.cstruct import cstruct

from ...models import UnknownChunk, ValidChunk

NAME = "squashfs"

YARA_RULE = r"""
    strings:
        $squashfs_magic_be = { 73 71 73 68 }
        $squashfs_magic_le = { 68 73 71 73 }
    condition:
        $squashfs_magic_le or $squashfs_magic_be
"""

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
    file: io.BufferedReader, start_offset: int
) -> Union[ValidChunk, UnknownChunk]:

    # read the magic and derive endianness from it
    magic = struct.unpack("I", file.read(4))[0]
    is_big_endian = magic == 0x68737173

    # read the major version (same offset regardless of version)
    file.seek(start_offset + 28)
    if is_big_endian:
        major_version = struct.unpack(">H", file.read(2))[0]
    else:
        major_version = struct.unpack("H", file.read(2))[0]

    # reset the cursor
    file.seek(start_offset)

    # adjust endianness of our parser
    cparser.endian = ">" if is_big_endian else "<"

    # header parsing
    if major_version == 3:
        header = cparser.SQUASHFS3_SUPER_BLOCK(file)
    elif major_version == 4:
        header = cparser.SQUASHFS4_SUPER_BLOCK(file)
    else:
        return UnknownChunk(
            start_offset=start_offset, reason="Unsupported squashfs version"
        )

    # the actual size is padded to 4KiB
    size = (1 + header.bytes_used // PAD_SIZE) * PAD_SIZE
    end_offset = start_offset + size

    return ValidChunk(
        start_offset=start_offset,
        end_offset=end_offset,
    )


def make_extract_command(inpath: str, outdir: str) -> List[str]:
    return ["unsquashfs", "-f", "-d", outdir, inpath]
