import io
import struct
from typing import List, Union

from dissect.cstruct import cstruct

from ....models import UnknownChunk, ValidChunk

NAME = "ext"

#TODO: handle big endian ?
YARA_RULE = r"""
    strings:
        $magic_le = {{ 53 ef ( 01 | 02 ) 00 ( 00 | 01 | 02 | 03 | 04 ) 00 }} // little endian
    condition:
        $magic_le
"""
YARA_MATCH_OFFSET = -0x38

EXTFS_HEADER = """
struct ext4_superblock {
    char blank[0x400];              // Not a part of the spec. But we expect the magic to be at 0x438. 
    uint32 s_inodes_count;          // Total number of inodes in file system
    uint32 s_blocks_count_lo;       // Total number of blocks in file system
    uint32 s_r_blocks_count_lo;     // Number of blocks reserved for superuser (see offset 80)
    uint32 s_free_blocks_count_lo;  // Total number of unallocated blocks
    uint32 s_free_inodes_count;     // Total number of unallocated inodes
    uint32 s_first_data_block;      // Block number of the block containing the superblock
    uint32 s_log_block_size;        // log2 (block size) - 10  (In other words, the number to shift 1,024 to the left by to obtain the block size)
    uint32 s_log_cluster_size;      // log2 (fragment size) - 10. (In other words, the number to shift 1,024 to the left by to obtain the fragment size)
    uint32 s_blocks_per_group;      // Number of blocks in each block group
    uint32 s_clusters_per_group;    // Number of fragments in each block group
    uint32 s_inodes_per_group;      // Number of inodes in each block group
    uint32 s_mtime;                 // Last mount time
    uint32 s_wtime;                 // Last written time
    uint16 s_mnt_count;             // Number of times the volume has been mounted since its last consistency check
    uint16 s_max_mnt_count;         // Number of mounts allowed before a consistency check must be done
    uint16 s_magic;                 // Ext signature (0xef53), used to help confirm the presence of Ext2 on a volume
    uint16 s_state;                 // File system state (0x1 - clean or 0x2 - has errors)
    uint16 s_errors;                // What to do when an error is detected (ignore/remount/kernel panic)
    uint16 s_minor_rev_level;       // Minor portion of version (combine with Major portion below to construct full version field)
    uint32 s_lastcheck;             // time of last consistency check
    uint32 s_checkinterval;         // Interval between forced consistency checks
    uint32 s_creator_os;            // Operating system ID from which the filesystem on this volume was created
    uint32 s_rev_level;             // Major portion of version (combine with Minor portion above to construct full version field)
    uint16 s_def_resuid;            // User ID that can use reserved blocks
    uint16 s_def_resgid;            // Group ID that can use reserved blocks    
}
"""
cparser_le = cstruct()
cparser_le.load(EXTFS_HEADER)

cparser_be = cstruct(endian=">")
cparser_be.load(EXTFS_HEADER)

PAD_SIZE = 4096

# TODO
# BIG_ENDIAN_MAGIC = 0x73717368

FIRST_BLOCKSIZE = 0x400
EXTFS_BLOCKSIZE = 0x400

OS_LIST = [
    (0x0, "Linux"),
    (0x1, "GNU HURD"),
    (0x2, "MASIX"),
    (0x3, "FreeBSD"),
    (0x4, "Other"), # Other "Lites" (BSD4.4-Lite derivatives such as NetBSD, OpenBSD, XNU/Darwin, etc.)
]


def calculate_chunk(
    file: io.BufferedIOBase, start_offset: int
) -> Union[ValidChunk, UnknownChunk]:

    # read the magic and derive endianness from it
    file.seek(abs())
    magic_bytes = file.read(4)
    magic = struct.unpack(">I", magic_bytes)[0]
    cparser = cparser_be if magic == BIG_ENDIAN_MAGIC else cparser_le

    file.seek(start_offset)

    magic_bytes = file.read(4)
    magic = struct.unpack(">I", magic_bytes)[0]
    cparser = cparser_be if magic == BIG_ENDIAN_MAGIC else cparser_le

    file.seek(start_offset)
    header = cparser.SQUASHFS3_SUPER_BLOCK(file)

    # the actual size is padded to 4KiB
    size = (1 + header.bytes_used // PAD_SIZE) * PAD_SIZE
    end_offset = start_offset + size

    return ValidChunk(start_offset=start_offset, end_offset=end_offset)


def make_extract_command(inpath: str, outdir: str) -> List[str]:
    return ["unsquashfs", "-f", "-d", outdir, inpath]
