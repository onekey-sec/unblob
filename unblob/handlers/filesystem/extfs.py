from typing import Optional

from structlog import get_logger

from unblob.file_utils import InvalidInputFormat

from ...extractors import Command
from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()


EXT_BLOCK_SIZE = 0x400
MAGIC_OFFSET = 0x438

OS_LIST = [
    (0x0, "Linux"),
    (0x1, "GNU HURD"),
    (0x2, "MASIX"),
    (0x3, "FreeBSD"),
    (
        0x4,
        "Other",
    ),  # Other "Lites" (BSD4.4-Lite derivatives such as NetBSD, OpenBSD, XNU/Darwin, etc.)
]


class EXTHandler(StructHandler):
    NAME = "extfs"

    PATTERNS = [HexString("53 ef ( 00 | 01 | 02 ) 00 ( 00 | 01 | 02 | 03 | 04 ) 00")]

    C_DEFINITIONS = r"""
        typedef struct ext4_superblock {
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
        } ext4_superblock_t;
    """
    HEADER_STRUCT = "ext4_superblock_t"

    PATTERN_MATCH_OFFSET = -MAGIC_OFFSET

    EXTRACTOR = Command("debugfs", "-R", 'rdump / "{outdir}"', "{inpath}")

    def valid_header(self, header) -> bool:
        if header.s_state not in [0x0, 0x1, 0x2]:
            logger.debug("ExtFS header state not valid", state=header.s_state)
            return False
        if header.s_errors not in [0x0, 0x1, 0x2, 0x3]:
            logger.debug(
                "ExtFS header error handling method value not valid",
                errors=header.s_errors,
            )
            return False
        if header.s_creator_os not in [x[0] for x in OS_LIST]:
            logger.debug("Creator OS value not valid.", creator_os=header.s_creator_os)
            return False
        if header.s_rev_level > 2:
            logger.debug(
                "ExtFS header major version too high", rev_level=header.s_rev_level
            )
            return False
        if header.s_log_block_size > 6:
            logger.debug(
                "ExtFS header s_log_block_size is too large",
                s_log_block_size=header.s_log_block_size,
            )
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file)
        end_offset = start_offset + (
            header.s_blocks_count_lo * (EXT_BLOCK_SIZE << header.s_log_block_size)
        )

        if not self.valid_header(header):
            raise InvalidInputFormat("Invalid ExtFS header.")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
