import io
from typing import List, Optional

from structlog import get_logger

from ...file_utils import get_endian, round_up
from ...models import StructHandler, ValidChunk

logger = get_logger()

PAD_SIZES = [4_096, 1_024]


class _SquashFSBase(StructHandler):

    BIG_ENDIAN_MAGIC = 0x73_71_73_68

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["sasquatch", "-no-exit-code", "-f", "-d", outdir, inpath]

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        file.seek(start_offset)
        endian = get_endian(file, self.BIG_ENDIAN_MAGIC)
        header = self.parse_header(file, endian)

        end_of_data_offset = start_offset + header.bytes_used
        file.seek(end_of_data_offset)
        padding = file.read(
            round_up(header.bytes_used, max(PAD_SIZES)) - header.bytes_used
        )

        for pad_size in sorted(PAD_SIZES, reverse=True):
            size = round_up(header.bytes_used, pad_size)
            padding_length = size - header.bytes_used

            if padding.startswith(b"\00" * padding_length):
                end_offset = start_offset + size
                return ValidChunk(start_offset=start_offset, end_offset=end_offset)

        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + header.bytes_used
        )


class SquashFSv3Handler(_SquashFSBase):
    NAME = "squashfs_v3"

    YARA_RULE = r"""
        strings:
            /**
            00000000  73 71 73 68 00 00 00 03  00 00 00 00 00 00 00 00  |sqsh............|
            00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 03 00 00  |................|
            */
            $squashfs_v3_magic_be = { 73 71 73 68 [24] 00 03 }

            /**
            00000000  68 73 71 73 03 00 00 00  00 00 00 00 00 00 00 00  |hsqs............|
            00000010  00 00 00 00 00 00 00 00  00 00 00 00 03 00 00 00  |................|
            */
            $squashfs_v3_magic_le = { 68 73 71 73 [24] 03 00 }

        condition:
            $squashfs_v3_magic_le or
            $squashfs_v3_magic_be
    """

    C_DEFINITIONS = r"""
        typedef struct squashfs3_super_block
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
            uint64  bytes_used;
            uint64  uid_start;
            uint64  guid_start;
            uint64  inode_table_start;
            uint64  directory_table_start;
            uint64  fragment_table_start;
            uint64  lookup_table_start;
        } squashfs3_super_block_t;
    """
    HEADER_STRUCT = "squashfs3_super_block_t"


class SquashFSv3DDWRTHandler(SquashFSv3Handler):
    NAME = "squashfs_v3_ddwrt"

    BIG_ENDIAN_MAGIC = 0x74_71_73_68

    YARA_RULE = r"""
        strings:
            /**
            00000000  68 73 71 74 21 02 00 00  00 00 00 00 00 00 00 00  |hsqt!...........|
            00000010  00 00 00 00 00 00 00 00  50 02 00 00 03 00 00 00  |........P.......|
            */
            $squashfs_v3_magic_ddwrt_le = { 68 73 71 74 [24] 03 00 }

            /**
            00000000  74 71 73 68 21 02 00 00  00 00 00 00 00 00 00 00  |tqsh!...........|
            00000010  00 00 00 00 00 00 00 00  50 02 00 03 00 00 00 00  |........P.......|
            */
            $squashfs_v3_magic_ddwrt_be = { 68 73 71 74 [24] 00 03 }

        condition:
            $squashfs_v3_magic_ddwrt_le or
            $squashfs_v3_magic_ddwrt_be
    """


class SquashFSv3BroadcomHandler(SquashFSv3Handler):
    NAME = "squashfs_v3_broadcom"

    BIG_ENDIAN_MAGIC = 0x71_73_68_73

    YARA_RULE = r"""
        strings:
            /**
            00000000  73 68 73 71 0f 05 00 00  c8 a9 00 01 00 00 00 bc  |shsq............|
            00000010  1f 2d 00 a2 d0 2b 00 bf  79 2e 00 65 03 00 00 00  |.-...+..y..e....|
            */
            $squashfs_v3_magic_broadcom_le = { 73 68 73 71 [24] 03 00}

            /**
            00000000  71 73 68 73 0f 05 00 00  c8 a9 00 01 00 00 00 bc  |qshs............|
            00000010  1f 2d 00 a2 d0 2b 00 bf  79 2e 00 65 00 03 00 00  |.-...+..y..e....|
            */
            $squashfs_v3_magic_broadcom_be = { 71 73 68 73 [24] 00 03 }

        condition:
            $squashfs_v3_magic_broadcom_le or
            $squashfs_v3_magic_broadcom_be
    """


class SquashFSv3NSHandler(SquashFSv3Handler):
    NAME = "squashfs_v3_nonstandard"

    BIG_ENDIAN_MAGIC = 0x73_71_6C_7A

    YARA_RULE = r"""
        strings:
            /**
            00000000  7a 6c 71 73 00 00 04 df  57 00 17 95 46 00 19 ed  |zlqs....W...F...|
            00000010  20 08 04 8e 02 40 01 06  c9 02 16 00 00 03 00 01  | ....@..........|
            */
            $squashfs_v3_magic_nonstandard_le = { 7A 6c 71 73 [24] 03 00 }

            /**
            00000000  73 71 6c 7a 00 00 04 df  57 00 17 95 46 00 19 ed  |sqlz....W...F...|
            00000010  20 08 04 8e 02 40 01 06  c9 02 16 00 00 03 00 01  | ....@..........|
            */
            $squashfs_v3_magic_nonstandard_be = { 73 71 6c 7A [24] 00 03 }

        condition:
            $squashfs_v3_magic_nonstandard_le or
            $squashfs_v3_magic_nonstandard_be
    """


class SquashFSv4LEHandler(_SquashFSBase):
    NAME = "squashfs_v4_le"

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

    C_DEFINITIONS = r"""
        typedef struct squashfs4_super_block
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
            uint64  bytes_used;
            uint64  id_table_start;
            uint64  xattr_id_table_start;
            uint64  inode_table_start;
            uint64  directory_table_start;
            uint64  fragment_table_start;
            uint64  lookup_table_start;
        } squashfs4_super_block_t;
    """
    HEADER_STRUCT = "squashfs4_super_block_t"


class SquashFSv4BEHandler(SquashFSv4LEHandler):
    NAME = "squashfs_v4_be"

    YARA_RULE = r"""
        strings:
            /**
            00000000  73 71 73 68 03 00 00 00  00 c1 9c 61 00 00 02 00  |sqsh.......a....|
            00000010  01 00 00 00 01 00 11 00  c0 00 01 00 04 00 00 00  |................|
            */
            $squashfs_v4_magic_be = { 73 71 73 68 [24] 00 04 }

        condition:
            $squashfs_v4_magic_be
    """

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["sasquatch-v4be", "-be", "-no-exit-code", "-f", "-d", outdir, inpath]
