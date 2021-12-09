import io
import statistics
from typing import List, Optional

from structlog import get_logger

from ...file_utils import find_first, get_endian
from ...iter_utils import get_intervals
from ...models import Handler, StructHandler, ValidChunk

logger = get_logger()


class UBIFSHandler(StructHandler):
    NAME = "ubifs"

    _BIG_ENDIAN_MAGIC = 0x06_10_18_31

    # TODO: At the moment, we only match on the UBIFS superblock. Do we also want to account for
    # cases where the first node isn't a UBIFS superblock? Would such a layout actually be valid?
    # It might be valid to be flagged, but not necessarily to be extracted.
    #
    # Since we are running the handlers against every single match, regardless of whether a
    # previous chunk has already been established. That means that, for example, if we find a
    # superblock, and then many other kinds of nodes, it will take forever to run caculate_chunk()
    # against all the other nodes, and we waste loads of time and resources.

    YARA_RULE = r"""
        strings:
            // magic (4 bytes), 16 bytes, node type (1 byte, 0x06 is superblock),
            // group type (1 byte), 2 nulls.
            $ubifs_superblock_magic_le = { 31 18 10 06 [16] 06 ( 00 | 01 | 02 ) 00 00 }
            $ubifs_superblock_magic_be = { 06 10 18 31 [16] 06 ( 00 | 01 | 02 ) 00 00 }
        condition:
            $ubifs_superblock_magic_le or $ubifs_superblock_magic_be
    """

    C_DEFINITIONS = r"""
        typedef uint64 __le64;
        typedef uint32 __le32;
        typedef uint16 __le16;
        typedef uint8 __u8;

        #define UBIFS_MAX_HASH_LEN 64
        #define UBIFS_MAX_HMAC_LEN 64

        struct ubifs_ch {
            __le32 magic;
            __le32 crc;
            __le64 sqnum;
            __le32 len;
            __u8 node_type;
            __u8 group_type;
            __u8 padding[2];
        };

        struct ubifs_sb_node {
            struct ubifs_ch ch;
            __u8 padding[2];
            __u8 key_hash;
            __u8 key_fmt;
            __le32 flags;
            __le32 min_io_size;
            __le32 leb_size;
            __le32 leb_cnt;
            __le32 max_leb_cnt;
            __le64 max_bud_bytes;
            __le32 log_lebs;
            __le32 lpt_lebs;
            __le32 orph_lebs;
            __le32 jhead_cnt;
            __le32 fanout;
            __le32 lsave_cnt;
            __le32 fmt_version;
            __le16 default_compr;
            __u8 padding1[2];
            __le32 rp_uid;
            __le32 rp_gid;
            __le64 rp_size;
            __le32 time_gran;
            __u8 uuid[16];
            __le32 ro_compat_version;
            __u8 hmac[UBIFS_MAX_HMAC_LEN];
            __u8 hmac_wkm[UBIFS_MAX_HMAC_LEN];
            __le16 hash_algo;
            __u8 hash_mst[UBIFS_MAX_HASH_LEN];
            __u8 padding2[3774];
        };
    """
    HEADER_STRUCT = "ubifs_sb_node"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        endian = get_endian(file, self._BIG_ENDIAN_MAGIC)
        sb_header = self.parse_header(file, endian)

        # At the moment we are only matching on superblock nodes, so we can get the size of the
        # chunk from the LEB size * LEB count.
        ubifs_length = sb_header.leb_size * sb_header.leb_cnt

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + ubifs_length,
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["ubireader_extract_files", inpath, "-o", outdir]


class PEBSizeNotFound(Exception):
    """Raised when we couldn't found the PEB size for UBI."""


class UBIHandler(Handler):
    NAME = "ubi"

    _UBI_EC_HEADER = b"UBI#"

    YARA_RULE = r"""
        strings:
            $ubi_magic = { 55 42 49 23 01 }  // UBI# and version 1
        condition:
            $ubi_magic
    """

    def _guess_peb_size(self, file: io.BufferedIOBase) -> int:
        # Since we don't know the PEB size, we need to guess it. At the moment we just find the
        # most common interval between every erase block header we find in the image. This _might_
        # cause an issue if we had a blob containing multiple UBI images, with different PEB sizes.
        all_ubi_eraseblock_offsets = []
        while True:
            offset = find_first(file, self._UBI_EC_HEADER)
            if offset == -1:
                break
            all_ubi_eraseblock_offsets.append(offset)

        offset_intervals = get_intervals(all_ubi_eraseblock_offsets)
        if not offset_intervals:
            raise PEBSizeNotFound

        return statistics.mode(offset_intervals)

    def _walk_ubi(self, file: io.BufferedIOBase, peb_size: int) -> int:
        """Walk from the start_offset, at PEB-sized intervals, until we don't hit an erase block."""
        while True:
            offset = file.tell()
            first_bytes = file.read(len(self._UBI_EC_HEADER))
            if first_bytes == b"" or first_bytes != self._UBI_EC_HEADER:
                break
            file.seek(offset + peb_size)

        return offset

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        try:
            peb_size = self._guess_peb_size(file)
        except PEBSizeNotFound:
            return

        logger.debug("Guessed UBI PEB size", size=peb_size)

        file.seek(start_offset)
        # We don't want to parse headers, because we don't know what third party tools are doing,
        # and it would be too expensive to validate the CRC and/or calculate all of the headers
        # This is good enough and way faster than parsing headers
        end_offset = self._walk_ubi(file, peb_size)

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["ubireader_extract_images", inpath, "-o", outdir]
