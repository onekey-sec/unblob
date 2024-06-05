import shutil
import statistics
from pathlib import Path
from typing import Optional

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import InvalidInputFormat, SeekError, get_endian, iterate_patterns
from ...iter_utils import get_intervals
from ...models import File, Handler, HexString, StructHandler, ValidChunk

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

    # magic (4 bytes), 16 bytes, node type (1 byte, 0x06 is superblock),
    # group type (1 byte), 2 nulls.
    PATTERNS = [
        HexString("31 18 10 06 [16] 06 ( 00 | 01 | 02 ) 00 00"),  # LE
        HexString("06 10 18 31 [16] 06 ( 00 | 01 | 02 ) 00 00"),  # BE
    ]

    C_DEFINITIONS = r"""
        typedef struct ubifs_ch {
            uint32 magic;
            uint32 crc;
            uint64 sqnum;
            uint32 len;
            uint8 node_type;
            uint8 group_type;
            uint8 padding[2];
        } ubifs_ch_t;

        typedef struct ubifs_sb_node {
            ubifs_ch_t ch;
            uint8 padding[2];
            uint8 key_hash;
            uint8 key_fmt;
            uint32 flags;
            uint32 min_io_size;
            uint32 leb_size;
            uint32 leb_cnt;
            uint32 max_leb_cnt;
            uint64 max_bud_bytes;
            uint32 log_lebs;
            uint32 lpt_lebs;
            uint32 orph_lebs;
            uint32 jhead_cnt;
            uint32 fanout;
            uint32 lsave_cnt;
            uint32 fmt_version;
            uint16 default_compr;
            uint8 padding1[2];
            uint32 rp_uid;
            uint32 rp_gid;
            uint64 rp_size;
            uint32 time_gran;
            uint8 uuid[16];
            uint32 ro_compat_version;
            uint8 hmac[64];
            uint8 hmac_wkm[64];
            uint16 hash_algo;
            uint8 hash_mst[64];
            uint8 padding2[3774];
        } ubifs_sb_node_t;
    """
    HEADER_STRUCT = "ubifs_sb_node_t"

    EXTRACTOR = Command("ubireader_extract_files", "{inpath}", "-w", "-o", "{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        endian = get_endian(file, self._BIG_ENDIAN_MAGIC)
        sb_header = self.parse_header(file, endian)

        # At the moment we are only matching on superblock nodes, so we can get the size of the
        # chunk from the LEB size * LEB count.
        ubifs_length = sb_header.leb_size * sb_header.leb_cnt

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + ubifs_length,
        )


class UBIExtractor(Command):
    def extract(self, inpath: Path, outdir: Path):
        super().extract(inpath, outdir)
        # ubireader_extract_images creates a superfluous directory named
        # after the UBI file (inpath here), so we simply move the files up
        # and delete the remaining directory.
        superfluous_dir_path = outdir.joinpath(inpath.name)
        for file_path in superfluous_dir_path.iterdir():
            shutil.move(file_path.as_posix(), outdir.as_posix())
        shutil.rmtree(superfluous_dir_path.as_posix())


class UBIHandler(Handler):
    NAME = "ubi"

    _UBI_EC_HEADER = b"UBI#"

    PATTERNS = [HexString("55 42 49 23 01  // UBI# and version 1")]

    EXTRACTOR = UBIExtractor("ubireader_extract_images", "{inpath}", "-o", "{outdir}")

    def _guess_peb_size(self, file: File) -> int:
        # Since we don't know the PEB size, we need to guess it. At the moment we just find the
        # most common interval between every erase block header we find in the image. This _might_
        # cause an issue if we had a blob containing multiple UBI images, with different PEB sizes.
        all_ubi_eraseblock_offsets = list(iterate_patterns(file, self._UBI_EC_HEADER))

        offset_intervals = get_intervals(all_ubi_eraseblock_offsets)
        if not offset_intervals:
            raise InvalidInputFormat

        return statistics.mode(offset_intervals)

    def _walk_ubi(self, file: File, peb_size: int) -> int:
        """Walk from the start_offset, at PEB-sized intervals, until we don't hit an erase block."""
        while True:
            offset = file.tell()
            first_bytes = file.read(len(self._UBI_EC_HEADER))
            if first_bytes == b"" or first_bytes != self._UBI_EC_HEADER:
                break
            try:
                file.seek(offset + peb_size)
            except SeekError:
                break
        return offset

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        peb_size = self._guess_peb_size(file)

        logger.debug("Guessed UBI PEB size", size=peb_size)

        file.seek(start_offset)
        # We don't want to parse headers, because we don't know what third party tools are doing,
        # and it would be too expensive to validate the CRC and/or calculate all of the headers
        # This is good enough and way faster than parsing headers
        end_offset = self._walk_ubi(file, peb_size)

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
