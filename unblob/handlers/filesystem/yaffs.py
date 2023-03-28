import io
import math
from enum import IntEnum
from typing import Optional

import attr
from dissect.cstruct import Instance
from structlog import get_logger

from unblob.file_utils import (
    Endian,
    InvalidInputFormat,
    get_endian,
    read_until_past,
    snull,
)

from ...extractors import Command
from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()

VALID_PAGE_SIZES = [512, 1024, 2048, 4096, 8192, 16384]
VALID_SPARE_SIZES = [512, 256, 128, 64, 32, 16]


class YAFFS_OBJECT_TYPE(IntEnum):
    UNKNOWN = 0
    FILE = 1
    SYMLINK = 2
    DIRECTORY = 3
    HARDLINK = 4
    SPECIAL = 5


@attr.define
class YAFFSConfig:
    endian: Endian
    page_size: int
    spare_size: int


def decode_file_size(high: int, low: int) -> int:
    """File size can be encoded as 64 bits or 32 bits values.
    If upper 32 bits are set, it's a 64 bits integer value.
    Otherwise it's a 32 bits value. 0xFFFFFFFF means zero.
    """
    if high != 0xFFFFFFFF:
        return (high << 32) | (low & 0xFFFFFFFF)

    if low != 0xFFFFFFFF:
        return low

    return 0


def valid_name(name: bytes) -> bool:
    # a valid name is either full of null bytes, or unicode decodable
    try:
        snull(name[:-1]).decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


class _YAFFSBase(StructHandler):
    C_DEFINITIONS = """
        struct yaffs_file_var {
            uint32 file_size;
            uint32 stored_size;
            uint32 shrink_size;
            int top_level;
        };


        typedef struct yaffs_obj_hdr {
            uint32 type;                   /* enum yaffs_obj_type  */
            /* Apply to everything  */
            uint32 parent_obj_id;
            uint16 sum_no_longer_used;	    /* checksum of name. No longer used */
            char name[256];
            uint16 chksum;
            /* The following apply to all object types except for hard links */
            uint32 yst_mode;		        /* protection */
            uint32 yst_uid;
            uint32 yst_gid;
            uint32 yst_atime;
            uint32 yst_mtime;
            uint32 yst_ctime;
            uint32 file_size_low;          /* File size  applies to files only */
            int equiv_id;               /* Equivalent object id applies to hard links only. */
            char alias[160];    /* Alias is for symlinks only. */

            uint32 yst_rdev;	            /* stuff for block and char devices (major/min) */

            uint32 win_ctime[2];
            uint32 win_atime[2];
            uint32 win_mtime[2];

            uint32 inband_shadowed_obj_id;
            uint32 inband_is_shrink;
            uint32 file_size_high;
            uint32 reserved[1];
            int shadows_obj;	    /* This object header shadows the specified object if > 0 */
            /* is_shrink applies to object headers written when we make a hole. */
            uint32 is_shrink;
            yaffs_file_var filehead;
        } yaffs_obj_hdr_t;
    """

    HEADER_STRUCT = "yaffs_obj_hdr_t"

    EXTRACTOR = Command("yaffshiv", "-b", "-d", "{outdir}", "-f", "{inpath}")

    BIG_ENDIAN_MAGIC = 0x00_00_00_01

    def is_valid_header(self, header: Instance) -> bool:
        if not valid_name(header.name):
            return False
        if header.sum_no_longer_used != 0xFFFF:
            return False
        if header.chksum != 0xFFFF:
            return False
        return True

    def get_files(self, file: File, start_offset: int, eof: int, config: YAFFSConfig):
        files = 0
        current_offset = start_offset
        while current_offset < eof:
            file.seek(current_offset, io.SEEK_SET)
            try:
                header = self.parse_header(file, config.endian)
                if not self.is_valid_header(header):
                    break
            except EOFError:
                break

            blocks = 1
            if header.type in [
                YAFFS_OBJECT_TYPE.UNKNOWN,
                YAFFS_OBJECT_TYPE.SYMLINK,
                YAFFS_OBJECT_TYPE.DIRECTORY,
                YAFFS_OBJECT_TYPE.HARDLINK,
                YAFFS_OBJECT_TYPE.SPECIAL,
            ]:
                pass
            elif header.type == YAFFS_OBJECT_TYPE.FILE:
                filesize = decode_file_size(header.file_size_high, header.file_size_low)
                files += 1
                # If the object is a file, the data is stored in the page section of
                # the subsequent pages. We calculate, given the filesize, how many
                # more pages we need to skip
                blocks += math.ceil(filesize / config.page_size)
            else:
                break
            current_offset += blocks * (config.page_size + config.spare_size)
        return files, current_offset

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        end_offset = 0
        total_files = 0

        endian = get_endian(file, self.BIG_ENDIAN_MAGIC)

        file.seek(0, io.SEEK_END)
        eof = file.tell()

        for page_size in VALID_PAGE_SIZES:
            for spare_size in VALID_SPARE_SIZES:
                if spare_size > page_size:
                    continue
                config = YAFFSConfig(endian, page_size, spare_size)
                files, offset = self.get_files(file, start_offset, eof, config)
                if files > total_files and offset <= eof:
                    end_offset = offset
                    total_files = files

        # not a single file was found, false positive
        if total_files == 0:
            raise InvalidInputFormat("Invalid YAFFS content.")

        # skip 0xFF padding
        file.seek(end_offset, io.SEEK_SET)
        read_until_past(file, b"\xff")
        return ValidChunk(start_offset=start_offset, end_offset=file.tell())


class YAFFS2Handler(_YAFFSBase):
    NAME = "yaffs2"

    PATTERNS = [
        HexString(
            "01 00 00 00 01 00 00 00 ff ff // LE, Look for YAFFS_OBJECT_TYPE_DIRECTORY with a null name"
        ),
        HexString("00 00 00 01 00 00 00 01 ff ff // BE"),
    ]

    BIG_ENDIAN_MAGIC = 0x00_00_00_01


class YAFFSHandler(_YAFFSBase):
    NAME = "yaffs"

    PATTERNS = [
        HexString(
            "03 00 00 00 01 00 00 00 ff ff // LE, Look for YAFFS_OBJECT_TYPE_DIRECTORY with a null name"
        ),
        HexString("00 00 00 03 00 00 00 01 ff ff // BE"),
    ]

    BIG_ENDIAN_MAGIC = 0x00_00_00_03
