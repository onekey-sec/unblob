import binascii
import io
from math import ceil

from unblob.extractors import Command
from unblob.file_utils import File, InvalidInputFormat, get_endian_short
from unblob.models import (
    HandlerDoc,
    HandlerType,
    Reference,
    Regex,
    StructHandler,
    ValidChunk,
)

C_DEFINITIONS = r"""
    typedef struct partclone_header{
        char magic[16];
        char partclone_version[14];
        char image_version_txt[4];
        char endian[2];
        char fs_type[16];
        uint64 fs_size;
        uint64 fs_total_block_count;
        uint64 fs_used_block_count_superblock;
        uint64 fs_used_block_count_bitmap;
        uint32 fs_block_size;
        uint32 feature_size;
        uint16 image_version;
        uint16 number_of_bits_for_CPU;
        uint16 checksum_mode;
        uint16 checksum_size;
        uint32 blocks_per_checksum;
        uint8 reseed_checksum;
        uint8 bitmap_mode;
        uint32 crc32;
    } partclone_header_t;
"""

HEADER_STRUCT = "partclone_header_t"
BIG_ENDIAN_MAGIC = 0xC0DE
ENDIAN_OFFSET = 34


class PartcloneHandler(StructHandler):
    NAME = "partclone"
    PATTERNS = [Regex(r"partclone-image\x00\d+\.\d+\.\d+.*?0002(\xde\xc0|\xc0\xde)")]
    HEADER_STRUCT = HEADER_STRUCT
    C_DEFINITIONS = C_DEFINITIONS
    EXTRACTOR = Command(
        "partclone.restore",
        "-W",
        "-s",
        "{inpath}",
        "-o",
        "{outdir}/partclone.restored",
        "-L",
        "/dev/stdout",
    )
    DOC = HandlerDoc(
        name="Partclone",
        description="Partclone is a utility used for backing up and restoring partitions. Many cloning tools (such as Clonezilla) rely on it to create block-level images that include filesystem metadata.",
        handler_type=HandlerType.ARCHIVE,
        vendor=None,
        references=[
            Reference(
                title="Partclone GitHub Repository",
                url="https://github.com/Thomas-Tsai/partclone",
            ),
            Reference(
                title="Clonezilla Official Documentation",
                url="https://clonezilla.org/",
            ),
        ],
        limitations=[],
    )

    def is_valid_header(self, header) -> bool:
        calculated_crc = binascii.crc32(header.dumps()[0:-4])
        return (
            header.crc32 ^ 0xFFFFFFFF
        ) == calculated_crc  # partclone does not final XOR

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(start_offset + ENDIAN_OFFSET, io.SEEK_SET)  # go to endian
        endian = get_endian_short(file, BIG_ENDIAN_MAGIC)
        file.seek(start_offset, io.SEEK_SET)  # go to beginning of file
        header = self.parse_header(file, endian)

        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid partclone header.")

        end_offset = start_offset + len(header)  # header
        end_offset += header.checksum_size  # checksum size
        end_offset += ceil(header.fs_total_block_count / 8)  # bitmap, as bytes

        if header.checksum_mode != 0:
            checksum_blocks = ceil(
                header.fs_used_block_count_bitmap / header.blocks_per_checksum
            )
            end_offset += checksum_blocks * header.checksum_size

        end_offset += header.fs_used_block_count_bitmap * header.fs_block_size  # Data
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
