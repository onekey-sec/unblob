import io
from typing import Optional

from structlog import get_logger

from unblob.extractors.command import Command

from ....file_utils import Endian
from ....models import File, Regex, StructHandler, ValidChunk

logger = get_logger()

CHUNK_TYPE_RAW = 0xCAC1
CHUNK_TYPE_FILL = 0xCAC2
CHUNK_TYPE_DONT_CARE = 0xCAC3
CHUNK_TYPE_CRC32 = 0xCAC4

VALID_CHUNK_TYPES = [
    CHUNK_TYPE_RAW,
    CHUNK_TYPE_FILL,
    CHUNK_TYPE_DONT_CARE,
    CHUNK_TYPE_CRC32,
]


class SparseHandler(StructHandler):
    NAME = "sparse"

    # magic (0xed26ff3a)
    # major version (0x1)
    # minor version (any)
    # file header size (0x1C in v1.0)
    # chunk header size (0XC in v1.0)
    PATTERNS = [Regex(r"\x3A\xFF\x26\xED\x01\x00[\x00-\xFF]{2}\x1C\x00\x0C\x00")]

    C_DEFINITIONS = r"""
        typedef struct sparse_header {
            uint32 magic;          /* 0xed26ff3a */
            uint16 major_version;  /* (0x1) - reject images with higher major versions */
            uint16 minor_version;  /* (0x0) - allow images with higer minor versions */
            uint16 file_hdr_sz;    /* 28 bytes for first revision of the file format */
            uint16 chunk_hdr_sz;   /* 12 bytes for first revision of the file format */
            uint32 blk_sz;         /* block size in bytes, must be a multiple of 4 (4096) */
            uint32 total_blks;     /* total blocks in the non-sparse output image */
            uint32 total_chunks;   /* total chunks in the sparse input image */
            uint32 image_checksum; /* CRC32 checksum of the original data, counting "don't care" */
                                    /* as 0. Standard 802.3 polynomial, use a Public Domain */
                                    /* table implementation */
        } sparse_header_t;

        typedef struct chunk_header {
            uint16 chunk_type; /* 0xCAC1 -> raw; 0xCAC2 -> fill; 0xCAC3 -> don't care */
            uint16 reserved1;
            uint32 chunk_sz; /* in blocks in output image */
            uint32 total_sz; /* in bytes of chunk input file including chunk header and data */
        } chunk_header_t;
    """
    HEADER_STRUCT = "sparse_header_t"

    EXTRACTOR = Command("simg2img", "{inpath}", "{outdir}/raw.image")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, Endian.LITTLE)

        count = 0
        while count < header.total_chunks:
            chunk_header = self.cparser_le.chunk_header_t(file)
            if chunk_header.chunk_type not in VALID_CHUNK_TYPES:
                logger.warning("Invalid chunk type in Android sparse image. Aborting.")
                return None
            file.seek(chunk_header.total_sz - len(chunk_header), io.SEEK_CUR)
            count += 1

        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.tell(),
        )
