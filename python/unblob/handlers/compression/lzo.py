import io
import zlib
from enum import IntEnum
from typing import Optional

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import Endian, convert_int32
from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()

MAGIC_LENGTH = 9
CHECKSUM_LENGTH = 4


# Header flags defined in lzop (http://www.lzop.org/) source in src/conf.h
class HeaderFlags(IntEnum):
    ADLER32_D = 0x00000001
    ADLER32_C = 0x00000002
    STDIN = 0x00000004
    STDOUT = 0x00000008
    NAME_DEFAULT = 0x00000010
    DOSISH = 0x00000020
    H_EXTRA_FIELD = 0x00000040
    H_GMTDIFF = 0x00000080
    CRC32_D = 0x00000100
    CRC32_C = 0x00000200
    MULTIPART = 0x00000400
    H_FILTER = 0x00000800
    H_CRC32 = 0x00001000
    H_PATH = 0x00002000


class LZOHandler(StructHandler):
    NAME = "lzo"

    PATTERNS = [HexString("89 4C 5A 4F 00 0D 0A 1A 0A")]

    C_DEFINITIONS = r"""
        typedef struct lzo_header_no_filter
        {
            char magic[9];
            uint16 version;
            uint16 libversion;
            uint16 reqversion;
            uint8 method;
            uint8 level;
            uint32 flags;
            //uint32 filter;              // only if flags & F_H_FILTER
            uint32 mode;
            uint32 mtime;
            uint32 gmtdiff;
            uint8 filename_len;
            char filename[filename_len];
            uint32 header_checksum;        // (CRC32 if flags & F_H_CRC32 else Adler32)
        } lzo_header_no_filter_t;

        typedef struct lzo_header_filter
        {
            char magic[9];
            uint16 version;
            uint16 libversion;
            uint16 reqversion;
            uint8 method;
            uint8 level;
            uint32 flags;
            uint32 filter;              // only if flags & F_H_FILTER
            uint32 mode;
            uint32 mtime;
            uint32 gmtdiff;
            uint8 filename_len;
            char filename[filename_len];
            uint32 header_checksum;        // (CRC32 if flags & F_H_CRC32 else Adler32)
        } lzo_header_filter_t;
    """
    HEADER_STRUCT = "lzo_header"

    EXTRACTOR = Command("lzop", "-d", "-f", "-f", "-N", "-p{outdir}", "{inpath}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.cparser_be.lzo_header_no_filter_t(file)
        # maxmimum compression level is 9
        if header.level > 9:
            logger.debug("Invalid LZO header level", header=header, _verbosity=3)
            return None

        if header.flags & HeaderFlags.H_FILTER:
            file.seek(start_offset)
            header = self.cparser_be.lzo_header_filter_t(file)

        logger.debug("LZO header parsed", header=header, _verbosity=3)

        # Checksum excludes the magic and the checksum itself
        if header.flags & HeaderFlags.H_CRC32:
            calculated_checksum = zlib.crc32(
                header.dumps()[MAGIC_LENGTH:-CHECKSUM_LENGTH]
            )
        else:
            calculated_checksum = zlib.adler32(
                header.dumps()[MAGIC_LENGTH:-CHECKSUM_LENGTH]
            )

        if header.header_checksum != calculated_checksum:
            logger.debug("Header checksum verification failed")
            return None

        uncompressed_size = convert_int32(file.read(4), endian=Endian.BIG)
        while uncompressed_size:
            compressed_size = convert_int32(file.read(4), endian=Endian.BIG)

            checksum_size = 0
            if (
                header.flags & HeaderFlags.ADLER32_D
                or header.flags & HeaderFlags.CRC32_D
            ):
                checksum_size += CHECKSUM_LENGTH

            if (
                header.flags & HeaderFlags.ADLER32_C
                or header.flags & HeaderFlags.CRC32_C
            ):
                checksum_size += CHECKSUM_LENGTH

            file.seek(checksum_size + compressed_size, io.SEEK_CUR)
            uncompressed_size = convert_int32(file.read(4), endian=Endian.BIG)

        end_offset = file.tell()

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
