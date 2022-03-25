import io
from typing import Optional

from structlog import get_logger

from unblob.extractors import Command

from ...file_utils import Endian, convert_int32
from ...models import StructHandler, ValidChunk

logger = get_logger()

CHECKSUM_LENGTH = 4

# Header flags defined in lzop (http://www.lzop.org/) source in src/conf.h
F_ADLER32_D = 0x00000001  # noqa
F_ADLER32_C = 0x00000002  # noqa
F_STDIN = 0x00000004  # noqa
F_STDOUT = 0x00000008  # noqa
F_NAME_DEFAULT = 0x00000010  # noqa
F_DOSISH = 0x00000020  # noqa
F_H_EXTRA_FIELD = 0x00000040  # noqa
F_H_GMTDIFF = 0x00000080  # noqa
F_CRC32_D = 0x00000100  # noqa
F_CRC32_C = 0x00000200  # noqa
F_MULTIPART = 0x00000400  # noqa
F_H_FILTER = 0x00000800  # noqa
F_H_CRC32 = 0x00001000  # noqa
F_H_PATH = 0x00002000  # noqa


class LZOHandler(StructHandler):
    NAME = "lzo"

    YARA_RULE = r"""
        strings:
            $lzo_magic = { 89 4C 5A 4F 00 0D 0A 1A 0A }
        condition:
            $lzo_magic
    """

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

    EXTRACTOR = Command("lzop", "-d", "-f", "-N", "-p{outdir}", "{inpath}")

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        header = self.cparser_be.lzo_header_no_filter_t(file)
        # maxmimum compression level is 9
        if header.level > 9:
            logger.debug("Invalid LZO header level", header=header, _verbosity=3)
            return

        if header.flags & F_H_FILTER:
            file.seek(start_offset)
            header = self.cparser_be.lzo_header_filter_t(file)

        logger.debug("LZO header parsed", header=header, _verbosity=3)

        uncompressed_size = convert_int32(file.read(4), endian=Endian.BIG)
        while uncompressed_size:
            compressed_size = convert_int32(file.read(4), endian=Endian.BIG)

            checksum_size = 0
            if header.flags & F_ADLER32_D or header.flags & F_CRC32_D:
                checksum_size += CHECKSUM_LENGTH

            if header.flags & F_ADLER32_C or header.flags & F_CRC32_C:
                checksum_size += CHECKSUM_LENGTH

            file.seek(checksum_size + compressed_size, io.SEEK_CUR)
            uncompressed_size = convert_int32(file.read(4), endian=Endian.BIG)

        end_offset = file.tell()

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
