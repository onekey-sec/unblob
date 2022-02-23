import io
from typing import List, Optional

from structlog import get_logger

from ...models import StructHandler, ValidChunk

logger = get_logger()


F_H_FILTER = 0x00000800


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
        } lzo_header_filter_t;

        typedef struct lzo_size_crc {
            uint32 original_crc;        // (CRC32 if flags & F_H_CRC32 else Adler32)
            uint32 uncompressed_size;
            uint32 compressed_size;
            uint32 uncompressed_crc;
            uint32 compressed_crc;      // (only if flags & F_ADLER32_C or flags & F_CRC32_C)
        } lzo_size_crc_t;
    """
    HEADER_STRUCT = "lzo_header"

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

        size_crc_header = self.cparser_be.lzo_size_crc_t(file)
        logger.debug("CRC header parsed", header=size_crc_header, _verbosity=3)

        end_offset = (
            len(header) + len(size_crc_header) + size_crc_header.compressed_size
        )

        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + end_offset
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["lzop", "-d", "-f", "-N", f"-p{outdir}", inpath]
