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
        struct lzo_header_no_filter
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
            /** The filename length is variable and set by filename_len,
            so we don't know what's the exact filename char array length
            at parsing time. Filename parsing is handled in calculate_chunk */
            //char filename[];
        }

        struct lzo_header_filter
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
            /** The filename length is variable and set by filename_len,
            so we don't know what's the exact filename char array length
            at parsing time. Filename parsing is handled in calculate_chunk */
            //char filename[];
        }

        struct lzo_size_crc {
            uint32 original_crc;        // (CRC32 if flags & F_H_CRC32 else Adler32)
            uint32 uncompressed_size;
            uint32 compressed_size;
            uint32 uncompressed_crc;
            uint32 compressed_crc;      // (only if flags & F_ADLER32_C or flags & F_CRC32_C)
        }
    """
    HEADER_STRUCT = "lzo_header"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:

        header = self.cparser_be.lzo_header_no_filter(file)

        if header.flags & F_H_FILTER:
            file.seek(start_offset)
            header = self.cparser_be.lzo_header_filter(file)

        file.seek(header.filename_len, io.SEEK_CUR)
        logger.debug("LZO header parsed", header=header)

        size_crc_header = self.cparser_be.lzo_size_crc(file)
        logger.debug("CRC header parsed", header=size_crc_header)

        end_offset = (
            len(header)
            + header.filename_len
            + len(size_crc_header)
            + size_crc_header.compressed_size
        )

        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + end_offset
        )

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["lzop", "-d", "-f", "-N", f"-p{outdir}", inpath]
