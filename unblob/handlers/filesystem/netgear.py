import io
from typing import Optional, List

from ...file_utils import InvalidInputFormat, Endian
from ...models import StructHandler, ValidChunk


class ChkHandler(StructHandler):
    NAME = "chk"

    YARA_RULE = r"""
        strings:
            $chk_header = { 2a 23 24 5e }
        condition:
            $chk_header
    """

    C_DEFINITIONS = r"""
        typedef struct chk_header {
            uint32 magic;
            uint32 header_len;
            uint8  reserved[8];
            uint32 kernel_chksum;
            uint32 rootfs_chksum;
            uint32 kernel_len;
            uint32 rootfs_len;
            uint32 image_chksum;
            uint32 header_chksum;
            /* char board_id[] - upto MAX_BOARD_ID_LEN */
        } chk_header_t;
    """
    HEADER_STRUCT = "chk_header_t"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.BIG)
        print("CHK", header, header.header_len, header.kernel_len, header.rootfs_len)
        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.header_len + header.kernel_len + header.rootfs_len,
        )

        # raise InvalidInputFormat("Invalid ZIP header.")

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["extractchk", '-f', '-e', outdir, inpath]


class TRXHandler(StructHandler):
    NAME = "trx"

    YARA_RULE = r"""
        strings:
            $trx_header = { 48 44 52 30 }
        condition:
            $trx_header
    """

    C_DEFINITIONS = r"""
        typedef struct trx_header {
            uint32 magic;		/* "HDR0" */
            uint32 len;		/* Length of file including header */
            uint32 crc32;		/* 32-bit CRC from flag_version to end of file */
            uint32 flag_version;	/* 0:15 flags, 16:31 version */
            uint32 offsets[3];	/* Offsets of partitions from start of header */
        }; trx_header_t;
    """
    HEADER_STRUCT = "trx_header_t"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.LITTLE)
        print("TRX", header, header.len)
        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.len,
        )

        # raise InvalidInputFormat("Invalid ZIP header.")

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["extracttrx", '-f', '-e', outdir, inpath]
