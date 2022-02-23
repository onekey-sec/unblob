import io
from typing import Optional

from structlog import get_logger

from ...extractors import Command
from ...file_utils import decode_int, round_up, snull
from ...models import StructHandler, ValidChunk

logger = get_logger()

CPIO_TRAILER_NAME = b"TRAILER!!!"
MAX_LINUX_PATH_LENGTH = 0x1000


class _CPIOHandlerBase(StructHandler):
    """A common base for all CPIO formats
    The format should be parsed the same, there are small differences how to calculate
    file and filename sizes padding and conversion from octal / hex.
    """

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    _PAD_ALIGN: int
    _FILE_PAD_ALIGN: int = 512

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        offset = start_offset
        while True:
            file.seek(offset)
            header = self.parse_header(file)

            c_filesize = self._calculate_file_size(header)
            c_namesize = self._calculate_name_size(header)

            # heuristics 1: check the filename
            if c_namesize > MAX_LINUX_PATH_LENGTH:
                return

            if c_namesize > 0:
                file.seek(offset + len(header))
                tmp_filename = file.read(c_namesize)

                # heuristics 2: check that filename is null-byte terminated
                if not tmp_filename.endswith(b"\x00"):
                    return

                filename = snull(tmp_filename)

                if filename == CPIO_TRAILER_NAME:
                    offset += self._pad_content(header, c_filesize, c_namesize)
                    break

            file.seek(c_filesize, io.SEEK_CUR)
            # Rounding up the total of the header size, and the c_filesize, again. Because
            # some CPIO implementations don't align the first chunk, but do align the 2nd.
            # In theory, with a "normal" CPIO file, we should just be aligned on the
            # 4-byte boundary already, but if we are not for some reason, then we just
            # need to round up again.

            if c_filesize > 0:
                offset += self._pad_content(header, c_filesize, c_namesize)
            else:
                offset = round_up(file.tell(), self._PAD_ALIGN)

        # Add padding that could exists between the cpio trailer and the end-of-file.
        # cpio aligns the file to 512 bytes
        offset = round_up(offset, self._FILE_PAD_ALIGN)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=offset,
        )

    @classmethod
    def _pad_content(cls, header, c_filesize: int, c_namesize: int) -> int:
        """Pad header and content with _PAD_ALIGN bytes."""
        padded_header = round_up(len(header), cls._PAD_ALIGN)
        padded_content = round_up(c_filesize + c_namesize, cls._PAD_ALIGN)
        return padded_header + padded_content

    @staticmethod
    def _calculate_file_size(header) -> int:
        raise NotImplementedError

    @staticmethod
    def _calculate_name_size(header) -> int:
        raise NotImplementedError


class BinaryHandler(_CPIOHandlerBase):
    NAME = "cpio_binary"
    YARA_RULE = r"""
        strings:
            $cpio_binary_magic= { c7 71 } // (default, bin, hpbin)

        condition:
            $cpio_binary_magic and
            /**
                check that c_mode file type is valid
                C_ISBLK		060000
                C_ISCHR		020000
                C_ISDIR		040000
                C_ISFIFO	010000
                C_ISSOCK	0140000
                C_ISLNK		0120000
                C_ISCTG		0110000
                C_ISREG		0100000
            */
            for any i in (0o1, 0o2, 0o4, 0o6, 0o10, 0o11, 0o12, 0o14) : (((uint16(@cpio_binary_magic + 6) & 0o770000) >> 0o14) == i) and

            /**
                check that c_mode sticky bits is valid
                C_NONE      000000
                C_ISUID		004000
                C_ISGID		002000
                C_ISVTX		001000
            */
            for any j in (0o0, 0o1, 0o2, 0o4): (((uint16(@cpio_binary_magic + 6) & 0o7000) >> 0o11) == j) and

            /**
                check that c_mode permissions are valid.
                should be between 0o000 (0x0) (---------) and 0o777 (rwxrwxrwx)
            */
            ((uint16(@cpio_binary_magic + 6) & 0o777) <= 0o777)
    """

    C_DEFINITIONS = r"""
        typedef struct old_cpio_header
        {
            uint16 c_magic;
            uint16 c_dev;
            uint16 c_ino;
            uint16 c_mode;
            uint16 c_uid;
            uint16 c_gid;
            uint16 c_nlink;
            uint16 c_rdev;
            uint16 c_mtimes[2];
            uint16 c_namesize;
            uint16 c_filesize[2];
        } old_cpio_header_t;
    """
    HEADER_STRUCT = "old_cpio_header_t"

    _PAD_ALIGN = 2

    @staticmethod
    def _calculate_file_size(header) -> int:
        return header.c_filesize[0] << 16 | header.c_filesize[1]

    @staticmethod
    def _calculate_name_size(header) -> int:
        return header.c_namesize + 1 if header.c_namesize % 2 else header.c_namesize


class PortableOldASCIIHandler(_CPIOHandlerBase):
    NAME = "cpio_portable_old_ascii"

    YARA_RULE = r"""
        strings:
            $cpio_portable_old_ascii_magic = { 30 37 30 37 30 37 } // 07 07 07

        condition:
            $cpio_portable_old_ascii_magic
    """
    C_DEFINITIONS = r"""
        typedef struct old_ascii_header
        {
            char c_magic[6];
            char c_dev[6];
            char c_ino[6];
            char c_mode[6];
            char c_uid[6];
            char c_gid[6];
            char c_nlink[6];
            char c_rdev[6];
            char c_mtime[11];
            char c_namesize[6];
            char c_filesize[11];
        } old_ascii_header_t;
    """
    HEADER_STRUCT = "old_ascii_header_t"

    _PAD_ALIGN = 2

    @staticmethod
    def _calculate_file_size(header) -> int:
        return decode_int(header.c_filesize, 8)

    @staticmethod
    def _calculate_name_size(header) -> int:
        return decode_int(header.c_namesize, 8)


class _NewASCIICommon(StructHandler):
    C_DEFINITIONS = r"""
        typedef struct new_ascii_header
        {
            char c_magic[6];
            char c_ino[8];
            char c_mode[8];
            char c_uid[8];
            char c_gid[8];
            char c_nlink[8];
            char c_mtime[8];
            char c_filesize[8];
            char c_dev_maj[8];
            char c_dev_min[8];
            char c_rdev_maj[8];
            char c_rdev_min[8];
            char c_namesize[8];
            char c_chksum[8];
        } new_ascii_header_t;
    """
    HEADER_STRUCT = "new_ascii_header_t"

    _PAD_ALIGN = 4


class PortableASCIIHandler(_NewASCIICommon, _CPIOHandlerBase):
    NAME = "cpio_portable_ascii"
    YARA_RULE = r"""
        strings:
            $cpio_portable_ascii_magic = { 30 37 30 37 30 31 } // 07 07 01 (newc)

        condition:
            $cpio_portable_ascii_magic
    """

    @staticmethod
    def _calculate_file_size(header) -> int:
        return decode_int(header.c_filesize, 16)

    @staticmethod
    def _calculate_name_size(header) -> int:
        return decode_int(header.c_namesize, 16)


class PortableASCIIWithCRCHandler(_NewASCIICommon, _CPIOHandlerBase):
    NAME = "cpio_portable_ascii_crc"
    YARA_RULE = r"""
        strings:
            $cpio_portable_ascii_crc_magic = { 30 37 30 37 30 32 } // 07 07 02

        condition:
            $cpio_portable_ascii_crc_magic
    """

    @staticmethod
    def _calculate_file_size(header):
        return decode_int(header.c_filesize, 16)

    @staticmethod
    def _calculate_name_size(header):
        return decode_int(header.c_namesize, 16)
