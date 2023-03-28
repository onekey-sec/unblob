import io
from typing import Optional

from structlog import get_logger

from ...extractors import Command
from ...file_utils import OffsetFile, decode_int, round_up, snull
from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()

CPIO_TRAILER_NAME = b"TRAILER!!!"
MAX_LINUX_PATH_LENGTH = 0x1000

C_ISBLK = 0o60000
C_ISCHR = 0o20000
C_ISDIR = 0o40000
C_ISFIFO = 0o10000
C_ISSOCK = 0o140000
C_ISLNK = 0o120000
C_ISCTG = 0o110000
C_ISREG = 0o100000

C_FILE_TYPES = (
    C_ISBLK,
    C_ISCHR,
    C_ISDIR,
    C_ISFIFO,
    C_ISSOCK,
    C_ISLNK,
    C_ISCTG,
    C_ISREG,
)

C_NONE = 0o00000
C_ISUID = 0o04000
C_ISGID = 0o02000
C_ISVTX = 0o01000
C_ISUID_ISGID = 0o06000

C_STICKY_BITS = (C_NONE, C_ISUID, C_ISGID, C_ISVTX, C_ISUID_ISGID)


class _CPIOHandlerBase(StructHandler):
    """A common base for all CPIO formats.

    The format should be parsed the same, there are small differences how to calculate
    file and filename sizes padding and conversion from octal / hex.
    """

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    _PAD_ALIGN: int
    _FILE_PAD_ALIGN: int = 512

    def calculate_chunk(  # noqa: C901
        self, file: File, start_offset: int
    ) -> Optional[ValidChunk]:
        file_with_offset = OffsetFile(file, start_offset)
        current_offset = start_offset
        while True:
            file.seek(current_offset)
            try:
                header = self.parse_header(file)
            except EOFError:
                break

            c_filesize = self._calculate_file_size(header)
            c_namesize = self._calculate_name_size(header)

            # heuristics 1: check the filename
            if c_namesize > MAX_LINUX_PATH_LENGTH:
                return None

            if c_namesize > 0:
                tmp_filename = file_with_offset.read(c_namesize)

                # heuristics 2: check that filename is null-byte terminated
                if not tmp_filename.endswith(b"\x00"):
                    return None

                filename = snull(tmp_filename)
                if filename == CPIO_TRAILER_NAME:
                    current_offset += self._pad_content(header, c_filesize, c_namesize)
                    break

            c_mode = self._calculate_mode(header)

            file_type = c_mode & 0o770000
            sticky_bit = c_mode & 0o7000

            # heuristics 3: check mode field
            is_valid = file_type in C_FILE_TYPES and sticky_bit in C_STICKY_BITS
            if not is_valid:
                return None

            file_with_offset.seek(c_filesize, io.SEEK_CUR)
            current_offset += self._pad_content(header, c_filesize, c_namesize)

        end_offset = start_offset + self._pad_file(
            file_with_offset, current_offset - start_offset
        )
        if start_offset == end_offset:
            return None
        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )

    @classmethod
    def _pad_file(cls, file: OffsetFile, end_offset: int) -> int:
        """CPIO archives can have a 512 bytes block padding at the end."""
        file.seek(end_offset, io.SEEK_SET)
        padded_end_offset = round_up(end_offset, cls._FILE_PAD_ALIGN)
        padding_size = padded_end_offset - end_offset
        if file.read(padding_size) == bytes([0]) * padding_size:
            return padded_end_offset
        return end_offset

    @classmethod
    def _pad_content(cls, header, c_filesize: int, c_namesize: int) -> int:
        """Pad header and content with _PAD_ALIGN bytes."""
        padded_header = round_up(len(header) + c_namesize, cls._PAD_ALIGN)
        padded_content = round_up(c_filesize, cls._PAD_ALIGN)
        return padded_header + padded_content

    @staticmethod
    def _calculate_file_size(header) -> int:
        raise NotImplementedError

    @staticmethod
    def _calculate_name_size(header) -> int:
        raise NotImplementedError

    @staticmethod
    def _calculate_mode(header) -> int:
        raise NotImplementedError


class BinaryHandler(_CPIOHandlerBase):
    NAME = "cpio_binary"
    PATTERNS = [HexString("c7 71 // (default, bin, hpbin)")]

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

    @staticmethod
    def _calculate_mode(header) -> int:
        return header.c_mode


class PortableOldASCIIHandler(_CPIOHandlerBase):
    NAME = "cpio_portable_old_ascii"

    PATTERNS = [HexString("30 37 30 37 30 37 // 07 07 07")]

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

    _PAD_ALIGN = 1

    @staticmethod
    def _calculate_file_size(header) -> int:
        return decode_int(header.c_filesize, 8)

    @staticmethod
    def _calculate_name_size(header) -> int:
        return decode_int(header.c_namesize, 8)

    @staticmethod
    def _calculate_mode(header) -> int:
        return decode_int(header.c_mode, 8)


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
    PATTERNS = [HexString("30 37 30 37 30 31 // 07 07 01 (newc)")]

    @staticmethod
    def _calculate_file_size(header) -> int:
        return decode_int(header.c_filesize, 16)

    @staticmethod
    def _calculate_name_size(header) -> int:
        return decode_int(header.c_namesize, 16)

    @staticmethod
    def _calculate_mode(header) -> int:
        return decode_int(header.c_mode, 16)


class PortableASCIIWithCRCHandler(_NewASCIICommon, _CPIOHandlerBase):
    NAME = "cpio_portable_ascii_crc"
    PATTERNS = [HexString("30 37 30 37 30 32 // 07 07 02")]

    @staticmethod
    def _calculate_file_size(header):
        return decode_int(header.c_filesize, 16)

    @staticmethod
    def _calculate_name_size(header):
        return decode_int(header.c_namesize, 16)

    @staticmethod
    def _calculate_mode(header) -> int:
        return decode_int(header.c_mode, 16)
