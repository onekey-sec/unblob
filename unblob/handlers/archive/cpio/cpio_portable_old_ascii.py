from dissect.cstruct import cstruct

from .base import _CPIOHandlerBase


cparser = cstruct()
cparser.load(
    """
struct old_ascii_header
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
};
"""
)


class PortableOldASCIIHandler(_CPIOHandlerBase):
    NAME = "cpio_portable_old_ascii"

    YARA_RULE = r"""
        strings:
            $cpio_portable_old_ascii_magic = { 30 37 30 37 30 37 } // 07 07 07

        condition:
            $cpio_portable_old_ascii_magic
    """

    _PAD_ALIGN = 2
    _HEADER_PARSER = cparser.old_ascii_header

    @staticmethod
    def _calculate_file_size(header) -> int:
        return int(header.c_filesize, 8)

    @staticmethod
    def _calculate_name_size(header) -> int:
        return int(header.c_namesize, 8)
