from dissect.cstruct import cstruct

from .base import _CPIOHandlerBase

cparser = cstruct()
cparser.load(
    """
struct new_ascii_header
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
};
"""
)


class PortableASCIIHandler(_CPIOHandlerBase):
    NAME = "cpio_portable_ascii"
    YARA_RULE = r"""
        strings:
            $cpio_portable_ascii_magic = { 30 37 30 37 30 31 } // 07 07 01 (newc)

        condition:
            $cpio_portable_ascii_magic
    """

    _PAD_ALIGN = 4
    _HEADER_PARSER = cparser.new_ascii_header

    @staticmethod
    def _calculate_file_size(header) -> int:
        return int(header.c_filesize, 16)

    @staticmethod
    def _calculate_name_size(header) -> int:
        return int(header.c_namesize, 16)
