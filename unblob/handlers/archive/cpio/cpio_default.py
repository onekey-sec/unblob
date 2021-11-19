from dissect.cstruct import cstruct

from .base import _CPIOHandlerBase

cparser = cstruct()
cparser.load(
    """
struct old_cpio_header
{
  ushort c_magic;
  ushort c_dev;
  ushort c_ino;
  ushort c_mode;
  ushort c_uid;
  ushort c_gid;
  ushort c_nlink;
  ushort c_rdev;
  ushort c_mtimes[2];
  ushort c_namesize;
  ushort c_filesize[2];
};

"""
)


class BinaryHandler(_CPIOHandlerBase):
    NAME = "cpio_binary"
    YARA_RULE = r"""
        strings:
            $cpio_binary_magic= { c7 71 } // (default, bin, hpbin)

        condition:
            $cpio_binary_magic
    """

    _PAD_ALIGN = 2
    _HEADER_PARSER = cparser.old_cpio_header

    @staticmethod
    def _calculate_file_size(header) -> int:
        return header.c_filesize[0] << 16 | header.c_filesize[1]

    @staticmethod
    def _calculate_name_size(header) -> int:
        return header.c_namesize + 1 if header.c_namesize % 2 else header.c_namesize
