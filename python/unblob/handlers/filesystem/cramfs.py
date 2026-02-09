import binascii
import struct

from unblob.extractors import Command

from ...file_utils import Endian, convert_int32, get_endian
from ...models import (
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

CRAMFS_FLAG_FSID_VERSION_2 = 0x00000001
BIG_ENDIAN_MAGIC = 0x28_CD_3D_45


def swap_int32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]


class CramFSHandler(StructHandler):
    NAME = "cramfs"

    PATTERNS = [
        HexString("28 CD 3D 45"),  # big endian
        HexString("45 3D CD 28"),  # little endian
    ]

    C_DEFINITIONS = r"""
        typedef struct cramfs_header {
            uint32 magic;
            uint32 size;
            uint32 flags;
            uint32 future;
            char signature[16];
            uint32 fsid_crc;
            uint32 fsid_edition;
            uint32 fsid_blocks;
            uint32 fsid_files;
            char name[16];
        } cramfs_header_t;
    """
    HEADER_STRUCT = "cramfs_header_t"

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    DOC = HandlerDoc(
        name="CramFS",
        description="CramFS is a lightweight, read-only file system format designed for simplicity and efficiency in embedded systems. It uses zlib compression for file data and stores metadata in a compact, contiguous structure.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="CramFS Documentation",
                url="https://web.archive.org/web/20160304053532/http://sourceforge.net/projects/cramfs/",
            ),
            Reference(
                title="CramFS Wikipedia",
                url="https://en.wikipedia.org/wiki/Cramfs",
            ),
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        endian = get_endian(file, BIG_ENDIAN_MAGIC)
        header = self.parse_header(file, endian)
        valid_signature = header.signature == b"Compressed ROMFS"

        if valid_signature and self._is_crc_valid(file, start_offset, header, endian):
            return ValidChunk(
                start_offset=start_offset,
                end_offset=start_offset + header.size,
            )
        return None

    def _is_crc_valid(
        self,
        file: File,
        start_offset: int,
        header,
        endian: Endian,
    ) -> bool:
        # old cramfs format do not support crc
        if not (header.flags & CRAMFS_FLAG_FSID_VERSION_2):
            return True
        file.seek(start_offset)
        content = bytearray(file.read(header.size))
        file.seek(start_offset + 32)
        crc_bytes = file.read(4)
        header_crc = convert_int32(crc_bytes, endian)
        content[32:36] = b"\x00\x00\x00\x00"
        computed_crc = binascii.crc32(content)
        # some vendors like their CRC's swapped, don't ask why
        return header_crc == computed_crc or header_crc == swap_int32(computed_crc)
