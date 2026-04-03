import binascii
import io
import struct

from unblob.extractors import Command

from ...file_utils import get_endian, iterate_file
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
FSID_CRC_OFFSET = 32
FSID_CRC_SIZE = 4


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
            uint32 fs_size;
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

        if valid_signature and self._is_crc_valid(file, start_offset, header):
            return ValidChunk(
                start_offset=start_offset,
                end_offset=start_offset + header.fs_size,
            )
        return None

    def _is_crc_valid(
        self,
        file: File,
        start_offset: int,
        header,
    ) -> bool:
        # old cramfs format do not support crc
        if not (header.flags & CRAMFS_FLAG_FSID_VERSION_2):
            return True

        file.seek(start_offset, io.SEEK_SET)
        header_bytes = bytearray(file.read(FSID_CRC_OFFSET + FSID_CRC_SIZE))
        header_bytes[FSID_CRC_OFFSET : FSID_CRC_OFFSET + FSID_CRC_SIZE] = (
            b"\x00\x00\x00\x00"
        )
        computed_crc = binascii.crc32(header_bytes)

        for chunk in iterate_file(
            file,
            start_offset + FSID_CRC_OFFSET + FSID_CRC_SIZE,
            header.fs_size - FSID_CRC_OFFSET + FSID_CRC_SIZE,
        ):
            computed_crc = binascii.crc32(chunk, computed_crc)

        # some vendors like their CRC's swapped, don't ask why
        return header.fsid_crc == computed_crc or header.fsid_crc == swap_int32(
            computed_crc
        )
