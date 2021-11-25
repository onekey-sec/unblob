import binascii
import io
from typing import List, Union

from dissect.cstruct import Instance

from ...file_utils import Endian, convert_int32
from ...models import StructHandler, UnknownChunk, ValidChunk

BIG_ENDIAN_MAGIC = 0x28_CD_3D_45


class CramFSHandler(StructHandler):

    NAME = "cramfs"

    YARA_RULE = r"""
        strings:
            $magic_be = { 28 CD 3D 45 }
            $magic_le = { 45 3D CD 28 }
        condition:
            $magic_le or $magic_be
    """

    C_DEFINITIONS = r"""
        struct cramfs_header {
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
        }
    """
    HEADER_STRUCT = "cramfs_header"

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Union[ValidChunk, UnknownChunk]:
        endian = self._get_endian(file)
        header = self.parse_header(file, endian)
        valid_signature = header.signature == b"Compressed ROMFS"

        if valid_signature and self._is_crc_valid(file, start_offset, header, endian):
            return ValidChunk(
                start_offset=start_offset,
                end_offset=start_offset + header.size,
            )
        else:
            return UnknownChunk(
                start_offset=start_offset, reason="Invalid CramFS header"
            )

    def _get_endian(self, file: io.BufferedIOBase) -> Endian:
        magic_bytes = file.read(4)
        magic = convert_int32(magic_bytes, Endian.BIG)
        endian = Endian.BIG if magic == BIG_ENDIAN_MAGIC else Endian.LITTLE
        file.seek(-4, io.SEEK_CUR)
        return endian

    def _is_crc_valid(
        self,
        file: io.BufferedIOBase,
        start_offset: int,
        header: Instance,
        endian: Endian,
    ) -> bool:
        file.seek(start_offset)
        content = bytearray(file.read(header.size))
        file.seek(start_offset + 32)
        crc_bytes = file.read(4)
        header_crc = convert_int32(crc_bytes, endian)
        content[32:36] = b"\x00\x00\x00\x00"
        computed_crc = binascii.crc32(content)
        return header_crc == computed_crc

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
