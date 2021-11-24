import binascii
import io
import struct
from typing import List, Union

from dissect.cstruct import cstruct

from ....models import UnknownChunk, ValidChunk

NAME = "cramfs"

YARA_RULE = r"""
    strings:
        $magic_be = { 28 CD 3D 45 }
        $magic_le = { 45 3D CD 28 }
    condition:
        $magic_le or $magic_be
"""
YARA_MATCH_OFFSET = 0

CRAMFS_HEADER = """
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
cparser_le = cstruct(endian="<")
cparser_le.load(CRAMFS_HEADER)

cparser_be = cstruct(endian=">")
cparser_be.load(CRAMFS_HEADER)

BIG_ENDIAN_MAGIC = 0x28CD3D45


def calculate_chunk(
    file: io.BufferedIOBase, start_offset: int
) -> Union[ValidChunk, UnknownChunk]:

    # read the magic and derive endianness from it
    magic_bytes = file.read(4)
    magic = struct.unpack(">I", magic_bytes)[0]
    cparser = cparser_be if magic == BIG_ENDIAN_MAGIC else cparser_le

    file.seek(start_offset)
    header = cparser.cramfs_header(file)
    file.seek(start_offset)

    # CRC check
    content = bytearray(file.read())
    file.seek(32)
    if magic == BIG_ENDIAN_MAGIC:
        header_crc = struct.unpack(">I", file.read(4))[0]
    else:
        header_crc = struct.unpack("<I", file.read(4))[0]

    content[32:36] = b"\x00\x00\x00\x00"
    computed_crc = binascii.crc32(content)

    if not header.signature == b"Compressed ROMFS" or not (header_crc == computed_crc):
        return UnknownChunk(start_offset=start_offset, reason="Invalid CramFS header")

    size = header.size
    end_offset = start_offset + size

    return ValidChunk(start_offset=start_offset, end_offset=end_offset)


def make_extract_command(inpath: str, outdir: str) -> List[str]:
    return ["7z", "x", "-y", inpath, f"-o{outdir}"]
