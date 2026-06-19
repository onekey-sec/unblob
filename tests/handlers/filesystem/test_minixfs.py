import pytest

from unblob.file_utils import Endian, File, InvalidInputFormat
from unblob.handlers.filesystem.minixfs import (
    VERSION_TO_C_DEFINITIONS,
    MinixFS,
    MinixFSv1Handler,
    MinixFSv2Handler,
    MinixFSv3Handler,
    get_endianness,
)
from unblob.testing import unhex

BLOCK_SIZE = 0x400
NULL = b"\x00"
SUPERBLOCK_V1_LE_14 = unhex(
    """\
00000400: 2000 2000 0100 0100 0500 0000 001c 0810   . .............
00000410: 7f13 0100 0000 0000 0000 0000 0000 0000  ................
"""
)
SUPERBLOCK_V1_BE_14 = unhex(
    """\
00000400: 0020 0020 0001 0001 0005 0000 1008 1c00  . . ............
00000410: 137f 0001 0000 0000 0000 0000 0000 0000  ................
"""
)
SUPERBLOCK_V2_LE_14 = unhex(
    """\
00000400: 1000 0000 0100 0100 0500 0000 ffff ff7f  ................
00000410: 6824 0100 2000 0000 0000 0000 0000 0000  h$.. ...........
"""
)
SUPERBLOCK_V2_BE_14 = unhex(
    """\
00000400: 0010 0000 0001 0001 0005 0000 7fff ffff  ................
00000410: 2468 0001 0000 0020 0000 0000 0000 0000  $h..... ........
"""
)
SUPERBLOCK_V3_LE = unhex(
    """\
00000400: 1000 0000 0000 0100 0100 0500 0000 0000  ................
00000410: ffff ff7f 2000 0000 5a4d 0000 0004 0000  .... ...ZM......
"""
)
SUPERBLOCK_V3_BE = unhex(
    """\
00000400: 0000 0010 0000 0001 0001 0005 0000 0000  ................
00000410: 7fff ffff 0000 0020 4d5a 0000 0400 0000  ....... MZ......
"""
)

V1_HANDLER = MinixFSv1Handler()
V2_HANDLER = MinixFSv2Handler()
V3_HANDLER = MinixFSv3Handler()


@pytest.mark.parametrize(
    "superblock, handler",
    [
        (SUPERBLOCK_V1_LE_14, V1_HANDLER),
        (SUPERBLOCK_V1_LE_14.replace(b"\x7f", b"\x8f"), V1_HANDLER),
        (SUPERBLOCK_V1_BE_14, V1_HANDLER),
        (SUPERBLOCK_V1_BE_14.replace(b"\x7f", b"\x8f"), V1_HANDLER),
        (SUPERBLOCK_V2_LE_14, V2_HANDLER),
        (SUPERBLOCK_V2_LE_14.replace(b"\x68", b"\x78"), V2_HANDLER),
        (SUPERBLOCK_V2_BE_14, V2_HANDLER),
        (SUPERBLOCK_V2_BE_14.replace(b"\x68", b"\x78"), V2_HANDLER),
        (SUPERBLOCK_V3_LE, V3_HANDLER),
        (SUPERBLOCK_V3_BE, V3_HANDLER),
    ],
)
def test_chunk_calculation(superblock, handler):
    file = File.from_bytes(
        NULL * BLOCK_SIZE
        + superblock
        + NULL * (BLOCK_SIZE - len(superblock))
        + NULL * BLOCK_SIZE * 31
    )
    chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == 32 * BLOCK_SIZE


def test_chunk_calculation_uses_remaining_file_size():
    prefix = NULL * BLOCK_SIZE
    file = File.from_bytes(
        prefix
        + NULL * BLOCK_SIZE
        + SUPERBLOCK_V1_LE_14
        + NULL * (BLOCK_SIZE - len(SUPERBLOCK_V1_LE_14))
        + NULL * BLOCK_SIZE * 29
    )

    with pytest.raises(InvalidInputFormat, match="larger than the file size"):
        V1_HANDLER.calculate_chunk(file, len(prefix))


@pytest.mark.parametrize(
    "superblock, error, handler",
    [
        (
            b"\x00\x00" + SUPERBLOCK_V1_LE_14[2:],
            "Invalid inode count",
            V1_HANDLER,
        ),
        (
            SUPERBLOCK_V1_LE_14[:2] + b"\x00\x00" + SUPERBLOCK_V1_LE_14[4:],
            "Invalid zone count",
            V1_HANDLER,
        ),
        (
            SUPERBLOCK_V1_LE_14[:4] + b"\x00\x00" + SUPERBLOCK_V1_LE_14[6:],
            "Invalid inode map block count",
            V1_HANDLER,
        ),
        (
            SUPERBLOCK_V1_LE_14[:6] + b"\x00\x00" + SUPERBLOCK_V1_LE_14[8:],
            "Invalid zone map block count",
            V1_HANDLER,
        ),
        (
            SUPERBLOCK_V1_LE_14[:2] + b"\xff\xff" + SUPERBLOCK_V1_LE_14[4:],
            "larger than the file size",
            V1_HANDLER,
        ),
        (
            SUPERBLOCK_V1_LE_14[:8] + b"\x00\x00" + SUPERBLOCK_V1_LE_14[10:],
            "Invalid first data zone",
            V1_HANDLER,
        ),
        (
            SUPERBLOCK_V1_LE_14[:10] + b"\x12\x34" + SUPERBLOCK_V1_LE_14[12:],
            "Invalid log zone size",
            V1_HANDLER,
        ),
        (
            SUPERBLOCK_V1_LE_14[:12] + b"\x00\x00\x00\x00" + SUPERBLOCK_V1_LE_14[16:],
            "Invalid max file size",
            V1_HANDLER,
        ),
        (
            SUPERBLOCK_V2_LE_14[:2]
            + b"\x00\x00"
            + SUPERBLOCK_V2_LE_14[4:18]
            + b"\x00\x00\x00\x00",
            "Invalid zone count",
            V2_HANDLER,
        ),
        (
            SUPERBLOCK_V3_LE[:28] + b"\xbe\xef" + SUPERBLOCK_V3_LE[30:],
            "Invalid block size",
            V3_HANDLER,
        ),
    ],
)
def test_invalid(superblock, error, handler):
    file = File.from_bytes(
        NULL * BLOCK_SIZE
        + superblock
        + NULL * (BLOCK_SIZE - len(superblock))
        + NULL * BLOCK_SIZE * 31
    )
    with pytest.raises(InvalidInputFormat, match=error):
        handler.calculate_chunk(file, 0)


def _v1_minixfs() -> MinixFS:
    # firstdatazone == 5, s_nzones == 32, so valid data zones are 5..31
    image = bytearray(
        NULL * BLOCK_SIZE
        + SUPERBLOCK_V1_LE_14
        + NULL * (BLOCK_SIZE - len(SUPERBLOCK_V1_LE_14))
        + NULL * BLOCK_SIZE * 31
    )
    return MinixFS(File.from_bytes(bytes(image)), 1, VERSION_TO_C_DEFINITIONS[1])


def test_read_zone_data_accepts_valid_data_zone():
    minix = _v1_minixfs()
    valid_zone = minix.superblock.s_firstdatazone
    assert len(minix._read_zone_data(valid_zone)) == minix.zone_size  # noqa: SLF001


@pytest.mark.parametrize(
    "zone_index",
    [
        4,  # inode table block, below the first data zone
        0,  # boot block
        32,  # one past the last zone
        1000,  # well past the end of the filesystem
    ],
)
def test_read_zone_data_rejects_out_of_range_zone(zone_index):
    minix = _v1_minixfs()
    with pytest.raises(InvalidInputFormat, match="Zone index out of range"):
        minix._read_zone_data(zone_index)  # noqa: SLF001


@pytest.mark.parametrize(
    "superblock, endianness, handler",
    [
        (SUPERBLOCK_V1_LE_14, Endian.LITTLE, V1_HANDLER),
        (SUPERBLOCK_V1_BE_14, Endian.BIG, V1_HANDLER),
        (SUPERBLOCK_V2_LE_14, Endian.LITTLE, V2_HANDLER),
        (SUPERBLOCK_V2_BE_14, Endian.BIG, V2_HANDLER),
        (SUPERBLOCK_V3_LE, Endian.LITTLE, V3_HANDLER),
        (SUPERBLOCK_V3_BE, Endian.BIG, V3_HANDLER),
    ],
)
def test_magic(superblock, endianness, handler):
    file = File.from_bytes(superblock)
    assert get_endianness(file, handler.VERSION) == endianness
