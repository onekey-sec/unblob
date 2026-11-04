import struct

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.executable.macho import MachOHandler

handler = MachOHandler()

FAT_HEADER_LEN = 8
FAT_ARCH_LEN = 20
PREFIX = b"\xff" * 16


def build_fat(slices: list[tuple[int, int]], total_size: int) -> bytes:
    fat = struct.pack(">II", 0xCAFEBABE, len(slices))
    for cpusubtype, (offset, size) in enumerate(slices):
        fat += struct.pack(">IIIII", 0x7, cpusubtype, offset, size, 0)
    return fat.ljust(total_size, b"\x00")


def test_fat_chunk():
    header_end = FAT_HEADER_LEN + 2 * FAT_ARCH_LEN
    fat = build_fat([(header_end + 16, 16), (header_end, 16)], header_end + 32)
    file = File.from_bytes(PREFIX + fat + b"\xff" * 16)
    file.seek(len(PREFIX))

    chunk = handler.calculate_chunk(file, len(PREFIX))

    assert chunk is not None
    assert chunk.start_offset == len(PREFIX)
    assert chunk.end_offset == len(PREFIX) + len(fat)


@pytest.mark.parametrize(
    "slices",
    [
        pytest.param([(0, 0x100)], id="slice-is-the-fat-binary"),
        pytest.param([(FAT_HEADER_LEN + FAT_ARCH_LEN - 1, 0x10)], id="slice-in-header"),
        pytest.param([(0x40, 0x20), (0x50, 0x20)], id="overlapping-slices"),
        pytest.param([(0x40, 0x20), (0x40, 0x20)], id="same-slice-twice"),
    ],
)
def test_fat_chunk_rejects_overlapping_slices(slices: list[tuple[int, int]]):
    file = File.from_bytes(PREFIX + build_fat(slices, 0x100))
    file.seek(len(PREFIX))

    with pytest.raises(InvalidInputFormat):
        handler.calculate_chunk(file, len(PREFIX))
