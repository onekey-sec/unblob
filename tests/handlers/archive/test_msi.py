import struct

import pytest

from unblob.file_utils import File
from unblob.handlers.archive.msi import (
    END_OF_CHAIN,
    FREE_SECTOR,
    MsiHandler,
)


def _build_msi_with_sector_shift(sector_shift: int) -> bytes:
    sector_size = 1 << sector_shift

    header = bytearray(sector_size)
    header[:8] = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1")

    dll_version = 4 if sector_shift >= 12 else 3
    # Offsets and values taken from the CFBF header specification
    struct.pack_into(
        "<HHHHHH",
        header,
        0x18,
        0x0033,
        dll_version,
        0xFFFE,
        sector_shift,
        6,
        0,
    )
    struct.pack_into("<I", header, 0x2C, 1)  # csectFat
    struct.pack_into("<I", header, 0x38, 4096)  # miniSectorCutoff
    struct.pack_into("<I", header, 0x3C, FREE_SECTOR)  # sectMiniFatStart
    struct.pack_into("<I", header, 0x44, FREE_SECTOR)  # sectDifStart

    sect_fat_entries = [FREE_SECTOR] * 109
    sect_fat_entries[0] = 0
    for index, entry in enumerate(sect_fat_entries):
        struct.pack_into("<I", header, 0x4C + index * 4, entry)

    entries_per_sector = sector_size // 4
    fat_sector = bytearray(sector_size)
    fat_entries = [END_OF_CHAIN] + [FREE_SECTOR] * (entries_per_sector - 1)
    for index, entry in enumerate(fat_entries):
        struct.pack_into("<I", fat_sector, index * 4, entry)

    return bytes(header + fat_sector)


@pytest.mark.parametrize("sector_shift", [9, 12])
def test_calculate_chunk_respects_sector_size(sector_shift: int):
    handler = MsiHandler()

    msi_content = _build_msi_with_sector_shift(sector_shift)
    prefix = b"prefix"
    file = File.from_bytes(prefix + msi_content)

    chunk = handler.calculate_chunk(file, len(prefix))

    assert chunk is not None
    assert chunk.start_offset == len(prefix)
    assert chunk.end_offset == len(prefix) + len(msi_content)
