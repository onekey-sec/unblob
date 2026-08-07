import struct

import pytest

from unblob.file_utils import File
from unblob.handlers.filesystem.ntfs import NTFSHandler

handler = NTFSHandler()

BOOT_SECTOR_SIZE = 512


def build_volume(bytes_per_sector: int, total_sectors: int) -> bytes:
    """Build a minimal NTFS volume.

    ``total_sectors`` excludes the trailing backup boot sector, so the volume
    occupies ``(total_sectors + 1) * bytes_per_sector`` bytes on disk.
    """
    boot = bytearray(BOOT_SECTOR_SIZE)
    boot[0:3] = b"\xeb\x52\x90"  # jump instruction
    boot[3:11] = b"NTFS    "  # oem_id
    struct.pack_into("<H", boot, 11, bytes_per_sector)
    boot[13] = 8  # sectors_per_cluster
    struct.pack_into("<Q", boot, 40, total_sectors)
    boot[510:512] = b"\x55\xaa"  # boot magic

    volume_size = (total_sectors + 1) * bytes_per_sector
    return bytes(boot) + b"\x11" * (volume_size - BOOT_SECTOR_SIZE)


@pytest.mark.parametrize("bytes_per_sector", [256, 512, 4096])
def test_chunk_covers_whole_volume(bytes_per_sector):
    total_sectors = 8
    volume = build_volume(bytes_per_sector, total_sectors)
    # trailing bytes belonging to whatever follows the volume
    file = File.from_bytes(volume + b"\xee" * 64)

    chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    # the backup boot sector is one sector wide, so the chunk must end exactly
    # at the volume boundary regardless of the sector size
    assert chunk.end_offset == len(volume)
