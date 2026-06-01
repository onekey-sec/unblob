import struct
from pathlib import Path

import pytest

from unblob.handlers.archive.par2 import PAR2_MAGIC, MultiVolumePAR2Handler


def build_packet(packet_length: int, tail: bytes = b"\xab" * 4096) -> bytes:
    # par2_header_t: magic[8], packet_length u64, md5_hash[16],
    # recovery_set_id[16], type[16] -> 64 bytes, followed by trailing data.
    header = PAR2_MAGIC + struct.pack("<Q", packet_length) + b"\x00" * 48
    return header + tail


@pytest.mark.parametrize("packet_length", [0, 20, 31, 63])
def test_is_valid_header_rejects_short_packet_length(packet_length, tmp_path: Path):
    # packet_length below the 64-byte header makes `packet_length - len(header) + 32`
    # negative; read(-1) then slurps the rest of the file past the packet boundary
    # and smaller values raise ValueError.
    path = tmp_path / "short.par2"
    path.write_bytes(build_packet(packet_length))
    assert MultiVolumePAR2Handler().is_valid_header([path]) is False
