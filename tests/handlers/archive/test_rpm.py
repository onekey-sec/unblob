import struct

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.rpm import RPMHandler


def build_minimal_rpm(package_size: int = 16) -> bytes:
    lead = struct.pack(
        ">4sBBHH66sHH16s",
        b"\xed\xab\xee\xdb",
        3,
        0,
        0,
        1,
        b"minimal",
        1,
        5,
        b"",
    )
    signature = (
        struct.pack(">3sB4sII", b"\x8e\xad\xe8", 1, b"", 1, 4)
        + struct.pack(">IIII", 1000, 4, 0, 1)
        + struct.pack(">I", package_size)
        + b"\x00" * 4
    )
    main_header = struct.pack(">3sB4sII", b"\x8e\xad\xe8", 1, b"", 0, 0)
    return lead + signature + main_header


def test_rpm_chunk_supports_nonzero_start_offset() -> None:
    prefix = b"arbitrary-prefix"
    rpm = build_minimal_rpm()

    chunk = RPMHandler().calculate_chunk(File.from_bytes(prefix + rpm), len(prefix))

    assert chunk is not None
    assert chunk.start_offset == len(prefix)
    assert chunk.end_offset == len(prefix) + len(rpm)


def test_rpm_chunk_rejects_size_beyond_eof() -> None:
    rpm = build_minimal_rpm(package_size=17)

    with pytest.raises(InvalidInputFormat, match="beyond the end"):
        RPMHandler().calculate_chunk(File.from_bytes(rpm), 0)
