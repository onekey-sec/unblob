import struct

import pytest

from unblob.file_utils import File
from unblob.handlers.archive.arc import ARCHandler

END_OF_ARCHIVE = b"\x1a\x00"


def arc_entry(header_type: int, name: bytes, content: bytes) -> bytes:
    header = (
        b"\x1a"
        + bytes([header_type])
        + name.ljust(13, b"\x00")
        + struct.pack("<IHHH", len(content), 0, 0, 0)
    )
    # type 1 (old style) headers have no length field
    if header_type != 1:
        header += struct.pack("<I", len(content))
    return header + content


@pytest.mark.parametrize(
    "archive",
    [
        pytest.param(
            arc_entry(1, b"APPLE.TXT", b"apple\n") + END_OF_ARCHIVE,
            id="old-header",
        ),
        pytest.param(
            arc_entry(1, b"APPLE.TXT", b"apple\n")
            + arc_entry(2, b"CHERRY.TXT", b"cherry\n")
            + END_OF_ARCHIVE,
            id="old-header-then-new-header",
        ),
        pytest.param(
            arc_entry(2, b"CHERRY.TXT", b"cherry\n")
            + arc_entry(1, b"APPLE.TXT", b"apple\n")
            + END_OF_ARCHIVE,
            id="new-header-then-old-header",
        ),
        pytest.param(
            arc_entry(2, b"CHERRY.TXT", b"cherry\n") + END_OF_ARCHIVE,
            id="new-header",
        ),
    ],
)
@pytest.mark.parametrize("prefix", [b"", b"PREFIX"])
def test_calculate_chunk(archive: bytes, prefix: bytes):
    file = File.from_bytes(prefix + archive + b"trailing data")

    chunk = ARCHandler().calculate_chunk(file, len(prefix))

    assert chunk is not None
    assert chunk.start_offset == len(prefix)
    assert chunk.end_offset == len(prefix) + len(archive)
