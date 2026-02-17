import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.dlink.fpkg import FPKGHandler
from unblob.testing import unhex

DB_FILE_CONTENTS = unhex(
    """\
00000000: 4650 4b47 0100 0000 0000 0034 0000 0001  FPKG.......4....
00000010: 0000 0020 4446 4c2d 3136 3030 0000 0000  ... DFL-1600....
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 001c 0100 6874 0000 30ad  ..........ht..0.
00000040: 6261 636b 7570 2e63 6667 002f 5452 2f78  backup.cfg./TR/x
00000050: 3c3f 786d 6c20 7665 7273 696f 6e3d 2231  <?xml version="1
"""
)
handler = FPKGHandler()


def test_chunk_calculation():
    file = File.from_bytes(DB_FILE_CONTENTS)
    chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == 0x30FD


@pytest.mark.parametrize(
    "contents, error",
    [
        (
            DB_FILE_CONTENTS[:8] + bytes.fromhex("00 00 00 02") + DB_FILE_CONTENTS[12:],
            "Invalid first entry offset",
        ),
        (
            DB_FILE_CONTENTS[:0x30],
            "No valid entries found",
        ),
        (
            DB_FILE_CONTENTS[:0x34]
            + bytes.fromhex("00 00 00 20")
            + DB_FILE_CONTENTS[0x34:],
            "Invalid file header length",
        ),
        (
            DB_FILE_CONTENTS[:0x40] + bytes.fromhex("FF FF") + DB_FILE_CONTENTS[0x42:],
            "Invalid filename",
        ),
    ],
)
def test_invalid_chunk(contents, error):
    file = File.from_bytes(contents)
    with pytest.raises(InvalidInputFormat, match=error):
        handler.calculate_chunk(file, 0)
