import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.compression.qca_lzma import QcaLzmaHandler
from unblob.testing import unhex

FILE_CONTENTS = unhex(
    """\
00000000: aabb ccdd 0000 0000 0000 0000 0000 0000  ................
00000010: 0100 0200 0200 0000 2200 0000 0000 0000  ........".......
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: ffff ffff 0300 0200 0010 0000 1200 0000  ................
00000090: 3c00 0000 0033 1bec c462 4220 8885 dd57  <....3...bB ...W
000000a0: ffff fb3e 8000 0000 0000 0000 0000 0000  ...>............
"""
)
START_OFFSET = 0x84
handler = QcaLzmaHandler()


def test_chunk_calculation():
    file = File.from_bytes(FILE_CONTENTS)
    file.seek(START_OFFSET)
    chunk = handler.calculate_chunk(file, START_OFFSET)

    assert chunk is not None
    assert chunk.start_offset == 132
    assert chunk.end_offset == 166


@pytest.mark.parametrize(
    "contents, error",
    [
        (
            FILE_CONTENTS[START_OFFSET : START_OFFSET + 8]
            + bytes.fromhex("00 00 00 00")
            + FILE_CONTENTS[12:],
            "Invalid compressed size 0",
        ),
        (
            FILE_CONTENTS[START_OFFSET : START_OFFSET + 12]
            + bytes.fromhex("01 00 00 00")
            + FILE_CONTENTS[16:],
            "Invalid decompressed size 1",
        ),
        (
            FILE_CONTENTS[START_OFFSET : START_OFFSET + 20]
            + bytes.fromhex("00")
            + FILE_CONTENTS[21:],
            "LZMA Decompression failed",
        ),
    ],
)
def test_invalid_chunk(contents, error):
    file = File.from_bytes(contents)
    with pytest.raises(InvalidInputFormat, match=error):
        handler.calculate_chunk(file, 0)
