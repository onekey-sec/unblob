import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.filesystem.minifs import MiniFSHandler
from unblob.testing import unhex

FILE_CONTENTS = unhex(
    """\
00000000: 4d49 4e49 4653 0000 0000 0000 0000 0000  MINIFS..........
00000010: 0000 0003 0000 0003 0000 000d 0000 0028  ...............(
00000020: 6672 7569 7400 6170 706c 652e 7478 7400  fruit.apple.txt.
00000030: 6261 6e61 6e61 2e74 7874 0063 6865 7272  banana.txt.cherr
00000040: 792e 7478 7400 0000 0000 0000 0000 0006  y.txt...........
00000050: 0000 0000 0000 0000 0000 0006 0000 0000  ................
00000060: 0000 0010 0000 0000 0000 0006 0000 0007  ................
00000070: 0000 0000 0000 001b 0000 0001 0000 0000  ................
00000080: 0000 0007 0000 0000 0000 0023 0000 000d  ...........#....
00000090: 0000 0023 0000 001e 0000 0007 5d00 0080  ...#........]...
000000a0: 00ff ffff ffff ffff ff00 309c 2cd8 6612  ..........0.,.f.
000000b0: 6114 81ad 0ea1 548c 3aff ffbb a800 005d  a.....T.:......]
000000c0: 0000 8000 ffff ffff ffff ffff 0031 9a08  .............1..
000000d0: d48d a39e 7f43 87ff ffed 1780 0000 0000  .....C..........
"""
)
handler = MiniFSHandler()


def test_chunk_calculation():
    file = File.from_bytes(FILE_CONTENTS)
    chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == 221


@pytest.mark.parametrize(
    "contents, error",
    [
        (
            FILE_CONTENTS[:20] + bytes.fromhex("00 00 00 00") + FILE_CONTENTS[24:],
            "Invalid number of files",
        ),
        (
            FILE_CONTENTS[:20] + bytes.fromhex("FF FF FF FF") + FILE_CONTENTS[24:],
            "Invalid number of files",
        ),
        (
            FILE_CONTENTS[:24] + bytes.fromhex("00 00 00 00") + FILE_CONTENTS[28:],
            "Invalid first chunk size",
        ),
        (
            FILE_CONTENTS[:28] + bytes.fromhex("00 00 00 00") + FILE_CONTENTS[32:],
            "Invalid file name table length",
        ),
    ],
)
def test_invalid_chunk(contents, error):
    file = File.from_bytes(contents)
    with pytest.raises(InvalidInputFormat, match=error):
        handler.calculate_chunk(file, 0)
