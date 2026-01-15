import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.dlink.deafbead import DeafBeadHandler
from unblob.testing import unhex

DB_FILE_CONTENTS = unhex(
    """\
00000000: deaf bead 8608 0074 6573 745f 6469 7287  .......test_dir.
00000010: 1300 7465 7374 5f64 6972 5c66 6f6f 6261  ..test_dir\\fooba
00000020: 722e 7478 741b 0000 001f 8b08 0064 d968  r.txt........d.h
00000030: 6902 ff4b cbcf 4f4a 2ce2 0200 4797 2cb2  i..K..OJ,...G.,.
00000040: 0700 0000 8708 0074 6573 742e 7478 741d  .......test.txt.
00000050: 0000 001f 8b08 0064 d968 6902 ff2b 492d  .......d.hi..+I-
00000060: 2e31 3432 36e1 0200 f54d cf25 0900 0000  .1426....M.%....
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
"""
)

INVALID = unhex(
    """\
00000000: deaf bead 86ff ffff ffff ffff ffff ffff  ................
00000010: ffff ffff ffff ffff ffff ffff ffff ffff  ................
"""
)


@pytest.mark.parametrize(
    "end_index",
    [
        0x70,  # file ends at end of deafbead file
        0x80,  # some padding after deafbead file
    ],
)
def test_chunk_calculation(end_index):
    file = File.from_bytes(DB_FILE_CONTENTS[:end_index])
    handler = DeafBeadHandler()
    chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == 0x70


@pytest.mark.parametrize(
    "contents, error",
    [
        (INVALID, EOFError),
        (bytes.fromhex("deafbead 86 00"), EOFError),
        (bytes.fromhex("deafbead 86 0000"), InvalidInputFormat),
        (bytes.fromhex("deafbead 87 00"), EOFError),
        (bytes.fromhex("deafbead 87 0100 00 00000000"), InvalidInputFormat),
        (bytes.fromhex("deafbead 87 0100 00 01000000"), EOFError),
    ],
)
def test_invalid_chunk(contents, error):
    file = File.from_bytes(contents)
    handler = DeafBeadHandler()
    with pytest.raises(error):
        handler.calculate_chunk(file, 0)
