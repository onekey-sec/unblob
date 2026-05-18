from unblob.file_utils import File
from unblob.handlers.archive.moxa.frm import MoxaFRMHandler
from unblob.testing import unhex

FILE_CONTENTS = unhex(
    """\
00000000: 2a46 524d 0000 0001 cc92 0e00 6000 0200  *FRM........`...
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0200 0000 6000 0000 d08c 0300 0000 0000  ....`...........
00000050: 0100 0000 308d 0300 9c05 0b00 0000 0000  ....0...........
00000060: 5265 6461 6374 6564 0000 0000 0000 0000  Redacted........
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0103 5d74 4668 101d 0200 2e79 1f01  ....]tFh.....y..
00000090: 0001 0000 000f 0000 4000 3c00 d07c 0300  ........@.<..|..
"""
)
handler = MoxaFRMHandler()


def test_chunk_calculation():
    file = File.from_bytes(FILE_CONTENTS)
    chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == 0xE92CC
