import copy

import pytest

from unblob.file_utils import File
from unblob.handlers.archive.arj import ARJChecksumError, ARJHandler, InvalidARJSize
from unblob.testing import unhex

ARJ_CONTENTS = unhex(
    """\
00000000  60 ea 2c 00 22 0b 01 02  10 00 02 06 bd 5d 9f 61  |`.,."........].a|
00000010  bd 5d 9f 61 00 00 00 00  00 00 00 00 00 00 00 00  |.].a............|
00000020  00 00 00 00 00 00 62 6c  61 68 2e 61 72 6a 00 00  |......blah.arj..|
00000030  57 06 57 c8 00 00 60 ea  39 00 2e 0b 01 02 10 00  |W.W...`.9.......|
00000040  00 bd bb 5d 9f 61 06 00  00 00 06 00 00 00 c6 6e  |...].a.........n|
00000050  0a fa 00 00 ff 11 00 00  00 00 00 00 bc 5d 9f 61  |.............].a|
00000060  bb 5d 9f 61 00 00 00 00  6b 61 6b 69 31 2e 74 78  |.].a....kaki1.tx|
00000070  74 00 00 7b d1 b4 cc 00  00 6b 61 6b 69 31 0a 60  |t..{.....kaki1.`|
00000080  ea 39 00 2e 0b 01 02 10  00 00 bd be 5d 9f 61 06  |.9..........].a.|
00000090  00 00 00 06 00 00 00 05  3d 27 d1 00 00 ff 11 00  |........='......|
000000a0  00 00 00 00 00 bf 5d 9f  61 be 5d 9f 61 00 00 00  |......].a.].a...|
000000b0  00 6b 61 6b 69 32 2e 74  78 74 00 00 06 fa 03 b9  |.kaki2.txt......|
000000c0  00 00 6b 61 6b 69 32 0a  60 ea 39 00 2e 0b 01 02  |..kaki2.`.9.....|
000000d0  10 00 00 bd c2 5d 9f 61  06 00 00 00 06 00 00 00  |.....].a........|
000000e0  44 0c 3c c8 00 00 ff 11  00 00 00 00 00 00 c3 5d  |D.<............]|
000000f0  9f 61 c2 5d 9f 61 00 00  00 00 6b 61 6b 69 33 2e  |.a.].a....kaki3.|
00000100  74 78 74 00 00 7b f8 8b  43 00 00 6b 61 6b 69 33  |txt..{..C..kaki3|
00000110  0a 60 ea 39 00 2e 0b 01  02 10 00 00 bd c6 5d 9f  |.`.9..........].|
00000120  61 06 00 00 00 06 00 00  00 83 9a 7d 87 00 00 ff  |a..........}....|
00000130  11 00 00 00 00 00 00 c6  5d 9f 61 c6 5d 9f 61 00  |........].a.].a.|
00000140  00 00 00 6b 61 6b 69 34  2e 74 78 74 00 00 c1 02  |...kaki4.txt....|
00000150  56 96 00 00 6b 61 6b 69  34 0a 60 ea 00 00 ff ff  |V...kaki4.`.....|
"""
)

# last two bytes are extra padding


def test_valid_calculation():
    contents_len = len(ARJ_CONTENTS)
    f = File.from_bytes(ARJ_CONTENTS)

    handler = ARJHandler()
    chunk = handler.calculate_chunk(f, 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == contents_len - 2


@pytest.mark.parametrize(
    "header_size",
    [
        pytest.param(0, id="size-small"),
        pytest.param(2700, id="size-large"),
        pytest.param(31, id="size-smaller-then-first_hdr_size"),
    ],
)
def test_invalid_block_size(header_size):
    contents = bytearray(copy.copy(ARJ_CONTENTS))
    contents[2] = header_size & 0xFF
    contents[3] = (header_size & 0xFF00) >> 8
    f = File.from_bytes(contents)
    f.seek(0)

    handler = ARJHandler()
    with pytest.raises(InvalidARJSize):
        handler._read_arj_main_header(f, 0)  # noqa: SLF001


def test_invalid_checksum():
    contents = bytearray(copy.copy(ARJ_CONTENTS))
    contents[4] = 0
    f = File.from_bytes(contents)
    f.seek(0)

    handler = ARJHandler()
    with pytest.raises(ARJChecksumError):
        handler._read_arj_main_header(f, 0)  # noqa: SLF001
