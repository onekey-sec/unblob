import pytest
from helpers import unhex

EMACS_VIM = """\
00000000: 0102 0304 0506 0708 090a 0b0c 0d0e 0f10  ................
00000010: 4142 4344 4546 4748 494a 4b4c 4d4e 4f44  ABCDEFGHIJKLMNOD
"""

HEXDUMP_C = """\
00000000  01 02 03 04 05 06 07 08  09 0a 0b 0c 0d 0e 0f 10  |................|
00000010  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 44  |ABCDEFGHIJKLMNOD|
00000020
"""

WITH_COMMENTS = """\
# Comments are supported
00000000  01 02 03 04 05 06 07 08  09 0a 0b 0c 0d 0e 0f 10  |................|
00000010  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 44  |ABCDEFGHIJKLMNOD|  # even at the end of lines
00000020  # also at the last line
"""

EXPECTED = b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10ABCDEFGHIJKLMNOD"


@pytest.mark.parametrize(
    "hexdump",
    (
        pytest.param(EMACS_VIM, id="Vim-Emacs"),
        pytest.param(HEXDUMP_C, id="hexdump-C"),
        pytest.param(WITH_COMMENTS, id="with-comments"),
    ),
)
def test_hexdump(hexdump):
    binary = unhex(hexdump)
    assert binary == EXPECTED


WITH_SQUEEZED_DATA = """\
00: 0102 0304 0506 0708 090a 0b0c 0d0e 0f10  ................
10: FF00 FF00 FF00 FF00 FF00 FF00 FF00 FF00  ................
*
30: 4142 4344 4546 4748 494a 4b4c 4d4e 4f44  ABCDEFGHIJKLMNOD
"""


def test_with_squized_data():
    binary = unhex(WITH_SQUEEZED_DATA)
    assert binary[:0x10] == EXPECTED[:0x10]
    assert binary[0x10:0x30] == b"\xFF\x00" * 0x10
    assert binary[0x30:] == EXPECTED[0x10:]


WITH_SQUEEZED_END = """\
00: FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF  ................
*
40
"""


def test_with_squized_end():
    binary = unhex(WITH_SQUEEZED_END)
    assert len(binary) == 0x40
    assert binary == b"\xFF" * 0x40
