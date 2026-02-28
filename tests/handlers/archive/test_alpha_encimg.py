import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.dlink.alpha_encimg import (
    AlphaEncimgHandler,
    AlphaEncimgV2Handler,
)
from unblob.testing import unhex

FILE_CONTENTS_V1 = unhex(
    """\
00000000: f52a a0b4 9253 bfef f821 a62e 28a7 398b  .*...S...!..(.9.
00000010: c353 6d97 101a 76ff 489d ea94 21e4 7ee5  .Sm...v.H...!.~.
00000020: db0c eb46 05e4 e3fd d3ce 38d2 8987 a932  ...F......8....2
00000030: f53e 809b f0d2 8d2d c9a2 76af 1997 6f12  .>.....-..v...o.
00000040: 0d52 ccbb a0d2 3555 c83e eb1e 8334 11ba  .R....5U.>...4..
00000050: 5bdd 56bc 04ef 2469 4db1 022f 6df2 b877  [.V...$iM../m..w
00000060: 9d28 af55 2a60 bb35 f8e6 87a5 cbf0 b198  .(.U*`.5........
00000070: 2fde 451f cb18 b70c 6ec0 85fc 526b 4805  /.E.....n...RkH.
00000080: 2b13 1235 fc27 199e dc6a 0d4a 2366 668e  +..5.'...j.J#ff.
00000090: cc35 56b5 e915 c4e0 7f86 a120 bfe3 0972  .5V........ ...r
000000a0: 61ec d2cc 53fb 099d 10d7 8f8c 531a 5780  a...S.......S.W.
000000b0: 017b 7dbc 3430 baa0 7550 fb14 00ea 33a9  .{}.40..uP....3.
000000c0: 5436 0ec5 a253 19e6 43a2 2ac6 2000 808e  T6...S..C.*. ...
"""
)
V2_SIZE_OFFSET = 0x68
FILE_CONTENTS_V2_LE = unhex(
    """\
00000000: 7761 7061 6333 305f 646b 6273 5f64 6170  wapac30_dkbs_dap
00000010: 3236 3130 0000 0000 0000 0000 0000 0000  2610............
00000020: 2103 0820 2103 0820 7632 2e30 3672 3038  !.. !.. v2.06r08
00000030: 3973 3839 3830 3800 6461 7032 3631 3000  9s89808.dap2610.
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 1000 0000 0000 0000  ................
00000070: 2f64 6576 2f75 7261 6e64 6f6d 0000 0000  /dev/urandom....
00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000090: 8ea3 0e0a 7ac2 40b3 bc33 9e3c 1343 0802  ....z.@..3.<.C..
000000a0: d6bd 2993 c5da 1c58 f8b0 0f0b 776f e3f2  ..)....X....wo..
"""
)
FILE_CONTENTS_V2_BE = (
    FILE_CONTENTS_V2_LE[:V2_SIZE_OFFSET]
    + bytes.fromhex("00 00 00 10")
    + FILE_CONTENTS_V2_LE[V2_SIZE_OFFSET + 4 :]
)

HANDLER_V1 = AlphaEncimgHandler()
HANDLER_V2 = AlphaEncimgV2Handler()


@pytest.mark.parametrize("padding", [0, 16, 64])
@pytest.mark.parametrize(
    "contents, handler, start_offset, end_offset",
    [
        (FILE_CONTENTS_V1, HANDLER_V1, 0, 0xD0),
        (
            FILE_CONTENTS_V2_LE,
            HANDLER_V2,
            -AlphaEncimgV2Handler.PATTERN_MATCH_OFFSET,
            HANDLER_V2.HEADER_SIZE + 0x10,
        ),
        (
            FILE_CONTENTS_V2_BE,
            HANDLER_V2,
            -AlphaEncimgV2Handler.PATTERN_MATCH_OFFSET,
            HANDLER_V2.HEADER_SIZE + 0x10,
        ),
    ],
)
def test_chunk_calculation(padding, contents, handler, start_offset, end_offset):
    file = File.from_bytes(contents + b"\0" * padding)
    chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.start_offset == start_offset
    assert chunk.end_offset == end_offset


@pytest.mark.parametrize(
    "contents, error, handler",
    [
        (
            FILE_CONTENTS_V1[:0x38] + b"\xff" * 4 + FILE_CONTENTS_V1[0x3C:],
            "Invalid file size",
            HANDLER_V1,
        ),
        (
            b"\0" * HANDLER_V1.HEADER_SIZE,
            "Device not supported",
            HANDLER_V1,
        ),
        (
            FILE_CONTENTS_V2_LE[:V2_SIZE_OFFSET]
            + b"\xff" * 4
            + FILE_CONTENTS_V2_LE[V2_SIZE_OFFSET + 4 :],
            "Invalid file size",
            HANDLER_V2,
        ),
        (
            FILE_CONTENTS_V2_LE[:V2_SIZE_OFFSET]
            + b"\1\0\0\0"
            + FILE_CONTENTS_V2_LE[V2_SIZE_OFFSET + 4 :],
            "not aligned",
            HANDLER_V2,
        ),
    ],
)
def test_invalid_chunk(contents, error, handler):
    file = File.from_bytes(contents)
    with pytest.raises(InvalidInputFormat, match=error):
        handler.calculate_chunk(file, 0)
