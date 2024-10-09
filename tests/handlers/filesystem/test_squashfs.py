import io
from typing import Optional

import pytest

from unblob.file_utils import round_up
from unblob.handlers.filesystem.squashfs import (
    SquashFSv1Handler,
    SquashFSv3Handler,
    SquashFSv4BEHandler,
    SquashFSv4LEHandler,
)
from unblob.testing import unhex

SQUASHFS_V4_LE_NO_PAD_CONTENTS = unhex(
    """\
00000000  68 73 71 73 05 00 00 00  06 b6 03 62 00 00 02 00  |hsqs.......b....|
00000010  01 00 00 00 01 00 11 00  c0 00 01 00 04 00 00 00  |................|
00000020  80 00 00 00 00 00 00 00  34 01 00 00 00 00 00 00  |........4.......|
00000030  2c 01 00 00 00 00 00 00  ff ff ff ff ff ff ff ff  |,...............|
00000040  79 00 00 00 00 00 00 00  b9 00 00 00 00 00 00 00  |y...............|
00000050  fe 00 00 00 00 00 00 00  1e 01 00 00 00 00 00 00  |................|
00000060  78 da 4b 2c 28 c8 49 35  e4 4a 04 51 46 10 ca 18  |x.K,(.I5.J.QF...|
00000070  42 99 70 01 00 8b ee 09  3b 3e 00 78 da 63 62 58  |B.p.....;>.x.cbX|
00000080  c2 c8 00 04 17 37 33 27  81 19 48 80 1d 88 99 90  |.....73'..H.....|
00000090  e4 99 d0 e4 d0 e5 99 91  e4 f9 b0 c8 b3 20 c9 8b  |............. ..|
000000a0  42 e5 19 19 fe 82 e5 af  03 e5 59 a1 72 20 7b c2  |B.........Y.r {.|
000000b0  81 98 0d 88 01 97 54 0d  e3 33 00 78 da 63 66 80  |......T..3.x.cf.|
000000c0  00 46 28 cd c4 c0 c9 90  58 50 90 93 6a a8 57 52  |.F(.....XP..j.WR|
000000d0  51 a2 00 14 87 8b 18 81  44 1c 80 7c b8 88 31 48  |Q.......D..|..1H|
000000e0  24 81 81 19 21 62 02 12  01 00 10 1c 10 41 0e 00  |$...!b.......A..|
000000f0  78 da 4b 60 80 00 49 28  0d 00 06 d8 00 7a ee 00  |x.K`..I(.....z..|
00000100  00 00 00 00 00 00 16 00  78 da 63 60 80 00 05 28  |........x.c`...(|
00000110  ed 00 a5 13 a0 74 03 94  06 00 14 28 01 41 06 01  |.....t.....(.A..|
00000120  00 00 00 00 00 00 04 80  00 00 00 00 26 01 00 00  |............&...|
00000130  00 00 00 00                                       |....|
00000134
"""
)

SQUASHFS_V4_BE_NO_PAD_CONTENTS = unhex(
    """\
00000000  73 71 73 68 00 00 00 05  62 1f 9f 26 00 02 00 00  |................|
00000010  00 00 00 01 00 01 00 11  00 c0 00 01 00 04 00 00  |................|
00000020  00 00 00 00 00 00 00 80  00 00 00 00 00 00 01 33  |................|
00000030  00 00 00 00 00 00 01 2b  ff ff ff ff ff ff ff ff  |................|
00000040  00 00 00 00 00 00 00 79  00 00 00 00 00 00 00 b5  |................|
00000050  00 00 00 00 00 00 00 ff  00 00 00 00 00 00 01 1d  |................|
00000060  78 da 4b 2c 28 c8 49 35  e4 4a 04 51 46 10 ca 18  |................|
00000070  42 99 70 01 00 8b ee 09  3b 00 3a 78 da 63 60 62  |................|
00000080  5c c2 00 04 49 f2 b1 c1  40 8a 91 01 15 b0 33 a0  |................|
00000090  ca 33 a1 c8 61 ca 33 23  c9 f3 61 91 67 41 92 17  |................|
000000a0  05 cb 33 32 fe 45 92 67  85 ca 31 31 84 83 69 36  |................|
000000b0  00 55 b7 0a 45 00 36 78  da 63 60 60 60 66 80 00  |................|
000000c0  46 30 c9 c4 c0 99 58 50  90 93 6a a8 57 52 51 c2  |................|
000000d0  a0 00 14 85 89 18 81 45  1c 80 7c 98 88 31 58 24  |................|
000000e0  01 68 02 4c c4 04 24 02  00 0f 1e 10 41 80 10 00  |................|
000000f0  00 00 00 00 00 00 60 00  00 00 19 00 00 00 00 00  |................|
00000100  00 00 00 00 00 00 ed 00  14 78 da 63 60 40 01 0a  |................|
00000110  50 da 01 4a 27 40 e9 06  00 0b 68 01 41 00 00 00  |................|
00000120  00 00 00 01 07 80 04 00  00 03 e8 00 00 00 00 00  |................|
00000130  00 01 25                                          |...|
00000133
"""
)

SQUASHFS_V3_LE_NO_PAD_CONTENTS = unhex(
    """\
00000000  68 73 71 73 05 00 00 00  00 00 00 00 00 00 00 00  |hsqs............|
00000010  00 00 00 00 00 00 00 00  00 00 00 00 03 00 01 00  |................|
00000020  00 00 11 00 c0 01 00 c9  cc 03 62 80 00 00 00 00  |..........b.....|
00000030  00 00 00 00 00 02 00 01  00 00 00 00 00 00 00 40  |...............@|
00000040  01 00 00 00 00 00 00 3c  01 00 00 00 00 00 00 00  |.......<........|
00000050  00 00 00 00 00 00 00 90  00 00 00 00 00 00 00 cd  |................|
00000060  00 00 00 00 00 00 00 16  01 00 00 00 00 00 00 34  |...............4|
00000070  01 00 00 00 00 00 00 78  da 4b 2c 28 c8 49 35 e4  |.......x.K,(.I5.|
00000080  4a 04 51 46 10 ca 18 42  99 70 01 00 8b ee 09 3b  |J.QF...B.p.....;|
00000090  3b 00 78 da 73 92 62 f8  7f 71 33 73 12 33 03 26  |;.x.s.b..q3s.3.&|
000000a0  60 07 62 27 a8 3c 0b 16  39 64 79 56 34 79 3e 34  |`.b'.<..9dyV4y>4|
000000b0  79 26 34 79 51 a8 fc 45  79 86 ff d7 81 f2 8c 40  |y&4yQ..Ey......@|
000000c0  36 48 8d 07 54 9e 0d 88  01 cc 3c 11 94 37 00 78  |6H..T.....<..7.x|
000000d0  da 63 66 00 02 66 10 e1  c0 c9 c0 90 58 50 90 93  |.cf..f......XP..|
000000e0  6a a8 57 52 51 a2 e0 c0  c9 08 e1 1a 81 b8 0e 0e  |j.WRQ...........|
000000f0  9c 4c 10 ae 31 88 9b e0  c0 f9 ff 3f 98 6b 02 e2  |.L..1......?.k..|
00000100  02 00 01 31 13 36 0e 00  78 da 2b 67 80 00 49 28  |...1.6..x.+g..I(|
00000110  0d 00 08 48 00 91 06 01  00 00 00 00 00 00 14 00  |...H............|
00000120  78 da 6b 60 80 80 04 06  54 a0 00 a5 1d a0 34 00  |x.k`....T.....4.|
00000130  24 28 01 41 1e 01 00 00  00 00 00 00 00 00 00 00  |$(.A............|
00000140
"""
)

SQUASHFS_V3_BE_NO_PAD_CONTENTS = unhex(
    """\
00000000  73 71 73 68 00 00 00 05  00 00 00 00 00 00 00 00  |sqsh............|
00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 03 00 01  |................|
00000020  00 00 00 11 c0 01 00 62  03 cc c3 00 00 00 00 00  |.......b........|
00000030  00 00 80 00 02 00 00 00  00 00 01 00 00 00 00 00  |................|
00000040  00 00 00 00 00 01 40 00  00 00 00 00 00 01 3c 00  |......@.......<.|
00000050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 90 00  |................|
00000060  00 00 00 00 00 00 cb 00  00 00 00 00 00 01 14 00  |................|
00000070  00 00 00 00 00 01 34 78  da 4b 2c 28 c8 49 35 e4  |......4x.K,(.I5.|
00000080  4a 04 51 46 10 ca 18 42  99 70 01 00 8b ee 09 3b  |J.QF...B.p.....;|
00000090  00 39 78 da 53 5c c2 f0  3f 89 79 f3 45 06 06 06  |.9x.S\\..?.y.E...|
000000a0  66 06 4c c0 ae 88 90 67  41 97 43 93 67 45 93 e7  |f.L....gA.C.gE..|
000000b0  43 93 67 42 93 17 05 c9  0b fe 05 cb 5f 07 b2 19  |C.gB........_...|
000000c0  c1 6a 38 e1 f2 6c 00 6f  a6 13 17 00 35 78 da 63  |.j8..l.o....5x.c|
000000d0  66 80 00 66 06 26 4e 06  86 c4 82 82 9c 54 43 bd  |f..f.&N......TC.|
000000e0  92 8a 12 46 20 97 11 cc  35 02 71 99 80 5c 26 30  |...F ...5.q..\\&0|
000000f0  d7 18 c4 65 66 e2 fc ff  1f cc 35 01 71 01 cb 90  |...ef.....5.q...|
00000100  11 84 80 10 00 00 00 00  00 00 00 77 00 00 00 19  |...........w....|
00000110  00 00 00 00 00 00 00 00  00 00 01 02 00 16 78 da  |..............x.|
00000120  63 60 00 83 06 08 c5 90  c0 80 0a 14 a0 b4 03 00  |c`..............|
00000130  1b 68 01 41 00 00 00 00  00 00 01 1c 00 00 00 00  |.h.A............|
00000140
"""
)

SQUASHFS_V1_LE_NO_PAD_CONTENTS = unhex(
    """\
00000000  68 73 71 73 25 03 00 00  40 01 00 00 A3 12 4B 00  |hsqs%.....K...K.|
00000010  00 00 00 00 13 DF 4A 00  B0 F7 4A 00 01 00 00 00  |......J...J.....|
00000020  00 80 0F 00 00 01 00 A1  82 C8 4D 18 18 AD 0E 00  |..........M.....|
00000030  00 00 00 90 32 00 00 5D  00 80 00 00 00 3F 91 45  |....2..].....?.E|
00000040  84 68 3B DE DE A6 11 C2  7E 99 A6 01 25 A5 98 99  |.h;.....~...%...|
00000050  6C C8 E3 5F C6 96 35 39  B8 DC E2 A2 BC C3 6A C0  |l.._..59......j.|
00000060  84 B4 3E 33 48 CD 5F 6D  FC 6E 0E 10 F9 17 BA D0  |..>3H._m.n......|
00000070  D5 B8 6B D2 D1 5D 62 0D  8C A7 F1 C6 C8 C2 87 1D  |..k..]b.........|
00000080  5C C0 F3 5C 04 8D 96 3F  94 B9 F1 6B 12 67 F0 78  |\\..\\...?...k.g.x|
00000090  8C 73 66 F6 D6 15 A1 B2  0A EF BF DE DD B7 DD 40  |.sf............@|
000000a0  7B DD 13 2E 1F AD A3 E7  AB 77 DF A3 D9 28 D2 2E  |{........w...(..|
000000b0  83 B2 78 48 5C 1E 19 65  05 85 FD 58 A2 65 BD 83  |..xH\\..e...X.e..|
000000c0  D2 BE E6 C1 B6 27 94 99  AA 0E DF 70 75 85 0B 02  |.....'.....pu...|
000000d0  22 98 17 FE F8 7D 2E 9C  59 3A 24 17 13 0F 76 04  |"....}..Y:$...v.|
000000e0  F8 F2 26 A3 33 B1 3C 48  68 00 20 75 13 02 2D DF  |..&.3.<Hh. u..-.|
000000f0  E6 4B C4 25 9B 55 3F EB  C3 07 A7 69 38 51 9D 1C  |.K.%.U?....i8Q..|
00000100  0C 77 8C 35 9A 66 BE F8  B4 4B 28 59 B1 EB 54 11  |.w.5.f...K(Y..T.|
00000110  CB 14 69 9F 8A 41 BF 71  27 59 E2 32 2E B4 46 16  |..i..A.q'Y.2..F.|
00000120  B2 DB B2 1E 3A 47 B0 3E  70 D0 AE EC B7 62 5B 2E  |....:G.>p....b[.|
00000130  59 3D 3B 7A AD D3 D4 C6  8E 4A 53 A3 9F 88 E9 0A  |Y=;z.....JS.....|
00000140
"""
)


def pad_contents(contents: bytes, alignment: int):
    content_size = len(contents)
    padded_size = round_up(content_size, alignment)
    return contents + b"\0" * (padded_size - content_size)


@pytest.mark.parametrize(
    "contents, handler_class",
    [
        pytest.param(SQUASHFS_V4_LE_NO_PAD_CONTENTS, SquashFSv4LEHandler, id="v4_le"),
        pytest.param(SQUASHFS_V4_BE_NO_PAD_CONTENTS, SquashFSv4BEHandler, id="v4_be"),
        pytest.param(SQUASHFS_V3_LE_NO_PAD_CONTENTS, SquashFSv3Handler, id="v3_le"),
        pytest.param(SQUASHFS_V3_BE_NO_PAD_CONTENTS, SquashFSv3Handler, id="v3_be"),
        pytest.param(SQUASHFS_V1_LE_NO_PAD_CONTENTS, SquashFSv1Handler, id="v1_le"),
    ],
)
@pytest.mark.parametrize(
    "start",
    [
        pytest.param(b"", id="zero_start"),
        pytest.param(b"A" * 128, id="non_zero_start"),
    ],
)
@pytest.mark.parametrize(
    "pad_align",
    [
        pytest.param(None, id="no_pad"),
        pytest.param(1024, id="1k_pad"),
        pytest.param(4096, id="4k_pad"),
    ],
)
@pytest.mark.parametrize(
    "extra",
    [
        pytest.param(
            b"",
            id="no_extra_end",
        ),
        pytest.param(
            b"A" * 128,
            id="extra_end",
        ),
        pytest.param(
            b"A" * 4096,
            id="extra_long_end",
        ),
        pytest.param(
            b"\0" * 128,
            id="extra_null_end",
        ),
        pytest.param(
            b"\0" * 128 + b"A" + b"\0" * 4096,
            id="extra-non-null-pad",
        ),
    ],
)
def test_squashfs_chunk_is_detected(
    contents: bytes, handler_class, start: bytes, pad_align: Optional[int], extra: bytes
):
    start_offset = len(start)
    if pad_align is None:
        pad_align = len(contents)
    complete_content = pad_contents(contents, pad_align)

    chunk = handler_class().calculate_chunk(
        io.BytesIO(start + complete_content + extra), start_offset
    )

    assert chunk.start_offset == start_offset
    assert chunk.end_offset == start_offset + pad_align


@pytest.mark.parametrize(
    "contents, handler_class",
    [
        pytest.param(SQUASHFS_V4_LE_NO_PAD_CONTENTS, SquashFSv4LEHandler, id="v4_le"),
        pytest.param(SQUASHFS_V4_BE_NO_PAD_CONTENTS, SquashFSv4BEHandler, id="v4_be"),
        pytest.param(SQUASHFS_V3_LE_NO_PAD_CONTENTS, SquashFSv3Handler, id="v3_le"),
        pytest.param(SQUASHFS_V3_BE_NO_PAD_CONTENTS, SquashFSv3Handler, id="v3_be"),
    ],
)
def test_squashfs_incomplete_header(contents: bytes, handler_class):
    with pytest.raises(EOFError):
        handler_class().calculate_chunk(io.BytesIO(contents[:10]), 0)


@pytest.mark.parametrize(
    "contents, handler_class",
    [
        pytest.param(SQUASHFS_V4_LE_NO_PAD_CONTENTS, SquashFSv4LEHandler, id="v4_le"),
        pytest.param(SQUASHFS_V4_BE_NO_PAD_CONTENTS, SquashFSv4BEHandler, id="v4_be"),
        pytest.param(SQUASHFS_V3_LE_NO_PAD_CONTENTS, SquashFSv3Handler, id="v3_le"),
        pytest.param(SQUASHFS_V3_BE_NO_PAD_CONTENTS, SquashFSv3Handler, id="v3_be"),
    ],
)
def test_squashfs_incomplete_file(contents: bytes, handler_class):
    chunk = handler_class().calculate_chunk(io.BytesIO(contents[:-10]), 0)

    # It is ok to return the whole chunk, incomplete files are taken care by the framework
    # the handlers does not need to manage that
    assert chunk.start_offset == 0
    assert chunk.end_offset == len(contents)
