import binascii

import pytest
from helpers import unhex

from unblob.file_utils import Endian, File
from unblob.handlers.filesystem.jffs2 import JFFS2NewHandler, JFFS2OldHandler

VALID_JFFS2_NEW_LE_HEADER_CONTENT = unhex(
    """\
00000000  85 19 03 20 0c 00 00 00  b1 b0 1e e4 85 19 01 e0  |... ............|
"""
)

VALID_JFFS2_NEW_BE_HEADER_CONTENT = unhex(
    """\
00000000  19 85 20 03 00 00 00 0c  f0 60 dc 98 19 85 e0 01  |.. ......`......|
"""
)

VALID_JFFS2_OLD_LE_HEADER_CONTENT = unhex(
    """\
00000000  84 19 03 20 0c 00 00 00  2f b0 b4 28 84 19 01 e0  |... ..../..(....|
"""
)

VALID_JFFS2_OLD_BE_HEADER_CONTENT = unhex(
    """\
00000000  19 84 20 03 00 00 00 0c  56 17 d7 2c 19 84 e0 01  |.. .....V..,....|
"""
)

new_handler = JFFS2NewHandler()
old_handler = JFFS2OldHandler()


def get_valid_jffs2_new_le_header():
    return new_handler.parse_header(
        File.from_bytes(VALID_JFFS2_NEW_LE_HEADER_CONTENT), Endian.LITTLE
    )


def get_valid_jffs2_new_be_header():
    return new_handler.parse_header(
        File.from_bytes(VALID_JFFS2_NEW_BE_HEADER_CONTENT), Endian.BIG
    )


def get_valid_jffs2_old_le_header():
    return old_handler.parse_header(
        File.from_bytes(VALID_JFFS2_OLD_LE_HEADER_CONTENT), Endian.LITTLE
    )


def get_valid_jffs2_old_be_header():
    return old_handler.parse_header(
        File.from_bytes(VALID_JFFS2_OLD_BE_HEADER_CONTENT), Endian.BIG
    )


def calculate_crc(header):
    return (binascii.crc32(header.dumps()[:-4], -1) ^ -1) & 0xFFFFFFFF


NODE_SIZE = 0x1000
JFFS2_NODE_ACCURATE = 0x2000
JFFS2_FEATURE_INCOMPAT = 0xC000
JFFS2_INVALID_NODE = 10
INVALID_NODETYPE = JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | JFFS2_INVALID_NODE
INACURATE_DIRENT = JFFS2_FEATURE_INCOMPAT | 1


VALID_JFFS2_NEW_LE_HEADER = get_valid_jffs2_new_le_header()
VALID_JFFS2_NEW_BE_HEADER = get_valid_jffs2_new_be_header()
VALID_JFFS2_OLD_LE_HEADER = get_valid_jffs2_old_le_header()
VALID_JFFS2_OLD_BE_HEADER = get_valid_jffs2_old_be_header()

JFFS2_NEW_LE_HEADER_INVALID_NODE = get_valid_jffs2_new_le_header()
JFFS2_NEW_LE_HEADER_INVALID_NODE.nodetype = INVALID_NODETYPE
JFFS2_NEW_LE_HEADER_INACURATE_NODE = get_valid_jffs2_new_le_header()
JFFS2_NEW_LE_HEADER_INACURATE_NODE.nodetype = INACURATE_DIRENT
JFFS2_NEW_LE_HEADER_PAST_EOF = get_valid_jffs2_new_le_header()
JFFS2_NEW_LE_HEADER_PAST_EOF.totlen = NODE_SIZE + 1
JFFS2_NEW_LE_HEADER_HIGH_TOTLEN = get_valid_jffs2_new_le_header()
JFFS2_NEW_LE_HEADER_HIGH_TOTLEN.totlen = len(JFFS2_NEW_LE_HEADER_INVALID_NODE) - 1

JFFS2_NEW_BE_HEADER_INVALID_NODE = get_valid_jffs2_new_be_header()
JFFS2_NEW_BE_HEADER_INVALID_NODE.nodetype = INVALID_NODETYPE
JFFS2_NEW_BE_HEADER_INACURATE_NODE = get_valid_jffs2_new_be_header()
JFFS2_NEW_BE_HEADER_INACURATE_NODE.nodetype = INACURATE_DIRENT
JFFS2_NEW_BE_HEADER_PAST_EOF = get_valid_jffs2_new_be_header()
JFFS2_NEW_BE_HEADER_PAST_EOF.totlen = NODE_SIZE + 1
JFFS2_NEW_BE_HEADER_HIGH_TOTLEN = get_valid_jffs2_new_be_header()
JFFS2_NEW_BE_HEADER_HIGH_TOTLEN.totlen = len(JFFS2_NEW_BE_HEADER_HIGH_TOTLEN) - 1

JFFS2_OLD_LE_HEADER_INVALID_NODE = get_valid_jffs2_old_le_header()
JFFS2_OLD_LE_HEADER_INVALID_NODE.nodetype = INVALID_NODETYPE
JFFS2_OLD_LE_HEADER_INACURATE_NODE = get_valid_jffs2_old_le_header()
JFFS2_OLD_LE_HEADER_INACURATE_NODE.nodetype = INACURATE_DIRENT
JFFS2_OLD_LE_HEADER_PAST_EOF = get_valid_jffs2_old_le_header()
JFFS2_OLD_LE_HEADER_PAST_EOF.totlen = NODE_SIZE + 1
JFFS2_OLD_LE_HEADER_HIGH_TOTLEN = get_valid_jffs2_old_le_header()
JFFS2_OLD_LE_HEADER_HIGH_TOTLEN.totlen = len(JFFS2_OLD_LE_HEADER_HIGH_TOTLEN) - 1

JFFS2_OLD_BE_HEADER_INVALID_NODE = get_valid_jffs2_old_be_header()
JFFS2_OLD_BE_HEADER_INVALID_NODE.nodetype = INVALID_NODETYPE
JFFS2_OLD_BE_HEADER_INACURATE_NODE = get_valid_jffs2_old_be_header()
JFFS2_OLD_BE_HEADER_INACURATE_NODE.nodetype = INACURATE_DIRENT
JFFS2_OLD_BE_HEADER_PAST_EOF = get_valid_jffs2_old_be_header()
JFFS2_OLD_BE_HEADER_PAST_EOF.totlen = NODE_SIZE + 1
JFFS2_OLD_BE_HEADER_HIGH_TOTLEN = get_valid_jffs2_old_be_header()
JFFS2_OLD_BE_HEADER_HIGH_TOTLEN.totlen = len(JFFS2_OLD_BE_HEADER_HIGH_TOTLEN) - 1


@pytest.mark.parametrize(
    "header, node_start_offset, eof, expected",
    [
        pytest.param(
            VALID_JFFS2_NEW_LE_HEADER,
            0,
            NODE_SIZE,
            True,
            id="jffs2-new-le-valid-header",
        ),
        pytest.param(
            VALID_JFFS2_NEW_BE_HEADER,
            0,
            NODE_SIZE,
            True,
            id="jffs2-new-be-valid-header",
        ),
        pytest.param(
            JFFS2_NEW_LE_HEADER_INVALID_NODE,
            0,
            NODE_SIZE,
            False,
            id="jffs2-new-le-invalid-node",
        ),
        pytest.param(
            JFFS2_NEW_LE_HEADER_INACURATE_NODE,
            0,
            NODE_SIZE,
            True,
            id="jffs2-new-le-inacurate-header",
        ),
        pytest.param(
            JFFS2_NEW_LE_HEADER_PAST_EOF,
            0,
            NODE_SIZE,
            False,
            id="jffs2-new-le-past-eof",
        ),
        pytest.param(
            JFFS2_NEW_LE_HEADER_HIGH_TOTLEN,
            0,
            NODE_SIZE,
            False,
            id="jffs2-new-le-high-totlen",
        ),
        pytest.param(
            JFFS2_NEW_BE_HEADER_INVALID_NODE,
            0,
            NODE_SIZE,
            False,
            id="jffs2-new-be-invalid-node",
        ),
        pytest.param(
            JFFS2_NEW_BE_HEADER_INACURATE_NODE,
            0,
            NODE_SIZE,
            True,
            id="jffs2-new-be-inacurate-header",
        ),
        pytest.param(
            JFFS2_NEW_BE_HEADER_PAST_EOF,
            0,
            NODE_SIZE,
            False,
            id="jffs2-new-be-past-eof",
        ),
        pytest.param(
            JFFS2_NEW_BE_HEADER_HIGH_TOTLEN,
            0,
            NODE_SIZE,
            False,
            id="jffs2-new-be-high-totlen",
        ),
    ],
)
def test_valid_header_new(header, node_start_offset: int, eof: int, expected: bool):
    header.hdr_crc = calculate_crc(header)
    assert new_handler.valid_header(header, node_start_offset, eof) == expected


@pytest.mark.parametrize(
    "header, node_start_offset, eof, expected",
    [
        pytest.param(
            VALID_JFFS2_OLD_LE_HEADER,
            0,
            NODE_SIZE,
            True,
            id="jffs2-old-le-valid-header",
        ),
        pytest.param(
            VALID_JFFS2_OLD_BE_HEADER,
            0,
            NODE_SIZE,
            True,
            id="jffs2-old-be-valid-header",
        ),
        pytest.param(
            JFFS2_OLD_LE_HEADER_INVALID_NODE,
            0,
            NODE_SIZE,
            False,
            id="jffs2-old-le-invalid-node",
        ),
        pytest.param(
            JFFS2_OLD_LE_HEADER_INACURATE_NODE,
            0,
            NODE_SIZE,
            True,
            id="jffs2-old-le-inacurate-header",
        ),
        pytest.param(
            JFFS2_OLD_LE_HEADER_PAST_EOF,
            0,
            NODE_SIZE,
            False,
            id="jffs2-old-le-past-eof",
        ),
        pytest.param(
            JFFS2_OLD_LE_HEADER_HIGH_TOTLEN,
            0,
            NODE_SIZE,
            False,
            id="jffs2-old-le-high-totlen",
        ),
        pytest.param(
            JFFS2_OLD_BE_HEADER_INVALID_NODE,
            0,
            NODE_SIZE,
            False,
            id="jffs2-old-be-invalid-node",
        ),
        pytest.param(
            JFFS2_OLD_BE_HEADER_INACURATE_NODE,
            0,
            NODE_SIZE,
            True,
            id="jffs2-old-be-inacurate-header",
        ),
        pytest.param(
            JFFS2_OLD_BE_HEADER_PAST_EOF,
            0,
            NODE_SIZE,
            False,
            id="jffs2-old-be-past-eof",
        ),
        pytest.param(
            JFFS2_OLD_BE_HEADER_HIGH_TOTLEN,
            0,
            NODE_SIZE,
            False,
            id="jffs2-old-be-high-totlen",
        ),
    ],
)
def test_valid_header_old(header, node_start_offset: int, eof: int, expected: bool):
    header.hdr_crc = calculate_crc(header)
    assert old_handler.valid_header(header, node_start_offset, eof) == expected


@pytest.mark.parametrize(
    "header",
    [
        pytest.param(VALID_JFFS2_NEW_LE_HEADER, id="new LE"),
        pytest.param(VALID_JFFS2_NEW_BE_HEADER, id="new BE"),
        pytest.param(VALID_JFFS2_OLD_LE_HEADER, id="old LE"),
        pytest.param(VALID_JFFS2_OLD_BE_HEADER, id="old BE"),
    ],
)
def test_invalid_crc(header):
    header.hdr_crc += 1
    assert old_handler.valid_header(header, 0, NODE_SIZE) is False
