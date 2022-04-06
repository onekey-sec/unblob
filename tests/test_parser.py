import pytest

from unblob.parser import hexstring2regex


@pytest.mark.parametrize(
    "hex_string, expected_regex",
    [
        pytest.param("00", rb"\x00", id="simple-byte"),
        pytest.param("00  01", rb"\x00\x01", id="simple-multi-byte"),
        pytest.param("00 ?? 02", rb"\x00.\x02", id="wildcard"),
        pytest.param("00 ?? ?? 02", rb"\x00..\x02", id="consecutive-wildcards"),
        pytest.param(
            "00 ?8 02",
            rb"\x00[\x08,\x18,\x28,\x38,\x48,\x58,\x68,\x78,\x88,\x98,\xa8,\xb8,\xc8,\xd8,\xe8,\xf8]\x02",
            id="first-nible-wildcard",
        ),
        pytest.param("00 8? 02", rb"\x00[\x80-\x8f]\x02", id="second-nible-wildcard"),
        pytest.param("00 [3] 02", rb"\x00.{3}\x02", id="simple-jump"),
        pytest.param("00 [2-4] 02", rb"\x00.{2,4}\x02", id="range-jump"),
        pytest.param(
            "00 ( 01 | 02 ) 03", rb"\x00(\x01|\x02)\x03", id="simple-alternative"
        ),
        pytest.param(
            "00 ( 01 | 02 | 03 ) 04",
            rb"\x00(\x01|\x02|\x03)\x04",
            id="multi-alternative",
        ),
        pytest.param(
            "00 ( 01 | 02 03 ) 04",
            rb"\x00(\x01|\x02\x03)\x04",
            id="multi-byte-alternative",
        ),
        pytest.param(
            "00 ( 01 02 | 03 04 ) 05",
            rb"\x00(\x01\x02|\x03\x04)\x05",
            id="multi-byte-alternative-2",
        ),
        pytest.param(
            "00 ( 01 | 02 ?? ) 04", rb"\x00(\x01|\x02.)\x04", id="wildcard-alternative"
        ),
        pytest.param(
            "00 ( 01 | 02 ( 03 | 04) ) 05",
            rb"\x00(\x01|\x02(\x03|\x04))\x05",
            id="nested-alternative",
        ),
    ],
)
def test_simple_convert(hex_string, expected_regex):
    regex = hexstring2regex(hex_string)

    assert expected_regex == regex


def test_single_line_comment():
    regex = hexstring2regex(
        """
  // inital comment
  01
  // comment
  02 // other comment
  // final comment
"""
    )

    assert regex == rb"\x01\x02"


def test_single_comment():
    regex = hexstring2regex("01 02 // other comment")

    assert regex == rb"\x01\x02"


def test_invalid_hexstring():
    with pytest.raises(ValueError):
        hexstring2regex("invalid hexstring")
