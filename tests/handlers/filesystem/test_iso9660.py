import pytest

from unblob.handlers.filesystem.iso9660 import from_723, from_733


@pytest.mark.parametrize(
    "value, expected",
    [
        (b"\x00\x00\x00\x00", 0),
        ([176, 0, 0, 0], 176),
        ([0, 8, 8, 0], 0x80800),
        ([0xFF, 0xFF, 0xFF, 0xFF], 0xFF_FF_FF_FF),
        (b"\xff\xff\xff\xff", 0xFF_FF_FF_FF),
    ],
)
def test_from_733(value, expected):
    assert from_733(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (b"\x00\x00\x00\x00", 0),
        (b"\x00\x00", 0),
        ([176, 0, 0, 0, 0, 0, 0, 176], 176),
        ([176, 0, 0, 0], 176),
        ([0, 8, 8, 0], 2048),
        ([0, 8], 2048),
        ([0xFF, 0xFF, 0xFF, 0xFF], 0xFFFF),
        ([0xFF, 0xFF], 0xFFFF),
        (b"\xff\xff\xff\xff", 0xFFFF),
    ],
)
def test_from_723(value, expected):
    assert from_723(value) == expected
