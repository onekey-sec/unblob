import io
from typing import List

import pytest

from unblob.file_utils import (
    Endian,
    File,
    InvalidInputFormat,
    StructParser,
    convert_int8,
    convert_int16,
    convert_int32,
    convert_int64,
    decode_multibyte_integer,
    get_endian,
    iterate_file,
    iterate_patterns,
    round_down,
    round_up,
)


@pytest.mark.parametrize(
    "size, alignment, result",
    [
        (0, 5, 0),
        (1, 10, 0),
        (12, 10, 10),
        (29, 10, 20),
        (1, 512, 0),
    ],
)
def test_round_down(size, alignment, result):
    assert round_down(size, alignment) == result


@pytest.mark.parametrize(
    "size, alignment, result",
    [
        (0, 5, 0),
        (1, 10, 10),
        (12, 10, 20),
        (22, 10, 30),
        (1, 512, 512),
    ],
)
def test_round_up(size, alignment, result):
    assert round_up(size, alignment) == result


@pytest.fixture
def fake_file() -> File:
    return File.from_bytes(b"0123456789abcdefghijklmnopqrst")


class TestStructParser:
    def test_parse_correct_endianness(self):
        test_content = b"\x01\x02\x03\x04"
        fake_file = File.from_bytes(test_content)

        definitions = r"""
        struct squashfs_header
        {
            uint32 inodes;
        }
        """
        parser = StructParser(definitions)

        header = parser.parse("squashfs_header", fake_file, Endian.BIG)
        assert header.inodes == 0x01_02_03_04

        fake_file = File.from_bytes(test_content)
        header2 = parser.parse("squashfs_header", fake_file, Endian.LITTLE)
        assert header2.inodes == 0x04_03_02_01


class TestConvertInt8:
    @pytest.mark.parametrize(
        "value, endian, expected",
        [
            (b"\x00", Endian.LITTLE, 0x0),
            (b"\x00", Endian.BIG, 0x0),
            (b"\xff", Endian.LITTLE, 0xFF),
            (b"\xff", Endian.BIG, 0xFF),
            (b"\x10", Endian.LITTLE, 0x10),
            (b"\x10", Endian.BIG, 0x10),
        ],
    )
    def test_convert_int8(self, value: bytes, endian: Endian, expected: int):
        assert convert_int8(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        [
            (b"", Endian.LITTLE),
            (b"", Endian.BIG),
            (b"\x00\x00", Endian.LITTLE),
            (b"\x00\x00", Endian.BIG),
            (b"\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff\xff", Endian.BIG),
        ],
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int8(value, endian)


class TestConvertInt16:
    @pytest.mark.parametrize(
        "value, endian, expected",
        [
            (b"\x00\x00", Endian.LITTLE, 0x0),
            (b"\x00\x00", Endian.BIG, 0x0),
            (b"\xff\xff", Endian.LITTLE, 0xFFFF),
            (b"\xff\xff", Endian.BIG, 0xFFFF),
            (b"\x10\x00", Endian.LITTLE, 0x10),
            (b"\x10\x00", Endian.BIG, 0x1000),
        ],
    )
    def test_convert_int16(self, value: bytes, endian: Endian, expected: int):
        assert convert_int16(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        [
            (b"", Endian.LITTLE),
            (b"", Endian.BIG),
            (b"\xff", Endian.LITTLE),
            (b"\xff", Endian.BIG),
            (b"\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff", Endian.BIG),
        ],
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int16(value, endian)


class TestConvertInt32:
    @pytest.mark.parametrize(
        "value, endian, expected",
        [
            (b"\x00\x00\x00\x00", Endian.LITTLE, 0x0),
            (b"\x00\x00\x00\x00", Endian.BIG, 0x0),
            (b"\xff\xff\xff\xff", Endian.LITTLE, 0xFFFFFFFF),
            (b"\xff\xff\xff\xff", Endian.BIG, 0xFFFFFFFF),
            (b"\x10\x00\x00\x00", Endian.LITTLE, 0x10),
            (b"\x10\x00\x00\x00", Endian.BIG, 0x10000000),
        ],
    )
    def test_convert_int32(self, value: bytes, endian: Endian, expected: int):
        assert convert_int32(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        [
            (b"", Endian.LITTLE),
            (b"", Endian.BIG),
            (b"\x00", Endian.LITTLE),
            (b"\x00", Endian.BIG),
            (b"\x00\x00", Endian.LITTLE),
            (b"\x00\x00", Endian.BIG),
            (b"\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff\xff", Endian.BIG),
        ],
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int32(value, endian)


class TestConvertInt64:
    @pytest.mark.parametrize(
        "value, endian, expected",
        [
            (b"\x00\x00\x00\x00\x00\x00\x00\x00", Endian.LITTLE, 0x0),
            (b"\x00\x00\x00\x00\x00\x00\x00\x00", Endian.BIG, 0x0),
            (b"\xff\xff\xff\xff\xff\xff\xff\xff", Endian.LITTLE, 0xFFFF_FFFF_FFFF_FFFF),
            (b"\xff\xff\xff\xff\xff\xff\xff\xff", Endian.BIG, 0xFFFF_FFFF_FFFF_FFFF),
            (b"\x10\x00\x00\x00\x00\x00\x00\x00", Endian.LITTLE, 0x10),
            (b"\x10\x00\x00\x00\x00\x00\x00\x00", Endian.BIG, 0x1000_0000_0000_0000),
        ],
    )
    def test_convert_int64(self, value: bytes, endian: Endian, expected: int):
        assert convert_int64(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        [
            (b"", Endian.LITTLE),
            (b"", Endian.BIG),
            (b"\x00", Endian.LITTLE),
            (b"\x00", Endian.BIG),
            (b"\x00\x00", Endian.LITTLE),
            (b"\x00\x00", Endian.BIG),
            (b"\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff\xff\xff\xff", Endian.BIG),
        ],
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int64(value, endian)


class TestMultibytesInteger:
    @pytest.mark.parametrize(
        "value, expected",
        [
            (b"\x00", (1, 0)),
            (b"\x01", (1, 1)),
            (b"\x01\x00", (1, 1)),
            (b"\x7f", (1, 127)),
            (b"\x7f\x00", (1, 127)),
            (b"\xff\x00", (2, 127)),
            (b"\x80\x08\x00", (2, 1024)),
            (b"\xff\xff\xff\xff\xff\xff\xff\x7f", (8, 0xFFFFFFFFFFFFFF)),
        ],
    )
    def test_decode_multibyte_integer(self, value: bytes, expected: int):
        assert decode_multibyte_integer(value) == expected

    @pytest.mark.parametrize(
        "value",
        [
            (b""),
            (b"\xff"),
            (b"\xff\xff\xff"),
        ],
    )
    def test_decode_invalid_values(self, value: bytes):
        with pytest.raises(InvalidInputFormat):
            decode_multibyte_integer(value)


@pytest.mark.parametrize(
    "content, pattern, expected",
    [
        (b"abcdef 123", b"abcdef", [0]),
        (b"abcdef abc", b"abcdef", [0]),
        (b"abcdef abcdef", b"abcdef", [0, 7]),
        (b"abcd", b"abcd", [0]),
        (b"abcdef abcdef", b"not-found", []),
    ],
)
def test_iterate_patterns(content: bytes, pattern: bytes, expected: List[int]):
    file = File.from_bytes(content)
    assert list(iterate_patterns(file, pattern)) == expected


@pytest.mark.parametrize(
    "content, start_offset, size, buffer_size, expected",
    [
        pytest.param(b"0123456789", 0, 6, 3, [b"012", b"345"], id="from_start"),
        pytest.param(b"0123456789", 0, 0, 3, [], id="zero_size"),
        pytest.param(b"0123456789", 0, 5, 3, [b"012", b"34"], id="size_buffersize"),
        pytest.param(b"0123456789", 0, 5, 100, [b"01234"], id="big_buffersize"),
        pytest.param(b"0123456789", 0, 10, 10, [b"0123456789"], id="real_all"),
        pytest.param(b"0123456789", 0, 10, 100, [b"0123456789"], id="big_buffersize"),
        pytest.param(b"0123456789", 0, 100, 10, [b"0123456789"], id="big_size"),
        pytest.param(b"0123456789", 5, 3, 2, [b"56", b"7"], id="middle_offset"),
        pytest.param(b"0123456789", 10, 3, 2, [], id="offset_bigger_than_file"),
    ],
)
def test_iterate_file(
    content: bytes,
    start_offset: int,
    size: int,
    buffer_size: int,
    expected: List[bytes],
):
    file = File.from_bytes(content)
    assert list(iterate_file(file, start_offset, size, buffer_size)) == expected


@pytest.mark.parametrize(
    "content, start_offset, size, buffer_size",
    [
        pytest.param(b"012345", 0, 3, -1, id="negative_buffer_size"),
        pytest.param(b"012345", 0, 3, 0, id="zero_buffer_size"),
    ],
)
def test_iterate_file_errors(
    content: bytes, start_offset: int, size: int, buffer_size: int
):
    file = File.from_bytes(content)
    with pytest.raises(ValueError, match="buffer_size must be greater than 0"):
        list(iterate_file(file, start_offset, size, buffer_size))


class TestGetEndian:
    @pytest.mark.parametrize(
        "content, big_endian_magic, expected",
        [
            pytest.param(
                b"\xff\x00\x00\x10", 0x100000FF, Endian.LITTLE, id="valid_little_endian"
            ),
            pytest.param(
                b"\x10\x00\x00\xff", 0x100000FF, Endian.BIG, id="valid_big_endian"
            ),
        ],
    )
    def test_get_endian(self, content: bytes, big_endian_magic: int, expected: Endian):
        file = File.from_bytes(content)
        assert get_endian(file, big_endian_magic) == expected

    @pytest.mark.parametrize(
        "content, big_endian_magic",
        [
            pytest.param(b"\x00\x00\x00\x01", 0xFF_FF_FF_FF_FF, id="larger_than_32bit"),
        ],
    )
    def test_get_endian_errors(self, content: bytes, big_endian_magic: int):
        file = File.from_bytes(content)
        with pytest.raises(
            ValueError, match="big_endian_magic is larger than a 32 bit integer"
        ):
            get_endian(file, big_endian_magic)

    def test_get_endian_resets_the_file_pointer(self):
        file = File.from_bytes(bytes.fromhex("FFFF 0000"))
        file.seek(-1, io.SEEK_END)
        pos = file.tell()
        with pytest.raises(InvalidInputFormat):
            get_endian(file, 0xFFFF_0000)
        assert file.tell() == pos
