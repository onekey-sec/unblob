import io
import sys
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

import pytest

from unblob.file_utils import (
    Endian,
    InvalidInputFormat,
    LimitedStartReader,
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
    valid_path,
)


@pytest.mark.parametrize(
    "size, alignment, result",
    (
        (0, 5, 0),
        (1, 10, 0),
        (12, 10, 10),
        (29, 10, 20),
        (1, 512, 0),
    ),
)
def test_round_down(size, alignment, result):
    assert round_down(size, alignment) == result


@pytest.mark.parametrize(
    "size, alignment, result",
    (
        (0, 5, 0),
        (1, 10, 10),
        (12, 10, 20),
        (22, 10, 30),
        (1, 512, 512),
    ),
)
def test_round_up(size, alignment, result):
    assert round_up(size, alignment) == result


@pytest.fixture()
def fake_file() -> io.BytesIO:
    return io.BytesIO(b"0123456789abcdefghijklmnopqrst")


class TestLimitedStartReader:
    def test_seek_forward(self, fake_file):
        reader = LimitedStartReader(fake_file, 5)
        reader.seek(10)
        assert reader.tell() == 10

    def test_seek_backward(self, fake_file):
        reader = LimitedStartReader(fake_file, 5)
        reader.seek(10)
        reader.seek(-4, io.SEEK_CUR)
        assert reader.tell() == 6

    def test_seek_before_start(self, fake_file):
        reader = LimitedStartReader(fake_file, 5)
        reader.seek(10)
        reader.seek(-6, io.SEEK_CUR)
        assert reader.tell() == 5

    def test_seek_to_end_of_file(self, fake_file):
        reader = LimitedStartReader(fake_file, 5)
        reader.seek(-1, io.SEEK_END)
        assert reader.tell() == len(fake_file.getvalue()) - 1

    def test_seek_to_above_max_off_t(self, fake_file):
        reader = LimitedStartReader(fake_file, 5)
        with pytest.raises(InvalidInputFormat):
            reader.seek(sys.maxsize + 1)

    def test_seek_to_below_min_off_t(self, fake_file):
        reader = LimitedStartReader(fake_file, 5)
        with pytest.raises(InvalidInputFormat):
            reader.seek(-(sys.maxsize + 2), io.SEEK_END)

    @pytest.mark.parametrize(
        "method_name",
        ("detach", "read", "read1", "readinto", "readinto1"),
    )
    def test_methods_dispatched_to_file(self, method_name):
        mock_file = MagicMock(io.BufferedReader)
        reader = LimitedStartReader(mock_file, 10)

        method = getattr(reader, method_name)
        method("arg1", "arg2", kw1="kw1", kw2="kw2")

        mock_method = getattr(mock_file, method_name)
        mock_method.assert_called_with("arg1", "arg2", kw1="kw1", kw2="kw2")

    def test_read_only(self, fake_file):
        reader = LimitedStartReader(fake_file, 5)
        with pytest.raises(TypeError):
            reader.write(b"something")


class TestStructParser:
    def test_parse_correct_endianness(self):
        test_content = b"\x01\x02\x03\x04"
        fake_file = io.BytesIO(test_content)

        definitions = r"""
        struct squashfs_header
        {
            uint32 inodes;
        }
        """
        parser = StructParser(definitions)

        header = parser.parse("squashfs_header", fake_file, Endian.BIG)
        assert header.inodes == 0x01_02_03_04

        fake_file = io.BytesIO(test_content)
        header2 = parser.parse("squashfs_header", fake_file, Endian.LITTLE)
        assert header2.inodes == 0x04_03_02_01


class TestConvertInt8:
    @pytest.mark.parametrize(
        "value, endian, expected",
        (
            (b"\x00", Endian.LITTLE, 0x0),
            (b"\x00", Endian.BIG, 0x0),
            (b"\xff", Endian.LITTLE, 0xFF),
            (b"\xff", Endian.BIG, 0xFF),
            (b"\x10", Endian.LITTLE, 0x10),
            (b"\x10", Endian.BIG, 0x10),
        ),
    )
    def test_convert_int8(self, value: bytes, endian: Endian, expected: int):
        assert convert_int8(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        (
            (b"", Endian.LITTLE),
            (b"", Endian.BIG),
            (b"\x00\x00", Endian.LITTLE),
            (b"\x00\x00", Endian.BIG),
            (b"\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff\xff", Endian.BIG),
        ),
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int8(value, endian)


class TestConvertInt16:
    @pytest.mark.parametrize(
        "value, endian, expected",
        (
            (b"\x00\x00", Endian.LITTLE, 0x0),
            (b"\x00\x00", Endian.BIG, 0x0),
            (b"\xff\xff", Endian.LITTLE, 0xFFFF),
            (b"\xff\xff", Endian.BIG, 0xFFFF),
            (b"\x10\x00", Endian.LITTLE, 0x10),
            (b"\x10\x00", Endian.BIG, 0x1000),
        ),
    )
    def test_convert_int16(self, value: bytes, endian: Endian, expected: int):
        assert convert_int16(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        (
            (b"", Endian.LITTLE),
            (b"", Endian.BIG),
            (b"\xff", Endian.LITTLE),
            (b"\xff", Endian.BIG),
            (b"\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff", Endian.BIG),
        ),
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int16(value, endian)


class TestConvertInt32:
    @pytest.mark.parametrize(
        "value, endian, expected",
        (
            (b"\x00\x00\x00\x00", Endian.LITTLE, 0x0),
            (b"\x00\x00\x00\x00", Endian.BIG, 0x0),
            (b"\xff\xff\xff\xff", Endian.LITTLE, 0xFFFFFFFF),
            (b"\xff\xff\xff\xff", Endian.BIG, 0xFFFFFFFF),
            (b"\x10\x00\x00\x00", Endian.LITTLE, 0x10),
            (b"\x10\x00\x00\x00", Endian.BIG, 0x10000000),
        ),
    )
    def test_convert_int32(self, value: bytes, endian: Endian, expected: int):
        assert convert_int32(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        (
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
        ),
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int32(value, endian)


class TestConvertInt64:
    @pytest.mark.parametrize(
        "value, endian, expected",
        (
            (b"\x00\x00\x00\x00\x00\x00\x00\x00", Endian.LITTLE, 0x0),
            (b"\x00\x00\x00\x00\x00\x00\x00\x00", Endian.BIG, 0x0),
            (b"\xff\xff\xff\xff\xff\xff\xff\xff", Endian.LITTLE, 0xFFFF_FFFF_FFFF_FFFF),
            (b"\xff\xff\xff\xff\xff\xff\xff\xff", Endian.BIG, 0xFFFF_FFFF_FFFF_FFFF),
            (b"\x10\x00\x00\x00\x00\x00\x00\x00", Endian.LITTLE, 0x10),
            (b"\x10\x00\x00\x00\x00\x00\x00\x00", Endian.BIG, 0x1000_0000_0000_0000),
        ),
    )
    def test_convert_int64(self, value: bytes, endian: Endian, expected: int):
        assert convert_int64(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        (
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
        ),
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int64(value, endian)


class TestMultibytesInteger:
    @pytest.mark.parametrize(
        "value, expected",
        (
            (b"\x00", (1, 0)),
            (b"\x01", (1, 1)),
            (b"\x01\x00", (1, 1)),
            (b"\x7f", (1, 127)),
            (b"\x7f\x00", (1, 127)),
            (b"\xff\x00", (2, 127)),
            (b"\x80\x08\x00", (2, 1024)),
            (b"\xff\xff\xff\xff\xff\xff\xff\x7f", (8, 0xFFFFFFFFFFFFFF)),
        ),
    )
    def test_decode_multibyte_integer(self, value: bytes, expected: int):
        assert decode_multibyte_integer(value) == expected

    @pytest.mark.parametrize(
        "value",
        (
            (b""),
            (b"\xff"),
            (b"\xff\xff\xff"),
        ),
    )
    def test_decode_invalid_values(self, value: bytes):
        with pytest.raises(InvalidInputFormat):
            decode_multibyte_integer(value)


@pytest.mark.parametrize(
    "content, pattern, expected",
    (
        (b"", b"", []),
        (b"abcdef 123", b"abcdef", [0]),
        (b"abcdef abc", b"abcdef", [0]),
        (b"abcdef abcdef", b"abcdef", [0, 7]),
        (b"abcd", b"abcd", [0]),
        (b"abcdef abcdef", b"not-found", []),
    ),
)
def test_iterate_patterns(content: bytes, pattern: bytes, expected: List[int]):
    file = io.BytesIO(content)
    assert list(iterate_patterns(file, pattern)) == expected


@pytest.mark.parametrize(
    "content, start_offset, size, buffer_size, expected",
    (
        pytest.param(b"", 0, 1, 10, [], id="empty_file"),
        pytest.param(b"0123456789", 0, 6, 3, [b"012", b"345"], id="from_start"),
        pytest.param(b"0123456789", 0, 0, 3, [], id="zero_size"),
        pytest.param(b"0123456789", 0, 5, 3, [b"012", b"34"], id="size_buffersize"),
        pytest.param(b"0123456789", 0, 5, 100, [b"01234"], id="big_buffersize"),
        pytest.param(b"0123456789", 0, 10, 10, [b"0123456789"], id="real_all"),
        pytest.param(b"0123456789", 0, 10, 100, [b"0123456789"], id="big_buffersize"),
        pytest.param(b"0123456789", 0, 100, 10, [b"0123456789"], id="big_size"),
        pytest.param(b"0123456789", 5, 3, 2, [b"56", b"7"], id="middle_offset"),
        pytest.param(b"0123456789", 10, 3, 2, [], id="offset_bigger_than_file"),
    ),
)
def test_iterate_file(
    content: bytes,
    start_offset: int,
    size: int,
    buffer_size: int,
    expected: List[bytes],
):
    file = io.BytesIO(content)
    assert list(iterate_file(file, start_offset, size, buffer_size)) == expected


@pytest.mark.parametrize(
    "content, start_offset, size, buffer_size",
    (
        pytest.param(b"012345", 0, 3, -1, id="negative_buffer_size"),
        pytest.param(b"012345", 0, 3, 0, id="zero_buffer_size"),
    ),
)
def test_iterate_file_errors(
    content: bytes, start_offset: int, size: int, buffer_size: int
):
    file = io.BytesIO(content)
    with pytest.raises(ValueError):
        list(iterate_file(file, start_offset, size, buffer_size))


class TestGetEndian:
    @pytest.mark.parametrize(
        "content, big_endian_magic, expected",
        (
            pytest.param(
                b"\xff\x00\x00\x10", 0x100000FF, Endian.LITTLE, id="valid_little_endian"
            ),
            pytest.param(
                b"\x10\x00\x00\xff", 0x100000FF, Endian.BIG, id="valid_big_endian"
            ),
        ),
    )
    def test_get_endian(self, content: bytes, big_endian_magic: int, expected: Endian):
        file = io.BytesIO(content)
        assert get_endian(file, big_endian_magic) == expected

    @pytest.mark.parametrize(
        "content, big_endian_magic",
        (pytest.param(b"\x00\x00\x00\x01", 0xFF_FF_FF_FF_FF, id="larger_than_32bit"),),
    )
    def test_get_endian_errors(self, content: bytes, big_endian_magic: int):
        file = io.BytesIO(content)
        with pytest.raises(ValueError):
            get_endian(file, big_endian_magic)

    def test_get_endian_resets_the_file_pointer(self):
        file = io.BytesIO(bytes.fromhex("FFFF 0000"))
        file.seek(-1, io.SEEK_END)
        pos = file.tell()
        with pytest.raises(InvalidInputFormat):
            get_endian(file, 0xFFFF_0000)
        assert file.tell() == pos


@pytest.mark.parametrize(
    "content, expected",
    (
        pytest.param("some_random_file.txt", True, id="valid_unicode_path"),
        pytest.param(
            "some/random/file\udce4\udc94.txt", False, id="invalid_unicode_path"
        ),
    ),
)
def test_valid_path(content: str, expected: bool):
    assert valid_path(Path(content)) == expected
