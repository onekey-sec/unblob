import io
from typing import List
from unittest.mock import MagicMock

import pytest

from unblob.file_utils import (
    Endian,
    LimitedStartReader,
    StructParser,
    convert_int32,
    find_first,
    iterate_file,
    round_up,
)


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
    def test_convert_int32(self, value, endian, expected):
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
    def test_convert_invalid_values(self, value, endian):
        with pytest.raises(ValueError):
            convert_int32(value, endian)


@pytest.mark.parametrize(
    "content, pattern, expected_position",
    (
        pytest.param(b"", b"not-found-pattern", -1, id="not_found"),
        pytest.param(b"some", b"not-found", -1, id="smaller_data_than_pattern"),
        pytest.param(b"pattern_12345", b"pattern", 0, id="pattern_at_beginning"),
        pytest.param(b"01234_pattern", b"pattern", 6, id="pattern_at_the_end"),
        pytest.param(b"01234_pattern5678", b"pattern", 6, id="pattern_in_middle"),
    ),
)
def test_find_first(content, pattern, expected_position):
    fake_file = io.BytesIO(content)
    assert find_first(fake_file, pattern) == expected_position


def test_find_first_big_chunksize():
    fake_file = io.BytesIO(b"0123456789_pattern")
    pos = find_first(fake_file, b"pattern", chunk_size=0x10)
    assert pos == 11


def test_find_first_smaller_chunksize_than_pattern_doesnt_hang():
    fake_file = io.BytesIO(b"0123456789_pattern")
    with pytest.raises(ValueError):
        find_first(fake_file, b"pattern", chunk_size=0x5)


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
