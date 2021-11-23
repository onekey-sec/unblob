import io
from unittest.mock import MagicMock

import pytest

from unblob.file_utils import LimitedStartReader, round_up


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
