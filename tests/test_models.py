import pytest

from unblob.models import Chunk, Handler, UnknownChunk


class TestChunk:
    @pytest.mark.parametrize(
        "chunk1, chunk2, result",
        (
            (Chunk(0, 10), Chunk(1, 2), True),
            (Chunk(0, 10), Chunk(11, 12), False),
            (Chunk(0, 10), Chunk(15, 20), False),
            (Chunk(1, 2), Chunk(3, 5), False),
            (Chunk(0, 10), Chunk(1, 10), True),
        ),
    )
    def test_contains(self, chunk1, chunk2, result):
        assert chunk1.contains(chunk2) is result

    def test_range_hex(self):
        chunk = UnknownChunk(start_offset=3, end_offset=10)
        assert chunk.range_hex == "0x3-0xa"

    @pytest.mark.parametrize(
        "chunk, offset, expected",
        [
            pytest.param(Chunk(0x1, 0x2), 0x0, False, id="offset_before_chunk"),
            pytest.param(Chunk(0x0, 0x2), 0x0, True, id="offset_start_of_chunk"),
            pytest.param(Chunk(0x0, 0x2), 0x1, True, id="offset_inside_chunk"),
            pytest.param(Chunk(0x0, 0x2), 0x2, False, id="offset_after"),
        ],
    )
    def test_contains_offset(self, chunk, offset, expected):
        assert expected is chunk.contains_offset(offset)


class TestHandler:
    class DummyHandler(Handler):
        NAME = "name"
        YARA_RULE = "yara_rule"

        def calculate_chunk(self, *args, **kwargs):
            pass

        @staticmethod
        def make_extract_command(*args, **kwargs):
            return ["testcommand", "with", "some", "-test", "arguments"]

    def test_get_extract_command(self):
        assert self.DummyHandler._get_extract_command() == "testcommand"
