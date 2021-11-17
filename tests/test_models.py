import pytest
from unblob.models import Chunk


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
