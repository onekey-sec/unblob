import pytest

from unblob.models import Chunk
from unblob.strategies import remove_inner_chunks


@pytest.mark.parametrize(
    "chunks, expected, explanation",
    [
        (
            [
                Chunk(1, 2),
            ],
            [Chunk(1, 2)],
            "Only one chunk",
        ),
        (
            [
                Chunk(0, 5),
                Chunk(1, 2),
            ],
            [Chunk(0, 5)],
            "One chunk within another",
        ),
        (
            [
                Chunk(10, 20),
                Chunk(11, 13),
                Chunk(14, 19),
            ],
            [Chunk(10, 20)],
            "Multiple chunks within 1 outer chunk",
        ),
        (
            [
                Chunk(11, 13),
                Chunk(10, 20),
                Chunk(14, 19),
            ],
            [Chunk(10, 20)],
            "Multiple chunks within 1 outer chunk, in different order",
        ),
        (
            [
                Chunk(1, 5),
                Chunk(6, 10),
            ],
            [Chunk(1, 5), Chunk(6, 10)],
            "Multiple outer chunks",
        ),
        (
            [
                Chunk(1, 5),
                Chunk(2, 3),
                Chunk(6, 10),
                Chunk(7, 8),
            ],
            [Chunk(1, 5), Chunk(6, 10)],
            "Multiple outer chunks, with chunks inside",
        ),
    ],
)
def test_remove_inner_chunks(chunks, expected, explanation):
    assert expected == remove_inner_chunks(chunks), explanation
