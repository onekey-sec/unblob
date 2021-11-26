import pytest

from unblob.models import Chunk, UnknownChunk
from unblob.strategies import calculate_unknown_chunks, remove_inner_chunks


@pytest.mark.parametrize(
    "chunks, expected, explanation",
    [
        (None, [], "None as chunks (No chunk found)"),
        ([], [], "Empty list as chunks (No chunk found)"),
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


@pytest.mark.parametrize(
    "chunks, file_size, expected",
    [
        ([], 0, []),
        ([], 10, [UnknownChunk(0, 0xA)]),
        ([Chunk(0x0, 0x5)], 5, []),
        ([Chunk(0x0, 0x5), Chunk(0x5, 0xA)], 10, []),
        ([Chunk(0x0, 0x5), Chunk(0x5, 0xA)], 12, [UnknownChunk(0xA, 0xC)]),
        ([Chunk(0x3, 0x5)], 5, [UnknownChunk(0x0, 0x3)]),
        ([Chunk(0x0, 0x5), Chunk(0x7, 0xA)], 10, [UnknownChunk(0x5, 0x7)]),
        (
            [Chunk(0x8, 0xA), Chunk(0x0, 0x5), Chunk(0xF, 0x14)],
            20,
            [UnknownChunk(0x5, 0x8), UnknownChunk(0xA, 0xF)],
        ),
    ],
)
def test_calculate_unknown_chunks(chunks, file_size, expected):
    assert expected == calculate_unknown_chunks(chunks, file_size)
