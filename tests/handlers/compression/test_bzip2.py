import io

import pytest

from unblob.file_utils import InvalidInputFormat
from unblob.handlers.compression.bzip2 import BZip2Handler

BLOCK_HEADER = b"\x31\x41\x59\x26\x53\x59"
BLOCK_ENDMARK = b"\x17\x72\x45\x38\x50\x90"


def shift_left(value: bytes, bits: int) -> bytes:
    # big endian to keep the order
    left_shifted = int.from_bytes(value, byteorder="big") << bits
    return left_shifted.to_bytes(7, byteorder="big")


@pytest.mark.parametrize(
    "content, start_offset, expected_end_offset",
    (
        pytest.param(
            BLOCK_HEADER + b"123" + BLOCK_ENDMARK, 0, 15, id="aligned_to_zero"
        ),
        pytest.param(
            b"0123" + BLOCK_HEADER + b"456" + BLOCK_ENDMARK,
            4,
            19,
            id="aligned_with_offset",
        ),
        pytest.param(
            b"0123" + BLOCK_HEADER + BLOCK_ENDMARK,
            4,
            16,
            id="aligned_offset_empty_content",
        ),
        # extra byte when shifted
        pytest.param(
            shift_left(BLOCK_HEADER, 1) + b"123" + BLOCK_ENDMARK,
            0,
            16,
            id="block_header_left_shifted_by_1",
        ),
        pytest.param(
            shift_left(BLOCK_HEADER, 7) + b"123" + BLOCK_ENDMARK,
            0,
            16,
            id="block_header_left_shifted_by_7",
        ),
        pytest.param(
            BLOCK_HEADER + b"123" + shift_left(BLOCK_ENDMARK, 1),
            0,
            16,
            id="block_endmark_left_shifted_by_1",
        ),
        pytest.param(
            BLOCK_HEADER + b"123" + shift_left(BLOCK_ENDMARK, 7),
            0,
            16,
            id="block_endmark_left_shifted_by_7",
        ),
        pytest.param(
            shift_left(BLOCK_HEADER, 1) + b"123" + shift_left(BLOCK_ENDMARK, 1),
            0,
            17,
            id="both_marks_shifted_by_1",
        ),
        pytest.param(
            shift_left(BLOCK_HEADER, 7) + b"123" + shift_left(BLOCK_ENDMARK, 7),
            0,
            17,
            id="both_marks_shifted_by_7",
        ),
        pytest.param(
            BLOCK_HEADER
            + b"123"
            + BLOCK_ENDMARK
            + b"AAAA"
            + BLOCK_HEADER
            + b"123"
            + BLOCK_ENDMARK,
            0,
            15,
            id="two_bzip2_streams_separated_by_garbage_1",
        ),
        pytest.param(
            BLOCK_HEADER
            + b"123"
            + BLOCK_ENDMARK
            + BLOCK_HEADER
            + b"123"
            + BLOCK_ENDMARK,
            0,
            30,
            id="two_bzip2_streams",
        ),
        pytest.param(
            BLOCK_HEADER
            + b"123"
            + BLOCK_ENDMARK
            + BLOCK_HEADER
            + b"123"
            + BLOCK_ENDMARK
            + b"AAAA",
            0,
            30,
            id="two_bzip2_streams_followed_by_garbage_2",
        ),
    ),
)
def test_bzip2_recover(content: bytes, start_offset: int, expected_end_offset: int):
    handler = BZip2Handler()
    fake_file = io.BytesIO(content)
    end_offset = handler.bzip2_recover(fake_file, start_offset)
    assert end_offset == expected_end_offset


@pytest.mark.parametrize(
    "content",
    (
        pytest.param(b"123", id="shorter_than_block"),
        pytest.param(b"asdfasdf", id="not_found"),
        pytest.param(b"0123" + BLOCK_HEADER, id="no_block_endmark"),
        pytest.param(b"0123" + BLOCK_ENDMARK, id="no_block_header"),
        # undefined behavior: (BLOCK_ENDMARK + BLOCK_HEADER),
    ),
)
def test_bzip2_recover_error(content: bytes):
    handler = BZip2Handler()
    fake_file = io.BytesIO(content)
    with pytest.raises(InvalidInputFormat):
        handler.bzip2_recover(fake_file, 0)
