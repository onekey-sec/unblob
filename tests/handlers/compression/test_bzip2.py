import io

import pytest

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
        pytest.param(b"123", 0, -1, id="shorter_than_block"),
        pytest.param(b"asdfasdf", 0, -1, id="not_found"),
        pytest.param(BLOCK_HEADER + b"123" + BLOCK_ENDMARK, 0, 9, id="aligned_to_zero"),
        pytest.param(
            b"0123" + BLOCK_HEADER + b"456" + BLOCK_ENDMARK,
            4,
            13,
            id="aligned_with_offset",
        ),
        pytest.param(
            b"0123" + BLOCK_HEADER + BLOCK_ENDMARK,
            4,
            10,
            id="aligned_offset_empty_content",
        ),
        pytest.param(b"0123" + BLOCK_HEADER, 0, -1, id="no_block_endmark"),
        pytest.param(b"0123" + BLOCK_ENDMARK, 0, -1, id="no_block_header"),
        # extra byte when shifted
        pytest.param(
            shift_left(BLOCK_HEADER, 1) + b"123" + BLOCK_ENDMARK,
            0,
            10,
            id="block_header_left_shifted",
        ),
        pytest.param(
            BLOCK_HEADER + b"123" + shift_left(BLOCK_ENDMARK, 1),
            0,
            10,
            id="block_endmark_left_shifted",
        ),
        pytest.param(
            shift_left(BLOCK_HEADER, 1) + b"123" + shift_left(BLOCK_ENDMARK, 1),
            0,
            11,
            id="both_marks_shifted",
        ),
        # undefined behavior: (BLOCK_ENDMARK + BLOCK_HEADER, 0, -1),
    ),
)
def test_bzip2_recover(content: bytes, start_offset: int, expected_end_offset: int):
    handler = BZip2Handler()
    fake_file = io.BytesIO(content)
    end_offset = handler.bzip2_recover(fake_file, start_offset)
    assert end_offset == expected_end_offset
