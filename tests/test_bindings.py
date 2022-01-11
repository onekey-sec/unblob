import io
import pytest
from pytest import approx

import unblob._py as python_binding

try:
    import unblob._rust as rust_binding
except ModuleNotFoundError:
    rust_binding = None


@pytest.fixture(
    params=[
        pytest.param(python_binding, id="Python"),
        pytest.param(
            rust_binding,
            id="Rust",
            marks=pytest.mark.skipif(
                rust_binding is None, reason="Rust binding is not present"
            ),
        ),
    ]
)
def binding(request):
    yield request.param


@pytest.mark.parametrize(
    "data, entropy",
    (
        pytest.param(b"", 0, id="empty"),
        pytest.param(b"\x00", 0, id="0 bit"),
        pytest.param(b"\x01\x01\x00\x00", 1.0, id="1 bit small"),
        pytest.param(b"\x01\x01\x00\x00" * 1000, 1.0, id="1 bit large"),
        pytest.param(b"\x00\x01\x02\x03", 2.0, id="2 bits"),
    ),
)
def test_shannon_entropy(binding, data, entropy):
    assert binding.shannon_entropy(data) == approx(entropy)

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
        pytest.param(b"0123" + BLOCK_HEADER, 0, -1, id="no_block_endmark"),
        pytest.param(b"0123" + BLOCK_ENDMARK, 0, -1, id="no_block_header"),
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
        # undefined behavior: (BLOCK_ENDMARK + BLOCK_HEADER, 0, -1),
    ),
)
def test_bzip2_recover_x(binding, content: bytes, start_offset: int, expected_end_offset: int):
    fake_file = io.BytesIO(content)
    end_offset = binding.bzip2_recover(fake_file, start_offset)
    assert end_offset == expected_end_offset
