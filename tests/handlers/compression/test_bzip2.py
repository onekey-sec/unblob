import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.compression.bzip2 import BZip2Handler

STREAM_MAGIC = b"BZ"
STREAM_HEADER = STREAM_MAGIC + b"h1"
FAKE_CRC = b"\xde\xad\xbe\xef"
BLOCK_START_MAGIC = b"\x31\x41\x59\x26\x53\x59"
BLOCK_SORT_BYTE = b"\x00"
BLOCK_HEADER = BLOCK_START_MAGIC + FAKE_CRC + BLOCK_SORT_BYTE
STREAM_END_MAGIC = b"\x17\x72\x45\x38\x50\x90"
STREAM_FOOTER = STREAM_END_MAGIC + FAKE_CRC
CONTENT = b"123"

STREAM_SIZE = len(STREAM_HEADER + BLOCK_HEADER + STREAM_FOOTER)


def shift_left(value: bytes, bits: int) -> bytes:
    # big endian to keep the order
    left_shifted = int.from_bytes(value, byteorder="big") << bits
    return left_shifted.to_bytes(7, byteorder="big")


@pytest.mark.parametrize(
    "content, start_offset, expected_length",
    (
        pytest.param(
            STREAM_HEADER + BLOCK_HEADER + CONTENT + STREAM_FOOTER,
            0,
            STREAM_SIZE + 3,
            id="aligned_to_zero",
        ),
        pytest.param(
            b"0123" + STREAM_HEADER + BLOCK_HEADER + CONTENT + STREAM_FOOTER,
            4,
            STREAM_SIZE + 3,
            id="aligned_with_offset",
        ),
        pytest.param(
            b"0123" + STREAM_HEADER + BLOCK_HEADER + STREAM_FOOTER,
            4,
            STREAM_SIZE,
            id="aligned_offset_empty_content",
        ),
        pytest.param(
            STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + shift_left(STREAM_END_MAGIC, 1)
            + FAKE_CRC,
            0,
            STREAM_SIZE + 1 + 3,
            id="block_end_magic_left_shifted_by_1",
        ),
        pytest.param(
            STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + shift_left(STREAM_END_MAGIC, 7)
            + FAKE_CRC,
            0,
            STREAM_SIZE + 1 + 3,
            id="block_end_magic_left_shifted_by_7",
        ),
        pytest.param(
            STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + STREAM_FOOTER
            + b"AAAA"
            + STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + STREAM_FOOTER,
            0,
            STREAM_SIZE + 3,
            id="two_bzip2_streams_separated_by_garbage_1",
        ),
        pytest.param(
            STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + STREAM_FOOTER
            + STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + STREAM_FOOTER,
            0,
            (STREAM_SIZE + 3) * 2,
            id="two_bzip2_streams",
        ),
        pytest.param(
            STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + STREAM_FOOTER
            + STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + STREAM_FOOTER
            + b"AAAA",
            0,
            (STREAM_SIZE + 3) * 2,
            id="two_bzip2_streams_followed_by_garbage_2",
        ),
        pytest.param(
            STREAM_HEADER + BLOCK_HEADER + CONTENT + STREAM_FOOTER + STREAM_MAGIC,
            0,
            STREAM_SIZE + 3,
            id="just_stream_magic_after_stream",
        ),
        pytest.param(
            STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + STREAM_FOOTER
            + STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT,
            0,
            STREAM_SIZE + 3,
            id="missing_footer_after_stream",
        ),
        pytest.param(
            STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + STREAM_FOOTER
            + STREAM_HEADER
            + CONTENT
            + STREAM_FOOTER,
            0,
            STREAM_SIZE + 3,
            id="missing_block_header_after_stream",
        ),
        pytest.param(
            STREAM_HEADER + BLOCK_HEADER + CONTENT + STREAM_FOOTER + b"AAAA",
            0,
            STREAM_SIZE + 3,
            id="garbage_after_stream_footer",
        ),
        pytest.param(
            STREAM_END_MAGIC + STREAM_HEADER + BLOCK_HEADER + CONTENT + STREAM_FOOTER,
            len(STREAM_END_MAGIC),
            STREAM_SIZE + 3,
            id="stream_end_magic_before_start",
        ),
        pytest.param(
            STREAM_END_MAGIC
            + b"AAAA"
            + STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + STREAM_FOOTER,
            len(STREAM_END_MAGIC) + 4,
            STREAM_SIZE + 3,
            id="stream_end_magic_before_start_and_padding",
        ),
        pytest.param(
            STREAM_HEADER
            + BLOCK_HEADER
            + CONTENT
            + STREAM_FOOTER
            + STREAM_HEADER
            + BLOCK_START_MAGIC,
            0,
            STREAM_SIZE + 3,
            id="just_block_magic_after_footer",
        ),
        pytest.param(
            STREAM_HEADER + BLOCK_HEADER + CONTENT + STREAM_FOOTER + STREAM_HEADER,
            0,
            STREAM_SIZE + 3,
            id="just_stream_header_after_footer",
        ),
    ),
)
def test_bzip2_recover(content: bytes, start_offset: int, expected_length: int):
    handler = BZip2Handler()
    fake_file = File.from_bytes(content)
    fake_file.seek(start_offset)
    chunk = handler.calculate_chunk(fake_file, start_offset)
    assert chunk is not None
    assert chunk.end_offset == start_offset + expected_length


@pytest.mark.parametrize(
    "content",
    (
        pytest.param(STREAM_HEADER, id="just_stream_header"),
        pytest.param(STREAM_HEADER + CONTENT, id="missing_block_header"),
        pytest.param(
            STREAM_HEADER + CONTENT + STREAM_FOOTER, id="missing_block_header2"
        ),
        pytest.param(STREAM_HEADER + BLOCK_START_MAGIC, id="only_block_start_magic"),
        pytest.param(
            STREAM_HEADER + BLOCK_HEADER + CONTENT, id="missing_stream_footer"
        ),
        pytest.param(
            STREAM_HEADER + BLOCK_HEADER + CONTENT + STREAM_END_MAGIC,
            id="incomplete_stream_footer",
        ),
    ),
)
def test_bzip2_recover_error(content: bytes):
    handler = BZip2Handler()
    fake_file = File.from_bytes(content)
    with pytest.raises(InvalidInputFormat):
        handler.calculate_chunk(fake_file, 0)
