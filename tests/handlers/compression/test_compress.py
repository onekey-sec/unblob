import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.compression.compress import UnixCompressHandler


@pytest.mark.parametrize(
    "content, start_offset, expected_end_offset",
    [
        pytest.param(
            b"\x1f\x9d\x90\x61\xe0\xc0\x61\x53\x26\x86\x02", 0, 0xB, id="valid"
        ),
        pytest.param(
            b"\x1f\x9d\x90\x61\xe0\xc0\x61\x53\x26\x86",
            0,
            0x9,
            id="valid_chunk_end_corrupt_1",
        ),
        pytest.param(
            b"\x1f\x9d\x90\x61\xe0\xc0\x61\x53\x26",
            0,
            0x8,
            id="valid_chunk_end_corrupt_2",
        ),
        pytest.param(
            b"\x1f\x9d\x09\x61\xe0\xc0\x61\x53\x26\x86\x02", 0, 0xB, id="valid_max"
        ),
    ],
)
def test_unlzw(content: bytes, start_offset: int, expected_end_offset: int):
    handler = UnixCompressHandler()
    fake_file = File.from_bytes(content)
    size = handler.unlzw(fake_file, start_offset, max_len=len(content))
    assert size == expected_end_offset


@pytest.mark.parametrize(
    "content, start_offset",
    [
        pytest.param(
            b"\x1f\x9d\x08\x61\xe0\xc0\x61\x53\x26\x86\x02", 0, id="header_too_low_max"
        ),
        pytest.param(
            b"\x1f\x9d\x11\x61\xe0\xc0\x61\x53\x26\x86\x02", 0, id="header_too_high_max"
        ),
        pytest.param(b"\x1f\x9d\x90", 0, id="header_no_content"),
        pytest.param(
            b"\x1f\x9d\x60\x61\xe0\xc0\x61\x53\x26\x86\x02",
            0,
            id="header_invalid_flag_bytes",
        ),
        pytest.param(b"\x1f\x9d\xff", 0, id="header_invalid_flag_code"),
        pytest.param(b"\x1f\x9d\x90\xff\xff", 0, id="code_not_literal"),
        pytest.param(b"\x1f\x9d\x90\x61", 0, id="file_ends_before_stream"),
        pytest.param(
            b"\x1f\x9d\x09\x61\xe0\xc0\x61\x53\x26\x86\xff", 0, id="invalid_code"
        ),
    ],
)
def test_unlzw_errors(content: bytes, start_offset: int):
    handler = UnixCompressHandler()
    fake_file = File.from_bytes(content)
    with pytest.raises(InvalidInputFormat):
        handler.unlzw(fake_file, start_offset, max_len=len(content))


# "ABCA\x0e" in the compress(1) stream format, with a clear code closing the
# first code group, which pads the stream out to a 9 byte boundary.
# Decompresses with both uncompress(1) and gzip(1).
CLEAR_CODE_STREAM = bytes.fromhex("1f9d9041840c010800000000411c00")


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(
            b"\x1f\x9d\x90\x61\xe0\xc0\x61\x53\x26\x86\x02", id="without_clear_code"
        ),
        pytest.param(CLEAR_CODE_STREAM, id="with_clear_code"),
    ],
)
@pytest.mark.parametrize("start_offset", [0, 1, 0x200])
def test_calculate_chunk_spans_whole_stream(content: bytes, start_offset: int):
    handler = UnixCompressHandler()
    file = File.from_bytes(b"\x00" * start_offset + content)

    chunk = handler.calculate_chunk(file, start_offset)

    assert chunk is not None
    assert chunk.start_offset == start_offset
    assert chunk.end_offset == start_offset + len(content)
