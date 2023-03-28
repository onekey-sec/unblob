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
