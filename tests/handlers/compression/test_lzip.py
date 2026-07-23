import pytest

from unblob.file_utils import File
from unblob.handlers.compression.lzip import LZipHandler


@pytest.mark.parametrize(
    "content, expected_end_offset",
    [
        # `printf A | lzip -9` produces a 37-byte member whose total length is
        # odd. The member_size field then lands on an odd offset, which the
        # scan used to skip over.
        pytest.param(
            bytes.fromhex(
                "4c5a4950010c0020c1fbffffffe00000008b9ed9d3"
                "01000000000000002500000000000000"
            ),
            0x25,
            id="odd_length_member",
        ),
    ],
)
def test_odd_length_member(content: bytes, expected_end_offset: int):
    handler = LZipHandler()
    fake_file = File.from_bytes(content)
    chunk = handler.calculate_chunk(fake_file, 0)
    assert chunk is not None
    assert chunk.end_offset == expected_end_offset
