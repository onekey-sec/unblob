import gzip
from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.compression.gzip import (
    GZIP2_STRICT_TRAILER_MAX_SIZE,
    GZIPHandler,
    MultiVolumeGzipHandler,
)


def test_multivolume_is_valid_gzip_empty_file(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.touch()
    assert not MultiVolumeGzipHandler().is_valid_gzip(empty)


def test_calculate_chunk_treats_concatenated_members_as_one_chunk():
    member_a = gzip.compress(b"durian")
    member_b = gzip.compress(b"jackfruit")
    file = File.from_bytes(member_a + member_b)

    with file:
        chunk = GZIPHandler().calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == len(member_a + member_b)


def test_calculate_chunk_stops_before_trailing_garbage():
    payload = gzip.compress(b"durian")
    trailing_garbage = b"not-a-member"
    file = File.from_bytes(payload + trailing_garbage)

    with file:
        chunk = GZIPHandler().calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == len(payload)


def _corrupt_crc(member: bytes) -> bytes:
    corrupted = bytearray(member)
    corrupted[-8] ^= 0xFF
    return bytes(corrupted)


def test_calculate_chunk_rejects_small_member_with_bad_trailer():
    # x86 code at a real-life false positive: `lea r8, [rip+0x88b1f]` reads
    # as a gzip header, followed by bytes that decode as a tiny deflate stream
    # and a trailer that does not match the decompressed data
    # header (10) | deflate stream (4) | trailer (8) | more code
    content = bytes.fromhex("1f8b080033d2488d0d018b0800e8ad3bfeffba7c000000e9ab000000")
    file = File.from_bytes(content)

    with file, pytest.raises(InvalidInputFormat):
        GZIPHandler().calculate_chunk(file, 0)


def test_calculate_chunk_rejects_small_member_with_bad_crc():
    file = File.from_bytes(_corrupt_crc(gzip.compress(b"durian")))

    with file, pytest.raises(InvalidInputFormat):
        GZIPHandler().calculate_chunk(file, 0)


def test_calculate_chunk_rejects_small_member_with_bad_size():
    member = bytearray(gzip.compress(b"durian"))
    member[-4] ^= 0xFF
    file = File.from_bytes(bytes(member))

    with file, pytest.raises(InvalidInputFormat):
        GZIPHandler().calculate_chunk(file, 0)


@pytest.mark.parametrize("payload_size", [6, GZIP2_STRICT_TRAILER_MAX_SIZE + 1])
def test_calculate_chunk_rejects_truncated_trailer(payload_size: int):
    file = File.from_bytes(gzip.compress(bytes(payload_size))[:-4])

    with file, pytest.raises(InvalidInputFormat):
        GZIPHandler().calculate_chunk(file, 0)


def test_calculate_chunk_accepts_large_member_with_bad_crc():
    payload = bytes(GZIP2_STRICT_TRAILER_MAX_SIZE + 1)
    member = _corrupt_crc(gzip.compress(payload))
    file = File.from_bytes(member)

    with file:
        chunk = GZIPHandler().calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.end_offset == len(member)


def test_calculate_chunk_stops_before_member_with_bad_trailer():
    member_a = gzip.compress(b"durian")
    member_b = _corrupt_crc(gzip.compress(b"jackfruit"))
    file = File.from_bytes(member_a + member_b)

    with file:
        chunk = GZIPHandler().calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.end_offset == len(member_a)
