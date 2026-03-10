import gzip
from pathlib import Path

from unblob.file_utils import File
from unblob.handlers.compression.gzip import GZIPHandler, MultiVolumeGzipHandler


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
