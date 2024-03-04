from pathlib import Path

from unblob.handlers.compression.gzip import MultiVolumeGzipHandler


def test_multivolume_is_valid_gzip_empty_file(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.touch()
    assert not MultiVolumeGzipHandler().is_valid_gzip(empty)
