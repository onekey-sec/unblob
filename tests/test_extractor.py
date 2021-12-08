import io
from pathlib import Path

from unblob.extractor import carve_unknown_chunks
from unblob.models import UnknownChunk


class TestCarveUnknownChunks:
    def test_no_chunks(self, tmp_path: Path):
        test_file = io.BytesIO(b"some file")
        carve_unknown_chunks(tmp_path, test_file, [])
        assert list(tmp_path.iterdir()) == []

    def test_one_chunk(self, tmp_path: Path):
        content = b"test file"
        test_file = io.BytesIO(content)
        chunk = UnknownChunk(0, len(content))
        carve_unknown_chunks(tmp_path, test_file, [chunk])
        written_path = tmp_path / "0-9.unknown"
        assert list(tmp_path.iterdir()) == [written_path]
        assert written_path.read_bytes() == content

    def test_multiple_chunks(self, tmp_path: Path):
        content = b"test file"
        test_file = io.BytesIO(content)
        chunks = [UnknownChunk(0, 4), UnknownChunk(4, 9)]
        carve_unknown_chunks(tmp_path, test_file, chunks)
        written_path1 = tmp_path / "0-4.unknown"
        written_path2 = tmp_path / "4-9.unknown"
        assert sorted(tmp_path.iterdir()) == [written_path1, written_path2]
        assert written_path1.read_bytes() == content[:4]
        assert written_path2.read_bytes() == content[4:]
