import zlib

from unblob.file_utils import DEFAULT_BUFSIZE, File
from unblob.handlers.compression.zlib import ZlibHandler


def test_calculate_chunk_stops_at_zlib_stream_end():
    stream = zlib.compress(b"first frame payload")
    following_data = b"A" * (DEFAULT_BUFSIZE * 2)
    file = File.from_bytes(stream + following_data)

    with file:
        chunk = ZlibHandler().calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.end_offset == len(stream)
