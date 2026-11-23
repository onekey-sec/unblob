import gzip
import struct

import pytest

from unblob.finder import search_chunks
from unblob.handlers.compression.gzip import GZIPHandler
from unblob.handlers.compression.lz4 import SkippableFrameHandler
from unblob.models import File, TaskResult
from unblob.testing import calculate_chunk

SKIPPABLE_MAGIC = b"\x52\x2a\x4d\x18"
DEFAULT_FRAME_MAGIC = b"\x04\x22\x4d\x18"


def skippable_frame(payload: bytes) -> bytes:
    return SKIPPABLE_MAGIC + struct.pack("<I", len(payload)) + payload


@pytest.mark.parametrize(
    "prefix, suffix",
    [(b"", b"suffix"), (b"prefix", b""), (b"prefix", DEFAULT_FRAME_MAGIC)],
    ids=("file-start", "file-end", "next-frame"),
)
def test_skippable_frame_has_lz4_stream_context(prefix: bytes, suffix: bytes):
    frame = skippable_frame(b"payload")

    chunk = calculate_chunk(
        SkippableFrameHandler, prefix + frame + suffix, start_offset=len(prefix)
    )

    assert chunk is not None
    assert (chunk.start_offset, chunk.end_offset) == (
        len(prefix),
        len(prefix) + len(frame),
    )


def test_skippable_frame_does_not_hide_embedded_chunk(task_result: TaskResult):
    compressed = gzip.compress(b"hello", mtime=0)
    prefix = b"prefix"
    content = prefix + skippable_frame(compressed) + b"suffix"
    gzip_start = len(prefix) + 8

    with File.from_bytes(content) as file:
        chunks = search_chunks(
            file,
            len(content),
            (SkippableFrameHandler, GZIPHandler),
            task_result,
        )

    assert [
        (chunk.handler.NAME, chunk.start_offset, chunk.end_offset) for chunk in chunks
    ] == [(GZIPHandler.NAME, gzip_start, gzip_start + len(compressed))]
