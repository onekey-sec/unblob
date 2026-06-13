import struct

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.compression.uzip import UZIPHandler

ZLIB_MAGIC = b"#!/bin/sh\x0a#V2.0\x20"


def build_image(toc: list[int]) -> bytes:
    # uzip_header_t: magic[16], format[112], uint32 block_size, uint32 block_count,
    # uint64 toc[block_count]
    block_count = len(toc)
    header = (
        ZLIB_MAGIC
        + b"\x00" * 112
        + struct.pack(">I", 16384)
        + struct.pack(">I", block_count)
        + struct.pack(f">{block_count}Q", *toc)
    )
    # keep toc[-1] within the file so only the ordering check can reject the image
    return header + b"\x00" * (max(toc) + 64 - len(header))


def test_calculate_chunk_accepts_sorted_toc():
    f = File.from_bytes(build_image([600, 700, 800]))
    f.seek(0)
    chunk = UZIPHandler().calculate_chunk(f, 0)
    assert chunk is not None
    assert chunk.end_offset == 800


@pytest.mark.parametrize("toc", [[600, 500, 700], [600, 5000, 1000], [800, 700, 600]])
def test_calculate_chunk_rejects_unsorted_toc(toc):
    f = File.from_bytes(build_image(toc))
    f.seek(0)
    with pytest.raises(InvalidInputFormat):
        UZIPHandler().calculate_chunk(f, 0)
