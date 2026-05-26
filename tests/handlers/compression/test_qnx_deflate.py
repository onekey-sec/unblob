import struct
from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.compression.qnx_deflate import (
    QNXDeflateExtractor,
    QNXDeflateHandler,
)


def build_image(next_offset: int) -> bytes:
    # filehdr_t: signature[8], int32 usize, uint16 blksize, uint8 cmptype, uint8 flags
    filehdr = b"iwlyfmbp" + struct.pack("<iHBB", 64, 4096, 0, 0)
    # cmphdr_t: prev, next, pusize, usize
    cmphdr = struct.pack("<HHHH", 0, next_offset, 0, 0)
    return filehdr + cmphdr + b"\xab" * 5000


@pytest.mark.parametrize("next_offset", [1, 4, 7])
def test_calculate_chunk_rejects_short_block_offset(next_offset):
    f = File.from_bytes(build_image(next_offset))
    f.seek(0)
    with pytest.raises(InvalidInputFormat):
        QNXDeflateHandler().calculate_chunk(f, 0)


@pytest.mark.parametrize("next_offset", [1, 4, 7])
def test_extract_rejects_short_block_offset(next_offset, tmp_path: Path):
    # next < 8 makes `cmphdr.next - 8` negative; mmap.read() would then slurp the
    # whole remaining file instead of the block bounded by next.
    inpath = tmp_path / "in.deflated"
    inpath.write_bytes(build_image(next_offset))
    with pytest.raises(InvalidInputFormat):
        QNXDeflateExtractor().extract(inpath, tmp_path)
