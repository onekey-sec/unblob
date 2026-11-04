import struct
import zlib

import pytest

from unblob.file_utils import InvalidInputFormat
from unblob.handlers.media.png import PNGHandler
from unblob.testing import calculate_chunk, find_chunks

SIGNATURE = b"\x89PNG\r\n\x1a\n"


def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + data)
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def make_ihdr(
    width=2, height=2, bit_depth=8, color_type=2, *, method=b"\x00\x00\x00"
) -> bytes:
    """IHDR chunk; method is the compression, filter and interlace method."""
    return make_chunk(
        b"IHDR",
        struct.pack(">IIBB", width, height, bit_depth, color_type) + method,
    )


IHDR = make_ihdr()  # 2x2 truecolour
IHDR_DATA = IHDR[8:-4]
IDAT = make_chunk(b"IDAT", zlib.compress(b"\x00" + b"\xff" * 6 + b"\x00" * 7))
IEND = make_chunk(b"IEND", b"")


def make_png(*chunks: bytes, ihdr=IHDR) -> bytes:
    if not chunks:
        chunks = (make_chunk(b"tEXt", b"Comment\x00embedded"), IDAT)
    return SIGNATURE + ihdr + b"".join(chunks) + IEND


@pytest.mark.parametrize(
    "png",
    [
        pytest.param(make_png(), id="simple"),
        pytest.param(make_png(ihdr=make_ihdr(method=b"\x00\x00\x01")), id="interlaced"),
        pytest.param(
            make_png(
                make_chunk(b"IDAT", b"\x78\x9c"), make_chunk(b"IDAT", b"\x03\x00")
            ),
            id="multiple-idat",
        ),
    ],
)
def test_finds_embedded_png(png: bytes):
    prefix = b"\x00firmware\x00"

    chunks = find_chunks(PNGHandler, prefix + png + b"trailing data")

    assert chunks == [(len(prefix), len(prefix) + len(png))]


@pytest.mark.parametrize(
    "ihdr",
    [
        pytest.param(make_chunk(b"IHDX", IHDR_DATA), id="not-ihdr"),
        pytest.param(make_chunk(b"IHDR", IHDR_DATA + b"\x00"), id="ihdr-length"),
        pytest.param(make_ihdr(method=b"\x01\x00\x00"), id="bad-compression"),
        pytest.param(make_ihdr(method=b"\x00\x01\x00"), id="bad-filter"),
        pytest.param(make_ihdr(method=b"\x00\x00\x02"), id="bad-interlace"),
    ],
)
def test_pattern_rejects_invalid_ihdr(ihdr: bytes):
    assert find_chunks(PNGHandler, make_png(ihdr=ihdr)) == []


def corrupt_idat_crc(png: bytes) -> bytes:
    # last byte of the IDAT CRC, just before the IEND chunk
    return png[: -len(IEND) - 1] + bytes([png[-len(IEND) - 1] ^ 0xFF]) + IEND


@pytest.mark.parametrize(
    "png, error",
    [
        pytest.param(make_png(ihdr=make_ihdr(width=0)), "dimensions", id="zero-width"),
        pytest.param(
            make_png(ihdr=make_ihdr(height=2**31)), "dimensions", id="too-high"
        ),
        pytest.param(
            make_png(ihdr=make_ihdr(bit_depth=4, color_type=2)),
            "bit depth",
            id="bad-bit-depth",
        ),
        pytest.param(
            make_png(ihdr=make_ihdr(color_type=5)), "bit depth", id="bad-colour-type"
        ),
        pytest.param(
            make_png(make_chunk(b"ID\x00T", b""), IDAT),
            "chunk header",
            id="non-letter-chunk-type",
        ),
        pytest.param(corrupt_idat_crc(make_png()), "CRC", id="bad-crc"),
        pytest.param(make_png(make_chunk(b"tEXt", b"x")), "IDAT", id="no-idat"),
    ],
)
def test_calculate_chunk_rejects_invalid_png(png: bytes, error: str):
    with pytest.raises(InvalidInputFormat, match=error):
        calculate_chunk(PNGHandler, png)


@pytest.mark.parametrize("cut", [1, 4, 13, 20])
def test_calculate_chunk_rejects_truncated_png(cut: int):
    with pytest.raises(InvalidInputFormat):
        calculate_chunk(PNGHandler, make_png()[:-cut])
