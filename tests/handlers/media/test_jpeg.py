import struct

import pytest

from unblob.file_utils import InvalidInputFormat
from unblob.handlers.media.jpeg import JPEGHandler
from unblob.testing import calculate_chunk, find_chunks

SOI = b"\xff\xd8"
EOI = b"\xff\xd9"


def segment(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


APP0 = segment(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
DQT = segment(0xDB, b"\x00" + bytes(range(64)))
SOF0 = segment(0xC0, b"\x08\x00\x10\x00\x10\x01\x01\x11\x00")
SOF2 = segment(0xC2, b"\x08\x00\x10\x00\x10\x01\x01\x11\x00")
DHT = segment(0xC4, b"\x00" + b"\x01" + b"\x00" * 15 + b"\x00")
SOS = segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
# entropy-coded data with byte stuffing (FF 00) and a restart marker (FF D0)
SCAN_DATA = b"\x12\x34\xff\x00\x56\xff\xd0\x78\x9a"


def make_jpeg(*segments: bytes) -> bytes:
    if not segments:
        segments = (APP0, DQT, SOF0, DHT, SOS + SCAN_DATA)
    return SOI + b"".join(segments) + EOI


@pytest.mark.parametrize(
    "jpeg",
    [
        pytest.param(make_jpeg(), id="baseline"),
        pytest.param(
            make_jpeg(
                segment(0xE1, b"Exif\x00\x00" + make_jpeg()),
                DQT,
                SOF0,
                DHT,
                SOS + SCAN_DATA,
            ),
            id="exif-thumbnail",
        ),
        pytest.param(
            make_jpeg(DQT, SOF2, DHT, SOS + SCAN_DATA, DHT, SOS + SCAN_DATA),
            id="progressive",
        ),
        pytest.param(
            make_jpeg(DQT, b"\xff\xff" + SOF0, DHT, SOS + SCAN_DATA + b"\xff\xff"),
            id="fill-bytes",
        ),
        # Motion-JPEG frames rely on the default Huffman tables
        pytest.param(make_jpeg(DQT, SOF0, SOS + SCAN_DATA), id="no-huffman-tables"),
    ],
)
def test_finds_embedded_jpeg(jpeg: bytes):
    prefix = b"\x00\x01\x02firmware"

    # a nested thumbnail is part of the image, not a chunk of its own
    chunks = find_chunks(JPEGHandler, prefix + jpeg + b"\xff\xd9 trailing \xff\xd9")

    assert chunks == [(len(prefix), len(prefix) + len(jpeg))]


@pytest.mark.parametrize(
    "jpeg, error",
    [
        pytest.param(make_jpeg(DQT, DHT), "without image data", id="tables-only"),
        pytest.param(
            make_jpeg(DQT, SOS + SCAN_DATA, SOF0), "before frame", id="scan-first"
        ),
        *(
            pytest.param(
                make_jpeg(DQT, segment(marker, b"\x00"), SOF0, SOS),
                "Invalid JPEG marker",
                id=f"marker-{marker:02x}",
            )
            for marker in (0x02, 0x80, 0xBF, 0xD8)
        ),
        pytest.param(
            make_jpeg(b"\xff\xdb\x00\x01", SOF0, SOS),
            "segment length",
            id="short-segment",
        ),
        pytest.param(
            make_jpeg(DQT, b"\x00", SOF0, SOS),
            "Missing JPEG marker",
            id="garbage-between-segments",
        ),
    ],
)
def test_calculate_chunk_rejects_invalid_jpeg(jpeg: bytes, error: str):
    with pytest.raises(InvalidInputFormat, match=error):
        calculate_chunk(JPEGHandler, jpeg)


@pytest.mark.parametrize("cut", [1, 2, 5, 40])
def test_calculate_chunk_rejects_truncated_jpeg(cut: int):
    with pytest.raises(InvalidInputFormat):
        calculate_chunk(JPEGHandler, make_jpeg()[:-cut])
