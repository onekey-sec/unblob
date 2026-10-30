import struct

import pytest

from unblob.file_utils import InvalidInputFormat, SeekError
from unblob.handlers.media.riff import WEBPHandler
from unblob.testing import calculate_chunk, find_chunks

# frame tag (3 bytes), start code, 16x16 dimensions, then compressed data
VP8_DATA = b"\x50\x02\x00\x9d\x01\x2a\x10\x00\x10\x00" + b"\x03" * 21
# signature, packed 16x16 dimensions and flags, then compressed data
VP8L_DATA = b"\x2f\x0f\xc0\x03\x00" + b"\x07" * 12
# flags (alpha), reserved, 16x16 canvas (minus one, 24 bit each)
VP8X_DATA = b"\x10\x00\x00\x00\x0f\x00\x00\x0f\x00\x00"


def chunk(chunk_id: bytes, data: bytes) -> bytes:
    padding = b"\x00" if len(data) % 2 else b""
    return chunk_id + struct.pack("<I", len(data)) + data + padding


def riff(*chunks: bytes) -> bytes:
    body = b"WEBP" + b"".join(chunks)
    return b"RIFF" + struct.pack("<I", len(body)) + body


@pytest.mark.parametrize(
    "webp",
    [
        pytest.param(riff(chunk(b"VP8 ", VP8_DATA)), id="lossy"),
        pytest.param(riff(chunk(b"VP8L", VP8L_DATA)), id="lossless"),
        pytest.param(
            riff(
                chunk(b"VP8X", VP8X_DATA),
                chunk(b"ALPH", b"\x00" * 7),
                chunk(b"VP8 ", VP8_DATA),
                chunk(b"EXIF", b"II*\x00"),
            ),
            id="extended",
        ),
    ],
)
def test_finds_embedded_webp(webp: bytes):
    prefix = b"\x00\x00RIFF"

    chunks = find_chunks(WEBPHandler, prefix + webp + b"RIFF trailing")

    assert chunks == [(len(prefix), len(prefix) + len(webp))]


@pytest.mark.parametrize(
    "webp",
    [
        pytest.param(riff(chunk(b"VP8 ", b"\x00" * 10)), id="vp8-no-start-code"),
        pytest.param(riff(chunk(b"VP8L", b"\x00" * 10)), id="vp8l-no-signature"),
        pytest.param(riff(chunk(b"VP8X", b"\x00" * 12)), id="vp8x-wrong-size"),
        pytest.param(
            riff(chunk(b"EXIF", b"II*\x00"), chunk(b"VP8 ", VP8_DATA)),
            id="metadata-first",
        ),
    ],
)
def test_pattern_rejects_invalid_first_chunk(webp: bytes):
    assert find_chunks(WEBPHandler, webp) == []


def test_calculate_chunk_rejects_form_without_chunks():
    with pytest.raises(InvalidInputFormat, match="without chunks"):
        calculate_chunk(WEBPHandler, riff())


@pytest.mark.parametrize("cut", [1, 10, 30])
def test_calculate_chunk_rejects_truncated_webp(cut: int):
    webp = riff(chunk(b"VP8 ", VP8_DATA))

    with pytest.raises((EOFError, SeekError)):
        calculate_chunk(WEBPHandler, webp[:-cut])
