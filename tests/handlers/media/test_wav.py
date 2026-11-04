import io
import struct
import wave

import pytest

from unblob.file_utils import InvalidInputFormat, SeekError
from unblob.handlers.media.riff import WAVHandler
from unblob.testing import calculate_chunk, find_chunks


def make_wav(frames: bytes = b"\x00\x01" * 50, channels=1, sample_width=2) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(sample_width)
        wav.setframerate(8000)
        wav.writeframes(frames)
    return buffer.getvalue()


def chunk(chunk_id: bytes, data: bytes, *, pad=True) -> bytes:
    padding = b"\x00" if pad and len(data) % 2 else b""
    return chunk_id + struct.pack("<I", len(data)) + data + padding


def riff(*chunks: bytes, form_type=b"WAVE", size_delta=0) -> bytes:
    body = form_type + b"".join(chunks)
    return b"RIFF" + struct.pack("<I", len(body) + size_delta) + body


def fmt(format_tag=1, channels=1, sample_rate=8000, block_align=2) -> bytes:
    return chunk(
        b"fmt ",
        struct.pack(
            "<HHIIHH",
            format_tag,
            channels,
            sample_rate,
            sample_rate * 2,
            block_align,
            16,
        ),
    )


@pytest.mark.parametrize(
    "wav",
    [
        pytest.param(make_wav(), id="python-wave"),
        pytest.param(
            riff(
                fmt(),
                chunk(b"fact", b"\x64\x00\x00\x00"),
                chunk(b"LIST", b"INFOISFT\x03\x00\x00\x00ab\x00"),
                chunk(b"data", b"\x01\x02\x03"),
            ),
            id="extra-chunks-and-padding",
        ),
        pytest.param(
            riff(fmt(), chunk(b"data", b"\x01\x02\x03", pad=False)),
            id="no-pad-byte-after-last-chunk",
        ),
    ],
)
def test_finds_embedded_wav(wav: bytes):
    prefix = b"beep.wav\x00\x00\x00\x00"

    chunks = find_chunks(WAVHandler, prefix + wav + b"RIFF trailing")

    assert chunks == [(len(prefix), len(prefix) + len(wav))]


@pytest.mark.parametrize(
    "wav, error",
    [
        pytest.param(riff(), "without chunks", id="no-chunks"),
        pytest.param(
            riff(fmt()), "one format chunk, then one data chunk", id="no-data"
        ),
        pytest.param(
            riff(chunk(b"data", b"\x00\x00")),
            "one format chunk, then one data chunk",
            id="no-fmt",
        ),
        pytest.param(
            riff(fmt(), fmt(), chunk(b"data", b"\x00\x00")),
            "one format chunk, then one data chunk",
            id="two-fmt",
        ),
        pytest.param(
            riff(fmt(), chunk(b"data", b"\x00\x00"), chunk(b"data", b"\x00\x00")),
            "one format chunk, then one data chunk",
            id="two-data",
        ),
        pytest.param(
            riff(chunk(b"data", b"\x00\x00"), fmt()),
            "one format chunk, then one data chunk",
            id="data-first",
        ),
        pytest.param(
            riff(chunk(b"fmt ", b"\x01\x00\x01\x00"), chunk(b"data", b"\x00\x00")),
            "too small",
            id="short-fmt",
        ),
        pytest.param(
            riff(fmt(format_tag=0), chunk(b"data", b"")),
            "Invalid WAV format",
            id="unknown-tag",
        ),
        pytest.param(
            riff(fmt(channels=0), chunk(b"data", b"")),
            "Invalid WAV format",
            id="no-channels",
        ),
        pytest.param(
            riff(fmt(channels=9), chunk(b"data", b"")),
            "Invalid WAV format",
            id="many-channels",
        ),
        pytest.param(
            riff(fmt(sample_rate=0), chunk(b"data", b"")),
            "Invalid WAV format",
            id="no-rate",
        ),
        pytest.param(
            riff(fmt(block_align=0), chunk(b"data", b"")),
            "Invalid WAV format",
            id="no-align",
        ),
        pytest.param(
            riff(fmt(), chunk(b"da\x00a", b"")), "chunk id", id="binary-chunk-id"
        ),
        pytest.param(
            riff(fmt(), chunk(b"data", b"\x00\x00"), size_delta=-1),
            "RIFF size",
            id="size-too-small",
        ),
        pytest.param(b"RIFF\x03\x00\x00\x00WAVE", "RIFF size", id="tiny-size"),
    ],
)
def test_calculate_chunk_rejects_invalid_wav(wav: bytes, error: str):
    with pytest.raises(InvalidInputFormat, match=error):
        calculate_chunk(WAVHandler, wav)


def test_calculate_chunk_rejects_riff_size_past_last_chunk():
    wav = riff(fmt(), chunk(b"data", b"\x00\x00"), size_delta=1) + b"\x00"

    with pytest.raises((EOFError, SeekError)):
        calculate_chunk(WAVHandler, wav)


@pytest.mark.parametrize("cut", [1, 50, 101])
def test_calculate_chunk_rejects_truncated_wav(cut: int):
    with pytest.raises((EOFError, SeekError)):
        calculate_chunk(WAVHandler, make_wav()[:-cut])
