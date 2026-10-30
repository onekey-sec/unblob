import struct

import pytest

from unblob.file_utils import InvalidInputFormat
from unblob.handlers.media.qoi import MAX_PIXELS, QOIHandler
from unblob.testing import calculate_chunk, find_chunks

END_MARKER = b"\x00" * 7 + b"\x01"

OP_RGB = b"\xfe\x10\x20\x30"
OP_RGBA = b"\xff\x10\x20\x30\x40"
OP_INDEX = b"\x05"
OP_DIFF = b"\x55"
OP_LUMA = b"\xa0\x88"


def op_run(length: int) -> bytes:
    return bytes([0xC0 | (length - 1)])


def make_qoi(width: int, height: int, ops: bytes, channels=4, colorspace=0) -> bytes:
    header = b"qoif" + struct.pack(">IIBB", width, height, channels, colorspace)
    return header + ops + END_MARKER


@pytest.mark.parametrize(
    "qoi",
    [
        pytest.param(
            make_qoi(5, 1, OP_RGBA + OP_RGB + OP_INDEX + OP_DIFF + OP_LUMA),
            id="one-pixel-per-op-type",
        ),
        # 1 + 62 + 62 + 3 = 128 pixels
        pytest.param(
            make_qoi(16, 8, OP_RGB + op_run(62) + op_run(62) + op_run(3), channels=3),
            id="runs",
        ),
        # an INDEX 0 op is a zero byte, the end marker starts with seven of them
        pytest.param(make_qoi(8, 1, b"\x00" * 8), id="zero-ops"),
        pytest.param(make_qoi(1, 1, OP_RGB, colorspace=1), id="linear"),
    ],
)
def test_finds_embedded_qoi(qoi: bytes):
    prefix = b"\x00\x01\x02\x03"

    chunks = find_chunks(QOIHandler, prefix + qoi + END_MARKER + b"\x00" * 16)

    assert chunks == [(len(prefix), len(prefix) + len(qoi))]


@pytest.mark.parametrize(
    "channels, colorspace",
    [
        pytest.param(5, 0, id="bad-channels"),
        pytest.param(4, 2, id="bad-colorspace"),
    ],
)
def test_pattern_rejects_invalid_channels_or_colorspace(channels: int, colorspace: int):
    qoi = make_qoi(1, 1, OP_RGB, channels=channels, colorspace=colorspace)

    assert find_chunks(QOIHandler, qoi) == []


@pytest.mark.parametrize(
    "qoi, error",
    [
        pytest.param(make_qoi(0, 1, OP_RGB), "dimensions", id="zero-width"),
        pytest.param(make_qoi(1, 0, OP_RGB), "dimensions", id="zero-height"),
        pytest.param(make_qoi(MAX_PIXELS, 2, OP_RGB), "dimensions", id="too-large"),
        pytest.param(
            make_qoi(2, 2, OP_RGB + op_run(4)), "more pixels", id="run-past-last-pixel"
        ),
        pytest.param(
            make_qoi(2, 1, OP_RGB + OP_INDEX)[:-1] + b"\x02",
            "end marker",
            id="bad-end-marker",
        ),
        pytest.param(make_qoi(1, 1, OP_RGB), "Standalone", id="whole-file"),
    ],
)
def test_calculate_chunk_rejects_invalid_qoi(qoi: bytes, error: str):
    with pytest.raises(InvalidInputFormat, match=error):
        calculate_chunk(QOIHandler, qoi)


@pytest.mark.parametrize("cut", [1, 8, 9, 11])
def test_calculate_chunk_rejects_truncated_qoi(cut: int):
    qoi = make_qoi(3, 1, OP_RGBA + OP_LUMA + OP_DIFF)

    with pytest.raises(InvalidInputFormat):
        calculate_chunk(QOIHandler, qoi[:-cut])
