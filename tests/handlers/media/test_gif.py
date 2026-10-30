import struct

import pytest

from unblob.file_utils import InvalidInputFormat
from unblob.handlers.media.gif import GIFHandler
from unblob.testing import calculate_chunk, find_chunks

GLOBAL_COLOR_TABLE_FLAG = 0x80
TRAILER = b"\x3b"


def screen_descriptor(width=2, height=2, flags=GLOBAL_COLOR_TABLE_FLAG) -> bytes:
    # flags & 0x07 == 0: a 2-entry colour table
    table = b"\x00\x00\x00\xff\xff\xff" if flags & GLOBAL_COLOR_TABLE_FLAG else b""
    return struct.pack("<HHBBB", width, height, flags, 0, 0) + table


def sub_blocks(data: bytes) -> bytes:
    blocks = b"".join(
        bytes([len(data[i : i + 255])]) + data[i : i + 255]
        for i in range(0, len(data), 255)
    )
    return blocks + b"\x00"


def image(lzw_code_size=2, data=b"\x44\x01", *, local_color_table=False) -> bytes:
    flags = 0x80 if local_color_table else 0
    table = b"\x00\x00\x00\xff\xff\xff" if local_color_table else b""
    descriptor = b"\x2c" + struct.pack("<HHHHB", 0, 0, 2, 2, flags)
    return descriptor + table + bytes([lzw_code_size]) + sub_blocks(data)


def extension(label: int, data: bytes) -> bytes:
    return bytes([0x21, label]) + sub_blocks(data)


# flags, delay (2 bytes), transparent colour index
GRAPHIC_CONTROL = extension(0xF9, b"\x00\x0a\x00\x00")
# application identifier block, then the looping sub-block, then terminator
NETSCAPE_LOOP = b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00"
ANIMATION_FRAME = GRAPHIC_CONTROL + image(local_color_table=True, data=bytes(600))


def make_gif(*blocks: bytes, version=b"89a", descriptor=None) -> bytes:
    if not blocks:
        blocks = (GRAPHIC_CONTROL, image())
    return (
        b"GIF"
        + version
        + (descriptor or screen_descriptor())
        + b"".join(blocks)
        + TRAILER
    )


@pytest.mark.parametrize(
    "gif",
    [
        pytest.param(make_gif(), id="simple"),
        pytest.param(make_gif(image(), version=b"87a"), id="gif87a"),
        pytest.param(
            make_gif(
                NETSCAPE_LOOP,
                ANIMATION_FRAME,
                ANIMATION_FRAME,
                extension(0xFE, b"comment"),
            ),
            id="animation",
        ),
        pytest.param(
            make_gif(
                image(local_color_table=True), descriptor=screen_descriptor(flags=0)
            ),
            id="no-global-color-table",
        ),
        pytest.param(
            make_gif(descriptor=screen_descriptor(0x100, 0x100)), id="256x256"
        ),
        *(
            pytest.param(
                make_gif(image(lzw_code_size=size)), id=f"lzw-code-size-{size}"
            )
            for size in (2, 8, 11)
        ),
    ],
)
def test_finds_embedded_gif(gif: bytes):
    prefix = b"/images/logo.gif\x00"

    chunks = find_chunks(GIFHandler, prefix + gif + b"\x3b trailing")

    assert chunks == [(len(prefix), len(prefix) + len(gif))]


@pytest.mark.parametrize(
    "width, height",
    [pytest.param(0, 2, id="zero-width"), pytest.param(2, 0, id="zero-height")],
)
def test_pattern_rejects_zero_dimensions(width: int, height: int):
    gif = make_gif(descriptor=screen_descriptor(width, height))

    assert find_chunks(GIFHandler, gif) == []


@pytest.mark.parametrize(
    "gif, error",
    [
        pytest.param(make_gif(GRAPHIC_CONTROL), "without image", id="no-image"),
        pytest.param(make_gif(image(), b"\x00"), "block type", id="unknown-block"),
        *(
            pytest.param(
                make_gif(image(lzw_code_size=size)), "LZW", id=f"lzw-code-size-{size}"
            )
            for size in (0, 1, 12, 255)
        ),
    ],
)
def test_calculate_chunk_rejects_invalid_gif(gif: bytes, error: str):
    with pytest.raises(InvalidInputFormat, match=error):
        calculate_chunk(GIFHandler, gif)


@pytest.mark.parametrize("cut", [1, 2, 5])
def test_calculate_chunk_rejects_truncated_gif(cut: int):
    with pytest.raises(InvalidInputFormat):
        calculate_chunk(GIFHandler, make_gif()[:-cut])
