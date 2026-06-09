import struct

import pytest

from unblob.file_utils import Endian, File
from unblob.handlers.filesystem.yaffs import (
    YAFFS2Chunk,
    YAFFS2Entry,
    YAFFS2Parser,
    YAFFSConfig,
    YaffsObjectType,
)

PAGE_SIZE = 512


def make_parser(data: bytes) -> YAFFS2Parser:
    config = YAFFSConfig(
        endianness=Endian.LITTLE,
        page_size=PAGE_SIZE,
        spare_size=16,
        ecc=False,
    )
    return YAFFS2Parser(File.from_bytes(data), config)


@pytest.mark.parametrize("byte_count", [PAGE_SIZE - 1, PAGE_SIZE, PAGE_SIZE + 1])
def test_file_chunk_byte_count_bounded_to_page_size(byte_count: int):
    page = b"A" * PAGE_SIZE
    data = page + b"B" * PAGE_SIZE
    parser = make_parser(data)
    parser.data_chunks[5] = [
        YAFFS2Chunk(
            chunk_id=1,
            offset=0,
            byte_count=byte_count,
            object_id=5,
            seq_number=1,
        )
    ]
    entry = YAFFS2Entry(object_type=YaffsObjectType.FILE, object_id=5, parent_obj_id=1)

    content = b"".join(parser.get_file_chunks(entry))
    expected_size = min(byte_count, PAGE_SIZE)

    assert len(content) == expected_size
    assert content == page[:expected_size]


def test_first_chunk_data_offset_not_negative():
    # When the very first chunk of the image is a file data chunk (chunk_id != 0),
    # iterate_over_file used to yield a pre-read offset for it only, so parse()
    # computed a negative data offset and get_file_chunks sliced from the end of
    # the image, mixing foreign bytes into the extracted file.
    page_size = 2048  # large enough to hold a yaffs2 object header
    spare_size = 64
    config = YAFFSConfig(
        endianness=Endian.LITTLE,
        page_size=page_size,
        spare_size=spare_size,
        ecc=False,
    )

    def tags(seq: int, object_id: int, chunk_id: int, byte_count: int) -> bytes:
        # first 2 bytes are dropped for the non-ecc spare layout
        spare = bytearray(spare_size)
        struct.pack_into("<IIII", spare, 2, seq, object_id, chunk_id, byte_count)
        return bytes(spare)

    def header(object_type: YaffsObjectType, parent: int, name: bytes) -> bytes:
        page = bytearray(page_size)
        struct.pack_into("<I", page, 0, int(object_type))  # type
        struct.pack_into("<I", page, 4, parent)  # parent_obj_id
        struct.pack_into("<H", page, 8, 0xFFFF)  # sum_no_longer_used
        page[10 : 10 + len(name)] = name  # name[256]
        return bytes(page)

    payload = b"A" * 16
    page0 = payload + b"\x00" * (page_size - len(payload))
    image = (
        page0
        + tags(seq=1, object_id=5, chunk_id=1, byte_count=len(payload))
        + header(YaffsObjectType.FILE, parent=1, name=b"f")
        + tags(seq=1, object_id=5, chunk_id=0, byte_count=0)
    )

    parser = YAFFS2Parser(File.from_bytes(image), config)
    parser.parse(store=True)

    assert parser.data_chunks[5][0].offset == 0
    entry = parser.get_entry(5)
    assert entry is not None
    content = b"".join(parser.get_file_chunks(entry))
    assert content == payload
