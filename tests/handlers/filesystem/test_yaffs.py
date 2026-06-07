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
