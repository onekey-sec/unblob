import struct

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.xiaomi.hdr import HDRExtractor

VALID_BLOB_MAGIC = b"\xbe\xba\x00\x00"  # 0x0000babe, little-endian
INVALID_BLOB_MAGIC = b"\xde\xad\xbe\xef"

BLOB_OFFSET = 0x30


def build_hdr1(blob_magic: bytes) -> bytes:
    header = b"HDR1"
    header += struct.pack("<I", BLOB_OFFSET)  # signature_offset
    header += struct.pack("<I", 0)  # crc32 (checked by calculate_chunk, not parse)
    header += struct.pack("<HH", 0, 0)  # unused, device_id
    header += struct.pack("<8I", BLOB_OFFSET, 0, 0, 0, 0, 0, 0, 0)  # blob_offsets

    blob = blob_magic
    blob += struct.pack("<I", 0)  # flash_offset
    blob += struct.pack("<I", 41)  # blob_size
    blob += struct.pack("<HH", 7, 0)  # type, unused
    blob += b"blob0".ljust(32, b"\x00")  # name
    return header + blob


def test_blob_with_magic_is_parsed():
    file = File.from_bytes(build_hdr1(VALID_BLOB_MAGIC))
    blobs = list(HDRExtractor("hdr1_header_t").parse(file))
    assert len(blobs) == 1


def test_blob_without_magic_is_rejected():
    file = File.from_bytes(build_hdr1(INVALID_BLOB_MAGIC))
    with pytest.raises(InvalidInputFormat):
        list(HDRExtractor("hdr1_header_t").parse(file))
