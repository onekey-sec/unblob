import struct

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.xiaomi.hdr import HDRExtractor

VALID_BLOB_MAGIC = b"\xbe\xba\x00\x00"  # 0x0000babe, little-endian
INVALID_BLOB_MAGIC = b"\xde\xad\xbe\xef"

BLOB_OFFSET = 0x30
BLOB_HEADER_LEN = 0x30  # magic + flash_offset + blob_size + type + unused + name[32]
BLOB_SIZE = 41


def build_hdr1(
    blob_magic: bytes,
    blob_size: int = BLOB_SIZE,
    signature_offset: int | None = None,
) -> bytes:
    # The signature block follows the blobs, so by default place it right where
    # the single blob's data ends.
    blob_data_start = BLOB_OFFSET + BLOB_HEADER_LEN
    if signature_offset is None:
        signature_offset = blob_data_start + blob_size

    header = b"HDR1"
    header += struct.pack("<I", signature_offset)  # signature_offset
    header += struct.pack("<I", 0)  # crc32 (checked by calculate_chunk, not parse)
    header += struct.pack("<HH", 0, 0)  # unused, device_id
    header += struct.pack("<8I", BLOB_OFFSET, 0, 0, 0, 0, 0, 0, 0)  # blob_offsets

    blob = blob_magic
    blob += struct.pack("<I", 0)  # flash_offset
    blob += struct.pack("<I", blob_size)  # blob_size
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


def test_blob_reaching_into_signature_is_rejected():
    # The blob has 16 bytes of room before the signature but declares a much
    # larger size, which would otherwise carve the signature block into its output.
    signature_offset = BLOB_OFFSET + BLOB_HEADER_LEN + 16
    file = File.from_bytes(
        build_hdr1(VALID_BLOB_MAGIC, blob_size=4096, signature_offset=signature_offset)
    )
    with pytest.raises(InvalidInputFormat):
        list(HDRExtractor("hdr1_header_t").parse(file))
