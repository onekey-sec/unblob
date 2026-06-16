import struct
import zlib

from unblob.file_utils import File
from unblob.handlers.compression.lzo import HeaderFlags, LZOHandler

MAGIC = bytes.fromhex("89 4C 5A 4F 00 0D 0A 1A 0A")


def build_lzo(flags: int, uncompressed_size: int, compressed_size: int) -> bytes:
    """Build a single-block lzo stream.

    A block is stored verbatim (incompressible) when compressed_size equals
    uncompressed_size, in which case lzop writes no compressed checksum.
    """
    body = struct.pack(
        ">HHHBBIIIIB",
        0x1030,  # version
        0x2080,  # libversion
        0x0940,  # reqversion
        1,  # method
        1,  # level
        flags,
        0,  # mode
        0,  # mtime
        0,  # gmtdiff
        0,  # filename_len
    )
    header = MAGIC + body + struct.pack(">I", zlib.adler32(body) & 0xFFFFFFFF)

    block = struct.pack(">I", uncompressed_size) + struct.pack(">I", compressed_size)
    stored = compressed_size >= uncompressed_size
    if not stored and flags & (HeaderFlags.ADLER32_C | HeaderFlags.CRC32_C):
        block += struct.pack(">I", 0)  # compressed checksum
    block += b"\xab" * compressed_size

    return header + block + struct.pack(">I", 0)  # zero size terminator


def test_calculate_chunk_stored_block_with_compressed_checksum_flag():
    # A stored (incompressible) block carries no compressed checksum even when
    # the F_*_C flag is set; the block walk must not skip past one.
    image = build_lzo(HeaderFlags.CRC32_C, uncompressed_size=32, compressed_size=32)
    f = File.from_bytes(image)
    f.seek(0)

    chunk = LZOHandler().calculate_chunk(f, 0)

    assert chunk is not None
    assert chunk.end_offset == len(image)


def test_calculate_chunk_compressed_block_with_compressed_checksum_flag():
    image = build_lzo(HeaderFlags.CRC32_C, uncompressed_size=64, compressed_size=32)
    f = File.from_bytes(image)
    f.seek(0)

    chunk = LZOHandler().calculate_chunk(f, 0)

    assert chunk is not None
    assert chunk.end_offset == len(image)
