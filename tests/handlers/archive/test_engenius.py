import struct

from unblob.file_utils import File
from unblob.handlers.archive.engeniustech.engenius import (
    XOR_KEY,
    EngeniusHandler,
)

handler = EngeniusHandler()

# The header is 0x88 bytes long when there is no trailing model name
# (model_len == 0).  The encrypted payload follows it and the `length`
# field holds the absolute image size, i.e. the offset of the end of the
# image, matching the reference decryptor which deciphers from the end of
# the header up to the end of the image.
HEADER_LEN = 0x88


def build_image(length: int, payload: bytes) -> bytes:
    header = b"".join(
        [
            b"\x00\x00\x00\x01",  # unknown_1
            b"\x00\x00\x00\x02",  # vendor_id
            b"\x00\x00\x00\x03",  # product_id
            b"v1.0".ljust(20, b"\x00"),  # version
            struct.pack(">I", length),  # length (absolute image size)
            b"\x00\x00\x00\x00",  # unknown_2
            XOR_KEY * 2,  # checksum (also lets f.find(XOR_KEY) succeed)
            b"\x00" * 32,  # padding
            b"\x00\x00\x00\x00",  # unknown_3
            b"\x12\x34\x56\x78",  # magic
            b"all\x00\x00\x00\x00\x00",  # reg_dom
            b"\x00\x00\x00\x01" * 7,  # the seven version words
            struct.pack(">I", 0),  # model_len
        ]
    )
    assert len(header) == HEADER_LEN
    return header + payload


def test_chunk_calculation():
    payload = b"\xaa" * 64
    image = build_image(HEADER_LEN + len(payload), payload)

    file = File.from_bytes(image)
    chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    # the image ends at `length`; the header must not be counted twice
    assert chunk.end_offset == len(image)
