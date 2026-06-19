import struct

import pytest

from unblob.file_utils import File
from unblob.handlers.archive.qnap._qnap import FOOTER_LEN
from unblob.handlers.archive.qnap.qnap_nas import QnapHandler

handler = QnapHandler()

# 64 bytes of payload that does not contain the "icpnas" footer signature
PAYLOAD = bytes(range(64))


def footer(encrypted_len: int) -> bytes:
    raw = (
        b"icpnas"
        + struct.pack("<I", encrypted_len)
        + b"QNAPNAS".ljust(16, b"\x00")  # device_id
        + b"5.0.0".ljust(16, b"\x00")  # file_version
        + b"2024-01-01".ljust(16, b"\x00")  # firmware_date
        + b"r1".ljust(16, b"\x00")  # revision
    )
    assert len(raw) == FOOTER_LEN
    return raw


def image(encrypted_len: int) -> File:
    return File.from_bytes(PAYLOAD + footer(encrypted_len))


def test_chunk_calculation():
    chunk = handler.calculate_chunk(image(len(PAYLOAD)), 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == len(PAYLOAD) + FOOTER_LEN


@pytest.mark.parametrize("encrypted_len", [len(PAYLOAD) + 1, 0x4000, 0])
def test_rejects_out_of_range_encrypted_len(encrypted_len):
    # encrypted_len reaching past the payload would make QnapExtractor decrypt
    # into the footer and underflow the trailing plaintext copy length.
    assert handler.calculate_chunk(image(encrypted_len), 0) is None
