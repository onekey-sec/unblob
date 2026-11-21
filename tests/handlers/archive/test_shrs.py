import hashlib
import struct

import pytest

from unblob.file_utils import InvalidInputFormat
from unblob.handlers.archive.dlink.shrs import SHRSHandler
from unblob.testing import calculate_chunk

HEADER_SIZE = 4 + 4 + 4 + 16 + 3 * 64 + 3 * 512


def build_image(file_size: int, payload: bytes) -> bytes:
    header = b"".join(
        [
            b"SHRS",
            struct.pack(">I", file_size),
            struct.pack(">I", len(payload)),  # file_size_no_padding
            b"\x01" * 16,  # iv
            b"\x00" * 64,  # decrypted_key_digest
            b"\x00" * 64,  # decrypted_digest
            hashlib.sha512(payload).digest(),  # encrypted_digest
            b"\x00" * 512,  # unused
            b"\x00" * 512,  # signature_1
            b"\x00" * 512,  # signature_2
        ]
    )
    assert len(header) == HEADER_SIZE
    return header + payload


# 2048 is a multiple of the 1 KiB decryption buffer, 2064 is not
@pytest.mark.parametrize("file_size", [2048, 2064])
@pytest.mark.parametrize("prefix", [b"", b"P" * 7])
@pytest.mark.parametrize("suffix", [b"", b"S" * 2000])
def test_chunk_calculation(file_size: int, prefix: bytes, suffix: bytes):
    image = build_image(file_size, b"\xaa" * file_size)

    chunk = calculate_chunk(SHRSHandler, prefix + image + suffix, len(prefix))

    assert chunk is not None
    assert chunk.start_offset == len(prefix)
    assert chunk.end_offset == len(prefix) + len(image)


def test_truncated_image():
    # only half of the declared firmware is present: the chunk end still comes
    # from the header (unblob drops a chunk past the end of the file)
    image = build_image(4096, b"\xaa" * 2048)

    chunk = calculate_chunk(SHRSHandler, image)

    assert chunk is not None
    assert chunk.end_offset == HEADER_SIZE + 4096


@pytest.mark.parametrize(
    "image",
    [
        pytest.param(
            build_image(HEADER_SIZE - 1, b"\xaa" * 2048), id="file_size_below_header"
        ),
        pytest.param(
            build_image(2048, b"\xaa" * 2048)[:-1] + b"\xab",
            id="encrypted_digest_mismatch",
        ),
    ],
)
def test_invalid_chunk(image: bytes):
    with pytest.raises(InvalidInputFormat, match="Invalid SHRS header"):
        calculate_chunk(SHRSHandler, image)
