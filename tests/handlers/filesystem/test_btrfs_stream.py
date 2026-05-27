from pathlib import Path

import pytest

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
)
from unblob.handlers.filesystem.btrfs_stream import C_DEFINITIONS, BTRFSParser

STREAM_HEADER = b"btrfs-stream\x00" + (2).to_bytes(4, "little")


def tlv(tlv_type: int, value: bytes) -> bytes:
    return tlv_type.to_bytes(2, "little") + len(value).to_bytes(2, "little") + value


def test_encoded_write_rejects_data_len_underflow(tmp_path: Path):
    # cmd_header.data_len is smaller than the bytes the ENCODED_WRITE command
    # consumes, so `data_len` turns negative and File.read() would return the
    # whole rest of the mapping instead of the declared payload.
    encoded_write = (
        tlv(15, b"file")  # path
        + tlv(0, bytes(8))  # file_offset
        + tlv(0, bytes(8))  # unencoded_file_len
        + tlv(0, bytes(8))  # unencoded_len
        + tlv(0, bytes(8))  # unencoded_offset
        + tlv(0, bytes(4))  # compression (NONE)
        + tlv(0, bytes(4))  # encryption
        + (24).to_bytes(2, "little")  # DATA tlv type, no length in v2
    )
    cmd_header = (0).to_bytes(4, "little") + (25).to_bytes(2, "little") + bytes(4)
    file = File.from_bytes(STREAM_HEADER + cmd_header + encoded_write + b"\xff" * 4096)

    parser = BTRFSParser(file, 0)
    header = StructParser(C_DEFINITIONS).parse("cmd_header_t", file, Endian.LITTLE)
    with pytest.raises(InvalidInputFormat):
        parser.replay_encoded_write(FileSystem(tmp_path), header)
