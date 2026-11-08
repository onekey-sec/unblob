import struct
from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.sonos_upd import (
    ENVELOPE_MAGIC,
    SonosUPDExtractor,
    SonosUPDHandler,
)
from unblob.report import EncryptionMetadataReport

UPD_MAGIC = bytes.fromhex("497f1635")


def section(section_type: int, flags: int, payload: bytes) -> bytes:
    return (
        UPD_MAGIC
        + struct.pack("<III", section_type, 16 + len(payload), flags)
        + payload
    )


PREINSTALL = b"#!/bin/sh\necho preinstall\n"
ENVELOPE = ENVELOPE_MAGIC + b"\x00" * 312 + b"\xaa" * 32

handler = SonosUPDHandler()


@pytest.mark.parametrize(
    "contents, start_offset, expected_start, expected_end",
    [
        (section(3, 0, PREINSTALL), 0, 0, 16 + len(PREINSTALL)),
        (b"garbage" + section(6, 0, b"kernel") + b"trailing", 7, 7, 7 + 16 + 6),
        (section(0xFFFFFFFF, 1, b"\x00" * 128), 0, 0, 16 + 128),
        (section(15, 0x14, ENVELOPE), 0, 0, 16 + len(ENVELOPE)),
    ],
)
def test_chunk_calculation(contents, start_offset, expected_start, expected_end):
    file = File.from_bytes(contents)
    # the finder seeks the file to the match offset before calling
    file.seek(start_offset)
    chunk = handler.calculate_chunk(file, start_offset)

    assert chunk is not None
    assert chunk.start_offset == expected_start
    assert chunk.end_offset == expected_end


def test_encrypted_chunk_is_reported():
    file = File.from_bytes(section(4, 4, ENVELOPE))
    chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.is_encrypted
    assert chunk.metadata_reports == [EncryptionMetadataReport(is_encrypted=True)]


def test_plaintext_chunk_has_no_metadata_reports():
    file = File.from_bytes(section(3, 0, PREINSTALL))
    chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert not chunk.is_encrypted
    assert chunk.metadata_reports == []


@pytest.mark.parametrize(
    "contents, error",
    [
        # header shorter than the magic
        (UPD_MAGIC[:3], EOFError),
        # truncated header
        (UPD_MAGIC + b"\x04\x00\x00\x00", EOFError),
        # section_size smaller than the header
        (
            section(4, 0, b"")[:8] + struct.pack("<I", 8) + b"\x00" * 4,
            InvalidInputFormat,
        ),
        # unknown flag bits set
        (section(4, 0x02, b"payload"), InvalidInputFormat),
        (section(4, 0x40, b"payload"), InvalidInputFormat),
        (section(4, 0x100, b"payload"), InvalidInputFormat),
        (section(4, 0xFFFF0000, b"payload"), InvalidInputFormat),
        # encrypted flag without the envelope magic
        (section(4, 4, b"not an envelope payload"), InvalidInputFormat),
        (section(6, 0x14, b"not an envelope payload"), InvalidInputFormat),
        # encrypted flag with a truncated envelope magic
        (section(4, 4, ENVELOPE_MAGIC[:2]), InvalidInputFormat),
    ],
)
def test_invalid_chunk(contents, error):
    file = File.from_bytes(contents)
    with pytest.raises(error):
        handler.calculate_chunk(file, 0)


@pytest.mark.parametrize(
    "section_type, expected_name",
    [
        (1, "version"),
        (3, "preinstall"),
        (4, "rootfs"),
        (6, "kernel"),
        (21, "capabilities"),
        (23, "application"),
        (0xFFFFFFFF, "signature"),
        (42, "section-42"),
    ],
)
def test_extract(tmp_path: Path, section_type: int, expected_name: str):
    payload = b"payload-bytes"
    inpath = tmp_path / "in.sonos_upd"
    inpath.write_bytes(section(section_type, 0, payload))

    SonosUPDExtractor().extract(inpath, tmp_path)

    assert (tmp_path / expected_name).read_bytes() == payload
    assert (tmp_path / expected_name).stat().st_size == len(payload)
