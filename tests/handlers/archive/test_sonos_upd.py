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


def envelope(
    data: bytes = b"\xdd" * 32,
    *,
    recipient: bytes = b"\x11" * 20,
    rsa: bytes = b"\xcc" * 256,
    cipher_id: int = 1,
) -> bytes:
    """Build a structurally valid Sonos encryption envelope."""
    header_len = 0x16 + len(recipient) + 4 + 4 + len(rsa) + 8
    return (
        ENVELOPE_MAGIC
        + header_len.to_bytes(4, "big")
        + b"\x00" * 12
        + bytes([len(recipient), 3])
        + recipient
        + (1).to_bytes(4, "big")
        + len(rsa).to_bytes(4, "big")
        + rsa
        + cipher_id.to_bytes(4, "big")
        + len(data).to_bytes(4, "big")
        + data
    )


PREINSTALL = b"#!/bin/sh\necho preinstall\n"

handler = SonosUPDHandler()


@pytest.mark.parametrize(
    "contents, start_offset, expected_start, expected_end",
    [
        (section(3, 0, PREINSTALL), 0, 0, 16 + len(PREINSTALL)),
        (b"garbage" + section(6, 0, b"kernel") + b"trailing", 7, 7, 7 + 16 + 6),
        (section(0xFFFFFFFF, 1, b"\x00" * 128), 0, 0, 16 + 128),
        (section(15, 0x14, envelope()), 0, 0, 16 + len(envelope())),
        (section(15, 0x94, envelope()), 0, 0, 16 + len(envelope())),
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
    file = File.from_bytes(section(4, 4, envelope()))
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


VALID_ENVELOPE = envelope()


def _patch_envelope(payload: bytes, offset: int, data: bytes) -> bytes:
    patched = bytearray(payload)
    patched[offset : offset + len(data)] = data
    return bytes(patched)


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
        # encryption modifier bits without the encrypted bit
        (section(4, 0x10, b"payload"), InvalidInputFormat),
        (section(4, 0x80, b"payload"), InvalidInputFormat),
        (section(4, 0x90, b"payload"), InvalidInputFormat),
        (section(4, 0x11, b"payload"), InvalidInputFormat),
        # encrypted flag without the envelope magic
        (section(4, 4, b"not an envelope payload"), InvalidInputFormat),
        (section(6, 0x14, b"not an envelope payload"), InvalidInputFormat),
        # envelope magic only, or truncated right after the magic
        (section(4, 4, ENVELOPE_MAGIC), InvalidInputFormat),
        (section(4, 4, ENVELOPE_MAGIC + b"\x00" * 10), InvalidInputFormat),
        # envelope header length below the structural minimum
        (
            section(
                4, 4, _patch_envelope(VALID_ENVELOPE, 4, (0x39).to_bytes(4, "big"))
            ),
            InvalidInputFormat,
        ),
        # envelope header length beyond the payload
        (
            section(
                4, 4, _patch_envelope(VALID_ENVELOPE, 4, (0x1000).to_bytes(4, "big"))
            ),
            InvalidInputFormat,
        ),
        # unexpected recipient length
        (
            section(4, 4, _patch_envelope(VALID_ENVELOPE, 0x14, b"\x10")),
            InvalidInputFormat,
        ),
        # RSA blob not capped by the header
        (
            section(
                4, 4, _patch_envelope(VALID_ENVELOPE, 0x2E, (0x80).to_bytes(4, "big"))
            ),
            InvalidInputFormat,
        ),
        # unsupported cipher id
        (
            section(
                4, 4, _patch_envelope(VALID_ENVELOPE, 0x132, (2).to_bytes(4, "big"))
            ),
            InvalidInputFormat,
        ),
        # data length inconsistent with the payload size
        (
            section(
                4, 4, _patch_envelope(VALID_ENVELOPE, 0x136, (0x40).to_bytes(4, "big"))
            ),
            InvalidInputFormat,
        ),
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
