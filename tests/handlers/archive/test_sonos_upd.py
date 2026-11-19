import re
import struct
from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.sonos_upd import (
    ALLOWLIST_MAGIC,
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
    recipient_count: int = 1,
    key_algorithm: int = 1,
    attributes: tuple[bytes, ...] = (),
    version: int = 1,
) -> bytes:
    """Build the version-1 wire structure read by libsonoscrypto."""
    record = (
        struct.pack(">IB", len(recipient), 3)
        + recipient
        + struct.pack(">II", key_algorithm, len(rsa))
        + rsa
    )
    body = (
        struct.pack(">HHI", version, 0, len(attributes))
        + b"".join(attributes)
        + bytes([recipient_count])
        + record * recipient_count
        + struct.pack(">II", cipher_id, len(data))
    )
    return ENVELOPE_MAGIC + struct.pack(">I", 8 + len(body)) + body + data


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
        (section(4, 0x200, b"payload"), InvalidInputFormat),
        (section(4, 0xFFFF0000, b"payload"), InvalidInputFormat),
        # unsupported values in the signing-key slot fields
        (section(15, 5 << 3, b"payload"), InvalidInputFormat),
        (section(15, 5 << 6, b"payload"), InvalidInputFormat),
        (section(15, 7 << 3, b"payload"), InvalidInputFormat),
        (section(15, 7 << 6, b"payload"), InvalidInputFormat),
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
                4, 4, _patch_envelope(VALID_ENVELOPE, 0x132, (3).to_bytes(4, "big"))
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
        (23, "application-archive"),
        (5, "opt-filesystem"),
        (7, "urlbase"),
        (8, "ulen"),
        (9, "partition-table-16"),
        (10, "partition-table-32"),
        (11, "r8-mot"),
        (12, "m16-firmware"),
        (13, "fpga"),
        (15, "bootloader"),
        (16, "m4-firmware"),
        (17, "signature"),
        (20, "firmware"),
        (24, "boot-sound"),
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


@pytest.mark.parametrize(
    "section_type", [1, 5, 7, 8, 9, 10, 11, 12, 18, 19, 20, 23, 24, 0xFFFFFFFF]
)
def test_supported_section_pattern(section_type):
    assert re.match(handler.PATTERNS[0].as_regex(), section(section_type, 0, b""))


def test_unknown_section_pattern():
    assert not re.match(handler.PATTERNS[0].as_regex(), section(42, 0, b""))


@pytest.mark.parametrize("uboot_slot", range(5))
@pytest.mark.parametrize("bl2_slot", range(5))
@pytest.mark.parametrize("encrypted", [False, True])
def test_signing_key_slots_do_not_determine_encryption(uboot_slot, bl2_slot, encrypted):
    flags = (uboot_slot << 3) | (bl2_slot << 6) | (4 if encrypted else 0)
    payload = envelope() if encrypted else b"bootloader"
    data = section(15, flags, payload)
    with File.from_bytes(data) as file:
        chunk = handler.calculate_chunk(file, 0)
        assert chunk.end_offset == len(data)
        assert chunk.is_encrypted == encrypted


@pytest.mark.parametrize("algorithm", [1, 2, 5, 6])
@pytest.mark.parametrize("key_algorithm", [1, 2])
@pytest.mark.parametrize("recipient_count", [1, 2])
def test_envelope_algorithms(algorithm, key_algorithm, recipient_count):
    payload = envelope(
        cipher_id=algorithm,
        key_algorithm=key_algorithm,
        recipient_count=recipient_count,
        attributes=(struct.pack(">II", 1, 3) + b"abc",),
    )
    with File.from_bytes(section(4, 4, payload)) as file:
        assert handler.calculate_chunk(file, 0).is_encrypted


@pytest.mark.parametrize(
    "payload",
    [
        envelope(version=0),
        envelope(version=2),
        envelope(recipient_count=0),
        envelope(recipient_count=3),
        envelope(key_algorithm=3),
        envelope(rsa=b"x" * 513),
        envelope(attributes=(struct.pack(">II", 0x80000009, 0),)),
        envelope(attributes=(struct.pack(">II", 1, 257) + b"x" * 257,)),
        envelope(attributes=(struct.pack(">II", 1, 0),) * 9),
    ],
)
def test_invalid_envelope_variants(payload):
    with (
        File.from_bytes(section(4, 4, payload)) as file,
        pytest.raises(InvalidInputFormat),
    ):
        handler.calculate_chunk(file, 0)


def test_optional_section_flag():
    with File.from_bytes(section(4, 2, b"payload")) as file:
        assert not handler.calculate_chunk(file, 0).is_encrypted


def test_encrypted_signature_is_invalid():
    with (
        File.from_bytes(section(17, 5, envelope())) as file,
        pytest.raises(InvalidInputFormat),
    ):
        handler.calculate_chunk(file, 0)


@pytest.mark.parametrize("entry_type, entry_size", [(1, 8), (2, 6), (3, 16)])
def test_envelope_allowlist(entry_type, entry_size):
    body = ALLOWLIST_MAGIC + struct.pack(">BI", entry_type, 2) + bytes(2 * entry_size)
    payload = envelope(attributes=(struct.pack(">II", 5, len(body)) + body,))
    with File.from_bytes(section(4, 4, payload)) as file:
        assert handler.calculate_chunk(file, 0).is_encrypted


@pytest.mark.parametrize(
    "attribute",
    [
        struct.pack(">II", 5, 0),
        struct.pack(">II", 5, 36) + ALLOWLIST_MAGIC + struct.pack(">BI", 4, 0),
        struct.pack(">II", 5, 36) + ALLOWLIST_MAGIC + struct.pack(">BI", 1, 0xFFFFFFFF),
        struct.pack(">II", 2, 1) + bytes([1]),
        struct.pack(">II", 2, 33) + bytes(33),
        struct.pack(">II", 3, 0),
        struct.pack(">II", 4, 2) + bytes(2),
        struct.pack(">II", 6, 0),
    ],
)
def test_invalid_envelope_attribute(attribute):
    with (
        File.from_bytes(section(4, 4, envelope(attributes=(attribute,)))) as file,
        pytest.raises(InvalidInputFormat),
    ):
        handler.calculate_chunk(file, 0)
