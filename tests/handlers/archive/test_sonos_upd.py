from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat, StructParser
from unblob.handlers.archive.sonos_upd import (
    ALLOWLIST_MAGIC,
    ATTRIBUTE_CRITICAL,
    BL2_SIGNING_KEY_SHIFT,
    C_DEFINITIONS,
    ENVELOPE_MAGIC,
    UBOOT_SIGNING_KEY_SHIFT,
    AllowlistEntryType,
    AttributeType,
    DataEncryptionAlgorithm,
    KeyEncryptionAlgorithm,
    RecipientIdentifierScheme,
    SectionFlag,
    SonosUPDExtractor,
    SonosUPDHandler,
)
from unblob.report import EncryptionMetadataReport

UPD_MAGIC = bytes.fromhex("497f1635")
STRUCTS = StructParser(C_DEFINITIONS)
LE = STRUCTS.cparser_le
BE = STRUCTS.cparser_be

PREINSTALL = b"#!/bin/sh\necho preinstall\n"
handler = SonosUPDHandler()


def section(
    section_type: int,
    flags: SectionFlag,
    payload: bytes,
    *,
    section_size: int | None = None,
) -> bytes:
    header = LE.upd_section_header_t(
        magic=int.from_bytes(UPD_MAGIC, "little"),
        section_type=section_type,
        section_size=section_size if section_size is not None else 16 + len(payload),
        flags=int(flags),
    )
    return header.dumps() + payload


def attribute(attribute_type: int, value: bytes) -> bytes:
    header = BE.envelope_attribute_t(type=attribute_type, length=len(value))
    return header.dumps() + value


def envelope(
    data: bytes = b"\xdd" * 32,
    *,
    recipient: bytes = b"\x11" * 20,
    rsa: bytes = b"\xcc" * 256,
    cipher_id: int = DataEncryptionAlgorithm.AES_128_CBC,
    recipient_count: int = 1,
    recipient_scheme: int = RecipientIdentifierScheme.SHA1,
    key_algorithm: int = KeyEncryptionAlgorithm.RSA_OAEP_SHA1,
    attributes: tuple[bytes, ...] = (),
    version: int = 1,
) -> bytes:
    """Build the version-1 envelope described by the handler's C definitions."""
    recipient_header = BE.envelope_recipient_t(
        identifier_length=len(recipient),
        identifier_scheme=recipient_scheme,
    )
    wrapped_key_header = BE.envelope_wrapped_key_t(
        key_encryption_algorithm=key_algorithm,
        wrapped_key_length=len(rsa),
    )
    recipient_record = (
        recipient_header.dumps() + recipient + wrapped_key_header.dumps() + rsa
    )
    recipient_total = BE.envelope_recipient_count_t(count=recipient_count)
    suffix = BE.envelope_suffix_t(cipher_id=cipher_id, data_length=len(data))
    body = (
        b"".join(attributes)
        + recipient_total.dumps()
        + recipient_record * recipient_count
        + suffix.dumps()
    )
    prefix = BE.envelope_prefix_t(
        magic=ENVELOPE_MAGIC,
        version_major=version,
        version_minor=0,
        attribute_count=len(attributes),
    )
    prefix.header_length = len(prefix) + len(body)
    return prefix.dumps() + body + data


def allowlist(entry_type: int, entry_count: int, entry_size: int) -> bytes:
    header = BE.envelope_allowlist_t(
        magic=ALLOWLIST_MAGIC,
        entry_type=entry_type,
        entry_count=entry_count,
    )
    return header.dumps() + bytes(entry_count * entry_size)


def _patch_envelope(payload: bytes, offset: int, data: bytes) -> bytes:
    patched = bytearray(payload)
    patched[offset : offset + len(data)] = data
    return bytes(patched)


@pytest.mark.parametrize(
    "contents, start_offset, expected_start, expected_end",
    [
        pytest.param(
            section(3, SectionFlag(0), PREINSTALL),
            0,
            0,
            16 + len(PREINSTALL),
            id="plaintext-preinstall",
        ),
        pytest.param(
            b"garbage" + section(6, SectionFlag(0), b"kernel") + b"trailing",
            7,
            7,
            7 + 16 + 6,
            id="embedded-kernel",
        ),
        pytest.param(
            section(0xFFFFFFFF, SectionFlag.SIGNATURE, b"\x00" * 128),
            0,
            0,
            16 + 128,
            id="signed-section",
        ),
        pytest.param(
            section(
                15,
                SectionFlag.ENCRYPTED | SectionFlag(2 << UBOOT_SIGNING_KEY_SHIFT),
                envelope(),
            ),
            0,
            0,
            16 + len(envelope()),
            id="encrypted-bootloader-key-slot-2",
        ),
        pytest.param(
            section(
                15,
                SectionFlag.ENCRYPTED
                | SectionFlag(2 << UBOOT_SIGNING_KEY_SHIFT)
                | SectionFlag(2 << BL2_SIGNING_KEY_SHIFT),
                envelope(),
            ),
            0,
            0,
            16 + len(envelope()),
            id="encrypted-bootloader-key-slots-2-2",
        ),
    ],
)
def test_chunk_calculation(contents, start_offset, expected_start, expected_end):
    with File.from_bytes(contents) as file:
        file.seek(start_offset)
        chunk = handler.calculate_chunk(file, start_offset)

    assert chunk is not None
    assert chunk.start_offset == expected_start
    assert chunk.end_offset == expected_end


def test_encrypted_chunk_is_reported():
    with File.from_bytes(section(4, SectionFlag.ENCRYPTED, envelope())) as file:
        chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.is_encrypted
    assert chunk.metadata_reports == [EncryptionMetadataReport(is_encrypted=True)]


def test_plaintext_chunk_has_no_metadata_reports():
    with File.from_bytes(section(3, SectionFlag(0), PREINSTALL)) as file:
        chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert not chunk.is_encrypted
    assert chunk.metadata_reports == []


VALID_ENVELOPE = envelope()


@pytest.mark.parametrize(
    "contents, error",
    [
        pytest.param(UPD_MAGIC[:3], EOFError, id="magic-truncated"),
        pytest.param(
            section(4, SectionFlag(0), b"")[:8],
            EOFError,
            id="header-truncated",
        ),
        pytest.param(
            section(4, SectionFlag(0), b"", section_size=8),
            InvalidInputFormat,
            id="section-size-smaller-than-header",
        ),
        pytest.param(
            section(4, SectionFlag(0x200), b"payload"),
            InvalidInputFormat,
            id="unknown-flag-bit",
        ),
        pytest.param(
            section(4, SectionFlag(0xFFFF0000), b"payload"),
            InvalidInputFormat,
            id="unknown-upper-flag-bits",
        ),
        pytest.param(
            section(15, SectionFlag(5 << UBOOT_SIGNING_KEY_SHIFT), b"payload"),
            InvalidInputFormat,
            id="invalid-uboot-key-slot-5",
        ),
        pytest.param(
            section(15, SectionFlag(5 << BL2_SIGNING_KEY_SHIFT), b"payload"),
            InvalidInputFormat,
            id="invalid-bl2-key-slot-5",
        ),
        pytest.param(
            section(15, SectionFlag(7 << UBOOT_SIGNING_KEY_SHIFT), b"payload"),
            InvalidInputFormat,
            id="invalid-uboot-key-slot-7",
        ),
        pytest.param(
            section(15, SectionFlag(7 << BL2_SIGNING_KEY_SHIFT), b"payload"),
            InvalidInputFormat,
            id="invalid-bl2-key-slot-7",
        ),
        pytest.param(
            section(4, SectionFlag.ENCRYPTED, b"not an envelope payload"),
            InvalidInputFormat,
            id="encrypted-payload-without-envelope-magic",
        ),
        pytest.param(
            section(
                6,
                SectionFlag.ENCRYPTED | SectionFlag(2 << UBOOT_SIGNING_KEY_SHIFT),
                b"not an envelope payload",
            ),
            InvalidInputFormat,
            id="encrypted-key-slot-without-envelope",
        ),
        pytest.param(
            section(4, SectionFlag.ENCRYPTED, ENVELOPE_MAGIC),
            InvalidInputFormat,
            id="envelope-prefix-missing",
        ),
        pytest.param(
            section(4, SectionFlag.ENCRYPTED, ENVELOPE_MAGIC + b"\x00" * 10),
            InvalidInputFormat,
            id="envelope-prefix-truncated",
        ),
        pytest.param(
            section(
                4,
                SectionFlag.ENCRYPTED,
                _patch_envelope(VALID_ENVELOPE, 4, (0x39).to_bytes(4, "big")),
            ),
            InvalidInputFormat,
            id="envelope-header-too-short",
        ),
        pytest.param(
            section(
                4,
                SectionFlag.ENCRYPTED,
                _patch_envelope(VALID_ENVELOPE, 4, (0x1000).to_bytes(4, "big")),
            ),
            InvalidInputFormat,
            id="envelope-header-exceeds-payload",
        ),
        pytest.param(
            section(
                4,
                SectionFlag.ENCRYPTED,
                _patch_envelope(
                    _patch_envelope(
                        VALID_ENVELOPE,
                        4,
                        (len(VALID_ENVELOPE) - 32 - 8).to_bytes(4, "big"),
                    ),
                    0x136,
                    (40).to_bytes(4, "big"),
                ),
            ),
            InvalidInputFormat,
            id="envelope-field-crosses-declared-header-boundary",
        ),
        pytest.param(
            section(
                4,
                SectionFlag.ENCRYPTED,
                _patch_envelope(VALID_ENVELOPE, 0x14, b"\x10"),
            ),
            InvalidInputFormat,
            id="recipient-length-inconsistent",
        ),
        pytest.param(
            section(
                4,
                SectionFlag.ENCRYPTED,
                _patch_envelope(VALID_ENVELOPE, 0x2E, (0x80).to_bytes(4, "big")),
            ),
            InvalidInputFormat,
            id="wrapped-key-length-inconsistent",
        ),
        pytest.param(
            section(
                4,
                SectionFlag.ENCRYPTED,
                _patch_envelope(VALID_ENVELOPE, 0x132, (3).to_bytes(4, "big")),
            ),
            InvalidInputFormat,
            id="unsupported-content-cipher",
        ),
        pytest.param(
            section(
                4,
                SectionFlag.ENCRYPTED,
                _patch_envelope(VALID_ENVELOPE, 0x136, (0x40).to_bytes(4, "big")),
            ),
            InvalidInputFormat,
            id="encrypted-data-length-inconsistent",
        ),
    ],
)
def test_invalid_chunk(contents, error):
    with File.from_bytes(contents) as file, pytest.raises(error):
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
    inpath.write_bytes(section(section_type, SectionFlag(0), payload))

    SonosUPDExtractor().extract(inpath, tmp_path)

    assert (tmp_path / expected_name).read_bytes() == payload


@pytest.mark.parametrize("uboot_slot", range(5))
@pytest.mark.parametrize("bl2_slot", range(5))
@pytest.mark.parametrize("encrypted", [False, True])
def test_signing_key_slots_do_not_imply_encryption(
    uboot_slot: int, bl2_slot: int, encrypted: bool
):
    flags = SectionFlag(uboot_slot << UBOOT_SIGNING_KEY_SHIFT) | SectionFlag(
        bl2_slot << BL2_SIGNING_KEY_SHIFT
    )
    if encrypted:
        flags |= SectionFlag.ENCRYPTED

    payload = envelope() if encrypted else b"bootloader"
    data = section(15, flags, payload)
    with File.from_bytes(data) as file:
        chunk = handler.calculate_chunk(file, 0)

    assert chunk.end_offset == len(data)
    assert chunk.is_encrypted == encrypted


@pytest.mark.parametrize(
    "algorithm",
    [
        DataEncryptionAlgorithm.AES_128_CBC,
        DataEncryptionAlgorithm.AES_128_GCM,
        DataEncryptionAlgorithm.AES_256_CBC,
        DataEncryptionAlgorithm.AES_256_GCM,
    ],
)
@pytest.mark.parametrize(
    "key_algorithm",
    [
        KeyEncryptionAlgorithm.RSA_OAEP_SHA1,
        KeyEncryptionAlgorithm.RSA_PKCS1,
    ],
)
@pytest.mark.parametrize("recipient_count", [1, 2])
def test_valid_envelope_algorithms(algorithm, key_algorithm, recipient_count):
    payload = envelope(
        cipher_id=algorithm,
        key_algorithm=key_algorithm,
        recipient_count=recipient_count,
        attributes=(attribute(AttributeType.PADDING, b"abc"),),
    )
    data = section(4, SectionFlag.ENCRYPTED, payload)
    with File.from_bytes(data) as file:
        chunk = handler.calculate_chunk(file, 0)

    assert chunk.end_offset == len(data)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(envelope(version=0), id="unsupported-version-zero"),
        pytest.param(envelope(version=2), id="unsupported-version-two"),
        pytest.param(envelope(recipient_count=0), id="no-recipients"),
        pytest.param(envelope(recipient_count=3), id="too-many-recipients"),
        pytest.param(
            envelope(recipient_scheme=0),
            id="unsupported-recipient-identifier-scheme",
        ),
        pytest.param(envelope(key_algorithm=3), id="unsupported-key-algorithm"),
        pytest.param(envelope(rsa=b"x" * 513), id="wrapped-key-too-large"),
        pytest.param(
            envelope(attributes=(attribute(ATTRIBUTE_CRITICAL | 9, b""),)),
            id="unknown-critical-attribute",
        ),
        pytest.param(
            envelope(attributes=(attribute(AttributeType.PADDING, b"x" * 257),)),
            id="attribute-too-large",
        ),
        pytest.param(
            envelope(attributes=(attribute(AttributeType.PADDING, b""),) * 9),
            id="too-many-attributes",
        ),
    ],
)
def test_invalid_envelope_variants(payload):
    with (
        File.from_bytes(section(4, SectionFlag.ENCRYPTED, payload)) as file,
        pytest.raises(InvalidInputFormat),
    ):
        handler.calculate_chunk(file, 0)


def test_optional_section_flag():
    data = section(4, SectionFlag.OPTIONAL, b"payload")
    with File.from_bytes(data) as file:
        chunk = handler.calculate_chunk(file, 0)

    assert chunk.end_offset == len(data)
    assert chunk.metadata_reports == []


def test_encrypted_signature_is_invalid():
    with (
        File.from_bytes(
            section(17, SectionFlag.ENCRYPTED | SectionFlag.SIGNATURE, envelope())
        ) as file,
        pytest.raises(InvalidInputFormat),
    ):
        handler.calculate_chunk(file, 0)


@pytest.mark.parametrize(
    "entry_type, entry_size",
    [
        (AllowlistEntryType.CPU_ID, 8),
        (AllowlistEntryType.SERIAL, 6),
        (AllowlistEntryType.CPU_ID_16, 16),
    ],
)
def test_valid_envelope_allowlist(entry_type, entry_size):
    payload = envelope(
        attributes=(
            attribute(AttributeType.ALLOWLIST, allowlist(entry_type, 2, entry_size)),
        )
    )
    data = section(4, SectionFlag.ENCRYPTED, payload)
    with File.from_bytes(data) as file:
        chunk = handler.calculate_chunk(file, 0)

    assert chunk.end_offset == len(data)


@pytest.mark.parametrize(
    "attribute_data",
    [
        pytest.param(
            attribute(AttributeType.ALLOWLIST, b""),
            id="missing-allowlist-header",
        ),
        pytest.param(
            attribute(AttributeType.ALLOWLIST, allowlist(4, 0, 0)),
            id="unknown-allowlist-entry-type",
        ),
        pytest.param(
            attribute(
                AttributeType.ALLOWLIST,
                allowlist(AllowlistEntryType.CPU_ID, 0, 0)[:-4]
                + (0xFFFFFFFF).to_bytes(4, "big"),
            ),
            id="allowlist-entry-count-too-large",
        ),
        pytest.param(
            BE.envelope_attribute_t(type=AttributeType.ALLOWLIST, length=35).dumps()
            + allowlist(AllowlistEntryType.CPU_ID, 0, 0),
            id="allowlist-length-too-short",
        ),
        pytest.param(
            attribute(AttributeType.MESSAGE_DIGEST, b"\x01"),
            id="message-digest-too-short",
        ),
        pytest.param(
            attribute(AttributeType.MESSAGE_DIGEST, bytes(33)),
            id="unsupported-message-digest-algorithm",
        ),
        pytest.param(
            attribute(AttributeType.CONTENT_TYPE, b""),
            id="content-type-too-short",
        ),
        pytest.param(
            attribute(AttributeType.SRK_REVOKE, bytes(2)),
            id="srk-revocation-length-invalid",
        ),
        pytest.param(
            attribute(AttributeType.ANTI_ROLLBACK_VERSION, b""),
            id="anti-rollback-version-missing",
        ),
    ],
)
def test_invalid_envelope_attribute(attribute_data):
    with (
        File.from_bytes(
            section(
                4,
                SectionFlag.ENCRYPTED,
                envelope(attributes=(attribute_data,)),
            )
        ) as file,
        pytest.raises(InvalidInputFormat),
    ):
        handler.calculate_chunk(file, 0)
