"""Sonos UPD firmware container.

A UPD package is a concatenation of self-delimiting sections. Each section
starts with the same 4-byte magic followed by a little-endian type, total
section size (header included) and flags:

    | magic (4) | section_type (4) | section_size (4) | flags (4) | payload |

There is no file level header, so every section is reported as an
independent chunk and unblob keeps scanning between sections.

Sections whose flags carry the encrypted bit (0x4) hold a Sonos "envelope"
payload (magic 0x886499ca) which wraps an AES-128-CBC encrypted payload
whose key is itself wrapped with RSA-OAEP/SHA-1 for a model specific
RSA-2048 recipient:

    | magic (4) | header_len (4, BE) | (12) | recipient_len (1) | (1) |
    | recipient_id (recipient_len) | (4) | rsa_len (4, BE) |
    | RSA wrapped key (rsa_len) | cipher_id (4, BE) | data_len (4, BE) |
    | IV + ciphertext (data_len) |

The corresponding private keys live on the devices, so encrypted sections
are reported as encrypted and skipped by the extractor; the complete
section (header + envelope + ciphertext) stays as a carved chunk in the
carve directory and can be decrypted offline with the matching private key.

Format reference: https://github.com/BookCatKid/sonos-firmware-archive
"""

import io
from pathlib import Path

from structlog import get_logger

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)
from unblob.report import EncryptionMetadataReport

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct upd_section_header {
        uint32 magic;          /* UPD magic, stored as 49 7f 16 35 */
        uint32 section_type;
        uint32 section_size;   /* total size of this section, header included */
        uint32 flags;
    } upd_section_header_t;
"""

ENCRYPTED_FLAG = 0x04

# Flag bits observed across the preserved UPD catalog (559 packages, 6059
# sections): 0x01 is set on the trailing manifest/signature sections, while
# 0x10 and 0x80 only ever appear together with the encrypted bit on payload
# sections, so 0x00, 0x01, 0x04, 0x14 and 0x94 are the observed values.
KNOWN_FLAGS = 0x01 | 0x04 | 0x10 | 0x80
ENCRYPTION_MODIFIERS = 0x10 | 0x80

# Magic of the RSA-OAEP/AES-128-CBC envelope prepended to encrypted payloads.
ENVELOPE_MAGIC = bytes.fromhex("886499ca")
# Smallest possible envelope header (see the format reference).
ENVELOPE_MIN_HEADER_LEN = 0x3A
# SHA-1 fingerprint of the RSA recipient's public key.
ENVELOPE_RECIPIENT_LEN = 20
# cipher_id identifying AES-128-CBC, the only algorithm seen in the catalog.
ENVELOPE_AES_CBC_ID = 1

# File names for the section types identified by the format reference.
SECTION_NAMES = {
    1: "version",
    2: "compatibility",
    3: "preinstall",
    4: "rootfs",
    6: "kernel",
    9: "partition-table",
    10: "partition-table",
    13: "device-payload",
    15: "device-payload",
    16: "metadata",
    17: "manifest",
    21: "capabilities",
    22: "ca-certificates",
    23: "application",
    0xFFFFFFFF: "signature",
}


class SonosUPDExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse(
                "upd_section_header_t", file, Endian.LITTLE
            )
            name = SECTION_NAMES.get(
                header.section_type, f"section-{header.section_type}"
            )
            fs.carve(Path(name), file, len(header), header.section_size - len(header))
        return ExtractResult(reports=fs.problems)


class SonosUPDHandler(StructHandler):
    NAME = "sonos_upd"

    PATTERNS = [
        HexString(
            """
            49 7f 16 35
        """
        ),
    ]
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "upd_section_header_t"
    EXTRACTOR = SonosUPDExtractor()

    DOC = HandlerDoc(
        name="Sonos UPD",
        description=(
            "Sonos UPD firmware packages are a concatenation of typed sections "
            "(version, compatibility list, preinstall script, kernel, root "
            "filesystem, partition tables, capability strings, certificates, "
            "signatures and payload sections). Each section is carved out and "
            "its payload extracted so nested formats can be processed "
            "recursively. Sections flagged as encrypted carry an RSA-OAEP "
            "wrapped AES-128-CBC envelope and are reported as encrypted."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="Sonos",
        references=[
            Reference(
                title="Sonos firmware archive UPD parser",
                url="https://github.com/BookCatKid/sonos-firmware-archive/blob/687ee8e1067370843ddead7e0ea2fcdd6abde2ac/src/sonos_firmware/upd.py",
            ),
        ],
        limitations=[
            "Encrypted sections are reported but not decrypted or extracted, "
            "as decryption requires device specific RSA-2048 private keys; "
            "the carved sections can be decrypted offline with the matching "
            "key."
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, endian=Endian.LITTLE)

        if header.section_size < len(header):
            raise InvalidInputFormat(
                f"Invalid UPD section size: {header.section_size}."
            )

        if header.flags & ~KNOWN_FLAGS:
            raise InvalidInputFormat(f"Unknown UPD section flags: {header.flags:#x}.")

        if header.flags & ENCRYPTION_MODIFIERS and not header.flags & ENCRYPTED_FLAG:
            raise InvalidInputFormat(
                f"Encryption modifier flags without the encrypted bit: {header.flags:#x}."
            )

        metadata_reports = []
        if header.flags & ENCRYPTED_FLAG:
            # Encrypted sections always start with a Sonos envelope, which
            # both confirms the flag and filters out false positive pattern
            # matches on random data.
            self._validate_envelope(file, start_offset, header)
            metadata_reports.append(EncryptionMetadataReport(is_encrypted=True))

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.section_size,
            metadata_reports=metadata_reports,
        )

    def _validate_envelope(self, file: File, start_offset: int, header) -> None:
        payload_offset = start_offset + len(header)
        payload_size = header.section_size - len(header)

        file.seek(payload_offset, io.SEEK_SET)
        prefix = file.read(8)
        if len(prefix) < 8 or not prefix.startswith(ENVELOPE_MAGIC):
            raise InvalidInputFormat(
                "Encrypted UPD section without the expected envelope magic."
            )

        header_len = int.from_bytes(prefix[4:8], "big")
        if header_len < ENVELOPE_MIN_HEADER_LEN or header_len > payload_size:
            raise InvalidInputFormat(
                f"Invalid UPD envelope header length: {header_len:#x}."
            )

        file.seek(payload_offset, io.SEEK_SET)
        envelope = file.read(header_len)
        if len(envelope) != header_len:
            raise InvalidInputFormat("Truncated UPD envelope header.")

        self._check_envelope_fields(envelope, header_len, payload_size)

    def _check_envelope_fields(
        self, envelope: bytes, header_len: int, payload_size: int
    ) -> None:
        recipient_len = envelope[0x14]
        if recipient_len != ENVELOPE_RECIPIENT_LEN:
            raise InvalidInputFormat(
                f"Unexpected UPD envelope recipient length: {recipient_len}."
            )

        rsa_len_offset = 0x16 + recipient_len + 4
        if rsa_len_offset + 4 > header_len:
            raise InvalidInputFormat("Truncated UPD envelope RSA field.")

        rsa_len = int.from_bytes(envelope[rsa_len_offset : rsa_len_offset + 4], "big")
        rsa_end = rsa_len_offset + 4 + rsa_len
        # The cipher id and data length fields cap the header exactly.
        if rsa_end + 8 != header_len:
            raise InvalidInputFormat("Invalid UPD envelope RSA key length.")

        cipher_id = int.from_bytes(envelope[rsa_end : rsa_end + 4], "big")
        if cipher_id != ENVELOPE_AES_CBC_ID:
            raise InvalidInputFormat(
                f"Unsupported UPD envelope cipher id: {cipher_id}."
            )

        data_len = int.from_bytes(envelope[header_len - 4 : header_len], "big")
        if data_len < 16 or header_len + data_len != payload_size:
            raise InvalidInputFormat("Invalid UPD encrypted data length.")
