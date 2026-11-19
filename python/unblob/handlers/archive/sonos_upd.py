import io
from enum import IntEnum, IntFlag
from pathlib import Path

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

C_DEFINITIONS = r"""
    typedef struct upd_section_header {
        uint32 magic;          /* UPD magic, stored as 49 7f 16 35 */
        uint32 section_type;
        uint32 section_size;   /* total size of this section, header included */
        uint32 flags;
    } upd_section_header_t;

    /* Envelope fields are big-endian. */
    typedef struct envelope_prefix {
        char magic[4];
        uint32 header_length;
        uint16 version_major;
        uint16 version_minor; /* inferred from the shared signature header */
        uint32 attribute_count;
    } envelope_prefix_t;

    typedef struct envelope_attribute {
        uint32 type;
        uint32 length;
    } envelope_attribute_t;

    typedef struct envelope_allowlist {
        char magic[31];
        uint8 entry_type;
        uint32 entry_count;
    } envelope_allowlist_t;

    typedef struct envelope_recipient_count {
        uint8 count;
    } envelope_recipient_count_t;

    typedef struct envelope_recipient {
        uint32 identifier_length;
        uint8 identifier_scheme;
    } envelope_recipient_t;

    typedef struct envelope_wrapped_key {
        uint32 key_encryption_algorithm;
        uint32 wrapped_key_length;
    } envelope_wrapped_key_t;

    typedef struct envelope_suffix {
        uint32 cipher_id;
        uint32 data_length;
    } envelope_suffix_t;
"""


class SectionFlag(IntFlag):
    SIGNATURE = 0x01
    # Unrecognized optional sections may be skipped.
    OPTIONAL = 0x02
    ENCRYPTED = 0x04
    # Signing-key slots occupy multibit fields in bootloader sections.
    UBOOT_SIGNING_KEY_MASK = 0x38
    BL2_SIGNING_KEY_MASK = 0x1C0


KNOWN_FLAGS = (
    SectionFlag.SIGNATURE
    | SectionFlag.OPTIONAL
    | SectionFlag.ENCRYPTED
    | SectionFlag.UBOOT_SIGNING_KEY_MASK
    | SectionFlag.BL2_SIGNING_KEY_MASK
)
UBOOT_SIGNING_KEY_SHIFT = 3
BL2_SIGNING_KEY_SHIFT = 6
# The updater recognizes slots 1 through 4. Zero is unspecified.
MAX_SIGNING_KEY_SLOT = 4

ENVELOPE_MAGIC = bytes.fromhex("886499ca")
ENVELOPE_VERSION = 1
MAX_ENVELOPE_ATTRIBUTES = 8
MAX_ATTRIBUTE_LENGTH = 256
MAX_RECIPIENTS = 2
MAX_RECIPIENT_IDENTIFIER_LENGTH = 0x7FF
MAX_WRAPPED_KEY_LENGTH = 512


class AttributeType(IntEnum):
    PADDING = 1
    MESSAGE_DIGEST = 2
    CONTENT_TYPE = 3
    SRK_REVOKE = 4
    ALLOWLIST = 5
    ANTI_ROLLBACK_VERSION = 6


class RecipientIdentifierScheme(IntEnum):
    X509_INLINE = 1
    X509_SUBJECT_KEY_IDENTIFIER = 2
    SHA1 = 3
    NAME = 4
    RSA_INLINE = 5


SUPPORTED_RECIPIENT_IDENTIFIER_SCHEMES = {
    RecipientIdentifierScheme.X509_INLINE,
    RecipientIdentifierScheme.X509_SUBJECT_KEY_IDENTIFIER,
    RecipientIdentifierScheme.SHA1,
    RecipientIdentifierScheme.NAME,
    RecipientIdentifierScheme.RSA_INLINE,
}


class AllowlistEntryType(IntEnum):
    CPU_ID = 1
    SERIAL = 2
    CPU_ID_16 = 3


ALLOWLIST_MAGIC = bytes.fromhex(
    "56ea9f16215431a5ba0f50abf164fa176dabb010c4b5719e333159c682ba4c"
)
ALLOWLIST_ENTRY_SIZES: dict[int, int] = {
    AllowlistEntryType.CPU_ID: 8,
    AllowlistEntryType.SERIAL: 6,
    AllowlistEntryType.CPU_ID_16: 16,
}
# Message digests contain a one-byte algorithm ID and a SHA-256 digest.
ATTRIBUTE_LENGTHS: dict[int, int] = {
    AttributeType.MESSAGE_DIGEST: 33,
    AttributeType.CONTENT_TYPE: 4,
    AttributeType.SRK_REVOKE: 1,
    AttributeType.ANTI_ROLLBACK_VERSION: 4,
}
ATTRIBUTE_CRITICAL = 0x80000000


class KeyEncryptionAlgorithm(IntEnum):
    RSA_OAEP_SHA1 = 1
    RSA_PKCS1 = 2


SUPPORTED_KEY_ENCRYPTION_ALGORITHMS = {
    KeyEncryptionAlgorithm.RSA_OAEP_SHA1,
    KeyEncryptionAlgorithm.RSA_PKCS1,
}


class DataEncryptionAlgorithm(IntEnum):
    AES_128_CBC = 1
    AES_128_GCM = 2
    AES_256_CBC = 5
    AES_256_GCM = 6


# CBC requires at least an IV and one encrypted block;
# GCM requires space for its nonce and authentication tag.
MIN_ENCRYPTED_DATA_LEN = {
    DataEncryptionAlgorithm.AES_128_CBC: 32,
    DataEncryptionAlgorithm.AES_128_GCM: 28,
    DataEncryptionAlgorithm.AES_256_CBC: 32,
    DataEncryptionAlgorithm.AES_256_GCM: 28,
}

SECTION_NAMES = {
    1: "version",
    2: "compatibility",
    3: "preinstall",
    4: "rootfs",
    5: "opt-filesystem",
    6: "kernel",
    7: "urlbase",
    8: "ulen",
    9: "partition-table-16",
    10: "partition-table-32",
    11: "r8-mot",
    12: "m16-firmware",
    13: "fpga",
    15: "bootloader",
    16: "m4-firmware",
    17: "signature",
    20: "firmware",
    21: "capabilities",
    22: "ca-certificates",
    23: "application-archive",
    24: "boot-sound",
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
            // Known and observed section types (18 and 19 remain unnamed).
            ( ( 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 0a | 0b | 0c | 0d | 0f |
                10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 ) 00 00 00 | ff ff ff ff )
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
            "recursively. Encrypted sections carry a Sonos cryptographic "
            "envelope and are reported as encrypted."
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
            "as decryption requires the designated recipient private key."
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk:
        header = self.parse_header(file, endian=Endian.LITTLE)

        if header.section_size < len(header):
            raise InvalidInputFormat(
                f"Invalid UPD section size: {header.section_size}."
            )

        if header.flags & ~int(KNOWN_FLAGS):
            raise InvalidInputFormat(f"Unknown UPD section flags: {header.flags:#x}.")

        uboot_slot = (
            header.flags & SectionFlag.UBOOT_SIGNING_KEY_MASK
        ) >> UBOOT_SIGNING_KEY_SHIFT
        bl2_slot = (
            header.flags & SectionFlag.BL2_SIGNING_KEY_MASK
        ) >> BL2_SIGNING_KEY_SHIFT
        if header.section_type == 15 and (
            uboot_slot > MAX_SIGNING_KEY_SLOT or bl2_slot > MAX_SIGNING_KEY_SLOT
        ):
            raise InvalidInputFormat("Invalid UPD signing key slot.")

        metadata_reports = []
        if header.flags & SectionFlag.ENCRYPTED:
            if header.flags & SectionFlag.SIGNATURE:
                raise InvalidInputFormat("Encrypted UPD signature section.")
            # Encrypted sections always start with a Sonos envelope, which
            # both confirms the flag and filters out false positive pattern
            # matches on random data.
            _EnvelopeParser(file, header.section_size - len(header)).validate()
            metadata_reports.append(EncryptionMetadataReport(is_encrypted=True))

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.section_size,
            metadata_reports=metadata_reports,
        )


class _EnvelopeParser:
    """Validate encrypted section framing without decrypting the payload."""

    def __init__(self, file: File, payload_size: int):
        self._file = file
        self._start = file.tell()
        self._payload_size = payload_size
        self._end = self._start + payload_size
        self._parser = StructParser(C_DEFINITIONS)

    def _parse(self, struct_name: str):
        struct_type = getattr(self._parser.cparser_be, struct_name)
        self._check_size(len(struct_type))
        return self._parser.parse(struct_name, self._file, Endian.BIG)

    def _check_size(self, length: int):
        if self._file.tell() + length > self._end:
            raise InvalidInputFormat("UPD envelope header field exceeds bounds.")

    def _skip(self, length: int):
        self._check_size(length)
        self._file.seek(length, io.SEEK_CUR)

    def _parse_attributes(self, count: int):
        if count > MAX_ENVELOPE_ATTRIBUTES:
            raise InvalidInputFormat("Too many UPD envelope attributes.")
        for _ in range(count):
            attribute = self._parse("envelope_attribute_t")
            attribute_type = attribute.type & ~ATTRIBUTE_CRITICAL
            # Allowlists carry an entry count inside their TLV value.
            if attribute_type == AttributeType.ALLOWLIST:
                self._parse_allowlist(attribute.length)
                continue
            self._parse_attribute_value(
                attribute_type, attribute.type, attribute.length
            )

    def _parse_attribute_value(self, attribute_type: int, raw_type: int, length: int):
        if length > MAX_ATTRIBUTE_LENGTH:
            raise InvalidInputFormat("UPD envelope attribute too large.")
        if raw_type & ATTRIBUTE_CRITICAL:
            try:
                AttributeType(attribute_type)
            except ValueError as exc:
                raise InvalidInputFormat(
                    "Unknown critical UPD envelope attribute."
                ) from exc
        if (
            attribute_type in ATTRIBUTE_LENGTHS
            and length != ATTRIBUTE_LENGTHS[attribute_type]
        ):
            raise InvalidInputFormat("Invalid UPD envelope attribute length.")
        if attribute_type == AttributeType.MESSAGE_DIGEST:
            self._check_size(1)
            if self._file.read(1) != bytes([1]):
                raise InvalidInputFormat("Unsupported UPD attribute hash algorithm.")
            self._skip(length - 1)
        else:
            self._skip(length)

    def _parse_allowlist(self, length: int):
        allowlist = self._parse("envelope_allowlist_t")
        entry_size = ALLOWLIST_ENTRY_SIZES.get(allowlist.entry_type)
        if allowlist.magic != ALLOWLIST_MAGIC or entry_size is None:
            raise InvalidInputFormat("Invalid UPD envelope allowlist.")
        entries_length = allowlist.entry_count * entry_size
        if length != len(allowlist) + entries_length:
            raise InvalidInputFormat("Invalid UPD envelope allowlist length.")
        self._skip(entries_length)

    def _parse_recipient(self):
        recipient = self._parse("envelope_recipient_t")
        if recipient.identifier_scheme not in SUPPORTED_RECIPIENT_IDENTIFIER_SCHEMES:
            raise InvalidInputFormat("Unsupported UPD recipient identifier scheme.")
        if not 1 <= recipient.identifier_length <= MAX_RECIPIENT_IDENTIFIER_LENGTH:
            raise InvalidInputFormat("Invalid UPD recipient identifier length.")
        self._skip(recipient.identifier_length)
        wrapped_key = self._parse("envelope_wrapped_key_t")
        if (
            wrapped_key.key_encryption_algorithm
            not in SUPPORTED_KEY_ENCRYPTION_ALGORITHMS
        ):
            raise InvalidInputFormat("Unsupported UPD key encryption algorithm.")
        if not 1 <= wrapped_key.wrapped_key_length <= MAX_WRAPPED_KEY_LENGTH:
            raise InvalidInputFormat("Invalid UPD wrapped key length.")
        self._skip(wrapped_key.wrapped_key_length)

    def validate(self):
        prefix = self._parse("envelope_prefix_t")
        if prefix.magic != ENVELOPE_MAGIC or prefix.version_major != ENVELOPE_VERSION:
            raise InvalidInputFormat("Invalid UPD envelope magic or version.")
        header_len = prefix.header_length
        if not len(prefix) <= header_len <= self._payload_size:
            raise InvalidInputFormat("Invalid UPD envelope header length.")
        self._end = self._start + header_len
        self._parse_attributes(prefix.attribute_count)

        recipient_count = self._parse("envelope_recipient_count_t").count
        if not 1 <= recipient_count <= MAX_RECIPIENTS:
            raise InvalidInputFormat("Invalid UPD envelope recipient count.")
        for _ in range(recipient_count):
            self._parse_recipient()

        suffix = self._parse("envelope_suffix_t")
        min_data_len = MIN_ENCRYPTED_DATA_LEN.get(suffix.cipher_id)
        if min_data_len is None:
            raise InvalidInputFormat(
                f"Unsupported UPD envelope cipher id: {suffix.cipher_id}."
            )
        if (
            suffix.data_length < min_data_len
            or header_len + suffix.data_length != self._payload_size
        ):
            raise InvalidInputFormat("Invalid UPD encrypted data length.")
