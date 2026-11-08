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
RSA-2048 recipient. The corresponding private keys live on the devices, so
encrypted sections are reported as encrypted and are left as carved chunks;
a carved envelope can be decrypted offline with the matching private key.

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

# Flag bits observed across the preserved UPD catalog (559 packages): 0x01 is
# set on the trailing manifest/signature sections, while 0x10 and 0x80 only
# appear together with the encrypted bit on payload sections.
KNOWN_FLAGS = 0x01 | 0x04 | 0x10 | 0x80

# Magic of the RSA-OAEP/AES-128-CBC envelope prepended to encrypted payloads.
ENVELOPE_MAGIC = bytes.fromhex("886499ca")

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
            "Encrypted sections are reported but not decrypted, as decryption "
            "requires device specific RSA-2048 private keys; carved sections "
            "can be decrypted offline with the matching key."
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

        metadata_reports = []
        if header.flags & ENCRYPTED_FLAG:
            # Encrypted sections always start with the Sonos envelope magic,
            # which both confirms the flag and filters out false positive
            # pattern matches on random data.
            file.seek(start_offset + len(header), io.SEEK_SET)
            if file.read(len(ENVELOPE_MAGIC)) != ENVELOPE_MAGIC:
                raise InvalidInputFormat(
                    "Encrypted UPD section without the expected envelope magic."
                )
            metadata_reports.append(EncryptionMetadataReport(is_encrypted=True))

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.section_size,
            metadata_reports=metadata_reports,
        )
