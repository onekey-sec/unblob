"""iRobot aPKG firmware container.

aPKG is the outer container of the ``*.signed`` OTA packages used by classic
iRobot robots (Marconi, Aero, Ningbo, Congo, Roomba 9xx, el Paso) and by the
SigmaStar-based generations (100/200/400/500/700 series).

The fixed header is little-endian:

    | magic "aPKG" | version (1) | data_end | field_0c (0x100) | name[32] |

``data_end`` is the offset at which the signed container data ends; every
observed package appends a 304-byte signature trailer after it, which stays
inside the chunk when it carries a valid signature block (see below).

Three payload layouts are observed:

- ``entry-table`` (marconi/aero/ningbo/congo): an entry count at 0x30 followed
  by 0x58-byte entries ``{id, offset, size, label[76]}`` at 0x34. Offsets are
  absolute positions inside the container.
- ``sequential-table`` (elpaso/roomba9xx): ``data_end`` repeated at 0x30, tag
  0x0b03 at 0x34, an entry count at 0x50 and 12-byte entries
  ``{id, field, size}`` at 0x54. A ``{size, 0x0b03}`` marker for the first
  entry follows the table, then payloads are stored back to back in table
  order. The last entry's declared size slightly overshoots the stored data,
  so it is carved up to ``data_end``.
- ``sigmastar-gzip`` (105/105v/205/405/505/705): a gzip member (original
  filename ``SStarOta.bin``) at 0x30, followed by a metadata region whose
  first bytes are the ASCII hex MD5 digest of the member, verified during
  extraction.

Every observed package appends a 304-byte signature trailer after
``data_end``: a 48-byte opaque header followed by a 256-byte RSA-2048
signature. The signature is a PKCS#1 v1.5 block carrying the raw SHA-256
digest (without an ASN.1 DigestInfo prefix) of everything up to and
including the 48-byte trailer header, that is ``package[0 : data_end +
48]``. Packages are verified during extraction against the OTA "Prod"
public key that the robots' own updater embeds; the same key is present in
every payload blob of all aPKG families. When the trailer's RSA block does
not carry valid padding the bytes are not an iRobot trailer at all, so the
chunk then ends at ``data_end`` and the bytes are left to generic handling.

Format reference: https://github.com/BookCatKid/irobot-firmware-archive
"""

import hashlib
import io
import zlib
from dataclasses import dataclass
from pathlib import Path

from structlog import get_logger

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    SeekError,
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
from unblob.report import ExtractionProblem

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct apkg_header {
        char magic[4];        /* "aPKG" */
        uint32 version;       /* container version, always 1 */
        uint32 data_end;      /* end of container data, signature trailer follows */
        uint32 field_0c;      /* always 0x100 in observed packages */
        char name[32];        /* package name, NUL padded */
    } apkg_header_t;

    typedef struct apkg_entry {
        uint32 id;
        uint32 offset;        /* entry payload offset inside the container */
        uint32 payload_size;
        char label[76];       /* NUL padded ASCII label */
    } apkg_entry_t;
"""

TABLE_VARIANT_COUNT_OFFSET = 0x30
TABLE_VARIANT_ENTRY_OFFSET = 0x34
TABLE_VARIANT_ENTRY_SIZE = 0x58

SEQ_VARIANT_TAG = 0x0B03
SEQ_VARIANT_COUNT_OFFSET = 0x50
SEQ_VARIANT_ENTRY_OFFSET = 0x54
SEQ_VARIANT_ENTRY_SIZE = 12
# the {first_size, 0x0b03} marker between the sequential table and the payloads
SEQ_VARIANT_MARKER_SIZE = 8

MAX_ENTRY_COUNT = 64

TRAILER_HEADER_LEN = 48
TRAILER_SIG_LEN = 256
TRAILER_LEN = TRAILER_HEADER_LEN + TRAILER_SIG_LEN

# iRobot OTA "Prod" RSA-2048 public key, embedded by the robots' own updater
# in every aPKG payload blob (public key material only). DER encoded
# SubjectPublicKeyInfo; the same modulus verifies all aPKG families.
_OTA_PUBLIC_KEY = bytes.fromhex(
    "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
    "00eb0697fb663283101e1df855344459c02f333d7e46e39a9fff701d60ccb905"
    "77026fe3d32c4cd556fbdd932a70354e9dbec920e3ea81137b50a91420dac7e8"
    "46ac5c8bb72d7836d5e591ac3690a8bfaac644fced9de110417a7f428cdc7080"
    "f7d71296c58debce1044f96d9d7a5441039ce097cd14c1bb649126031561b278"
    "e917b64c5d39a04473e45456206fcdabf4062261b919686565a9d6fc0be4b4e0"
    "b969ea13e2370c0c9fa88937e7aeaf1f107069445216141159f7af33d4f99b0b"
    "8fd9aa727b7d5a2095043c7f2d9f6ca0b81080a8fe4dbf2fd49c504089067e38"
    "03526afeaa2a0b6f5e1f362e9269facd62b2c1c334e9ab3cdfd743568217adf6"
    "9f0203010001"
)


def _der_tlv(buf: bytes, offset: int):
    """Return (tag, value, next_offset) of a DER element."""
    tag = buf[offset]
    lead = buf[offset + 1]
    if lead & 0x80:
        length_bytes = lead & 0x7F
        length = int.from_bytes(buf[offset + 2 : offset + 2 + length_bytes], "big")
        value_offset = offset + 2 + length_bytes
    else:
        length = lead
        value_offset = offset + 2
    return tag, buf[value_offset : value_offset + length], value_offset + length


def _prod_key_numbers() -> tuple[int, int]:
    """Return (modulus, exponent) of the embedded OTA Prod key."""
    # SubjectPublicKeyInfo ::= SEQ { AlgorithmIdentifier, BIT STRING }
    _, spki, _ = _der_tlv(_OTA_PUBLIC_KEY, 0)
    _, _, pos = _der_tlv(spki, 0)  # AlgorithmIdentifier
    _, bit_string, _ = _der_tlv(spki, pos)
    # RSAPublicKey ::= SEQ { modulus INTEGER, exponent INTEGER }; skip the
    # BIT STRING's unused-bits byte
    _, seq, _ = _der_tlv(bit_string[1:], 0)
    _, modulus, pos = _der_tlv(seq, 0)
    _, exponent, _ = _der_tlv(seq, pos)
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")


_PROD_N, _PROD_E = _prod_key_numbers()


def _decrypt_signature(signature: bytes) -> bytes | None:
    """Public-decrypt a trailer signature block.

    Returns the 32-byte digest when the block is a PKCS#1 v1.5 message
    signed by the iRobot OTA Prod key (``00 01 FF* 00 || digest``), or
    None when the bytes are not such a block.
    """
    if len(signature) != TRAILER_SIG_LEN:
        return None
    s = int.from_bytes(signature, "big")
    if s >= _PROD_N:
        return None
    block = pow(s, _PROD_E, _PROD_N).to_bytes(TRAILER_SIG_LEN, "big")
    if block[:2] != b"\x00\x01":
        return None
    separator = block.find(b"\x00", 2)
    if separator < 10 or len(block) - separator - 1 != 32:
        return None
    return block[separator + 1 :]


@dataclass(frozen=True)
class ApkgEntry:
    id: int
    offset: int
    size: int
    name: str | None


@dataclass(frozen=True)
class ApkgContainer:
    data_end: int
    entries: list[ApkgEntry]
    # for the sigmastar variant the payload is a single gzip member
    sigmastar: bool

    @classmethod
    def parse(cls, file: File, start_offset: int, header) -> "ApkgContainer":
        if header.version != 1:
            raise InvalidInputFormat(
                f"Unsupported aPKG container version: {header.version}."
            )
        if header.field_0c != 0x100:
            raise InvalidInputFormat(
                f"Unexpected aPKG header field: {header.field_0c:#x}."
            )
        data_end = header.data_end
        if data_end <= 0x30:
            raise InvalidInputFormat(f"Invalid aPKG data_end: {data_end:#x}.")

        file.seek(start_offset + TABLE_VARIANT_COUNT_OFFSET, io.SEEK_SET)
        marker = file.read(8)
        if marker[:2] == b"\x1f\x8b":
            if marker[2] != 0x08:  # deflate
                raise InvalidInputFormat("Invalid aPKG gzip member header.")
            return cls(data_end=data_end, entries=[], sigmastar=True)

        seq_marker = int.from_bytes(marker[:4], "little")
        seq_tag = int.from_bytes(marker[4:8], "little")
        if seq_marker == data_end and seq_tag == SEQ_VARIANT_TAG:
            return cls._parse_sequential(file, start_offset, data_end)

        return cls._parse_entry_table(file, start_offset, data_end)

    @classmethod
    def _parse_entry_table(
        cls, file: File, start_offset: int, data_end: int
    ) -> "ApkgContainer":
        file.seek(start_offset + TABLE_VARIANT_COUNT_OFFSET, io.SEEK_SET)
        entry_count = int.from_bytes(file.read(4), "little")
        if not 1 <= entry_count <= MAX_ENTRY_COUNT:
            raise InvalidInputFormat(f"Invalid aPKG entry count: {entry_count}.")
        table_end = TABLE_VARIANT_ENTRY_OFFSET + entry_count * TABLE_VARIANT_ENTRY_SIZE
        if table_end > data_end:
            raise InvalidInputFormat("aPKG entry table exceeds container data.")

        struct_parser = StructParser(C_DEFINITIONS)
        entries = []
        for _ in range(entry_count):
            raw = file.read(TABLE_VARIANT_ENTRY_SIZE)
            if len(raw) != TABLE_VARIANT_ENTRY_SIZE:
                raise InvalidInputFormat("Truncated aPKG entry table.")
            entry = struct_parser.cparser_le.apkg_entry_t(raw)
            if entry.payload_size == 0:
                raise InvalidInputFormat("aPKG entry with zero size.")
            if entry.offset < table_end or entry.offset + entry.payload_size > data_end:
                raise InvalidInputFormat(
                    "aPKG entry points outside the container data."
                )
            label = entry.label.split(b"\0", 1)[0].decode("ascii", "replace")
            entries.append(
                ApkgEntry(
                    id=entry.id,
                    offset=entry.offset,
                    size=entry.payload_size,
                    name=label or None,
                )
            )
        return cls(data_end=data_end, entries=entries, sigmastar=False)

    @classmethod
    def _parse_sequential(
        cls, file: File, start_offset: int, data_end: int
    ) -> "ApkgContainer":
        file.seek(start_offset + SEQ_VARIANT_COUNT_OFFSET, io.SEEK_SET)
        entry_count = int.from_bytes(file.read(4), "little")
        if not 1 <= entry_count <= MAX_ENTRY_COUNT:
            raise InvalidInputFormat(
                f"Invalid aPKG sequential entry count: {entry_count}."
            )
        table_end = SEQ_VARIANT_ENTRY_OFFSET + entry_count * SEQ_VARIANT_ENTRY_SIZE
        if table_end + SEQ_VARIANT_MARKER_SIZE > data_end:
            raise InvalidInputFormat("aPKG entry table exceeds container data.")

        raw_entries = []
        for _ in range(entry_count):
            entry_id = int.from_bytes(file.read(4), "little")
            file.read(4)  # second field, meaning not yet identified
            size = int.from_bytes(file.read(4), "little")
            raw_entries.append((entry_id, size))

        # the table is followed by a {size, 0x0b03} marker describing the
        # first stored entry
        first_size = int.from_bytes(file.read(4), "little")
        marker_tag = int.from_bytes(file.read(4), "little")
        if marker_tag != SEQ_VARIANT_TAG or first_size != raw_entries[0][1]:
            raise InvalidInputFormat("Invalid aPKG sequential block marker.")

        payload_offset = table_end + SEQ_VARIANT_MARKER_SIZE
        entries = cls._sequential_entries(raw_entries, payload_offset, data_end)
        return cls(data_end=data_end, entries=entries, sigmastar=False)

    @staticmethod
    def _sequential_entries(raw_entries, payload_offset: int, data_end: int):
        entries = []
        for ordinal, (entry_id, declared_size) in enumerate(raw_entries):
            if declared_size == 0 or payload_offset >= data_end:
                raise InvalidInputFormat("Invalid aPKG sequential entry size.")
            size = declared_size
            if payload_offset + size > data_end:
                if ordinal != len(raw_entries) - 1:
                    raise InvalidInputFormat(
                        "aPKG sequential entry exceeds container data."
                    )
                # the last declared size overshoots the stored data; carve
                # what is actually stored
                size = data_end - payload_offset
            entries.append(
                ApkgEntry(id=entry_id, offset=payload_offset, size=size, name=None)
            )
            payload_offset += size
        return entries


class IRobotApkgExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("apkg_header_t", file, Endian.LITTLE)
            container = ApkgContainer.parse(file, 0, header)

            if container.sigmastar:
                name = self._gzip_original_name(file) or "payload.bin"
                fs.carve(
                    Path(name),
                    file,
                    0x30,
                    container.data_end - 0x30,
                )
                self._verify_member_digest(fs, file, container.data_end, name)
            else:
                seen: dict[str, int] = {}
                for entry in container.entries:
                    name = self._entry_name(entry, seen)
                    fs.carve(Path(name), file, entry.offset, entry.size)
            self._verify_signature(fs, file, container.data_end)
        return ExtractResult(reports=fs.problems)

    def _entry_name(self, entry: ApkgEntry, seen: dict[str, int]) -> str:
        if entry.name:
            base = "".join(c if c.isalnum() or c in "+._-" else "_" for c in entry.name)
        else:
            base = f"entry-{entry.id}"
        count = seen.get(base, 0)
        seen[base] = count + 1
        return base if count == 0 else f"{base}-{count}"

    def _gzip_original_name(self, file: File) -> str | None:
        # RFC 1952: when FNAME is set the zero-terminated original filename
        # follows the fixed ten-byte header and optional FEXTRA block
        file.seek(0x30, io.SEEK_SET)
        member_header = file.read(10)
        if len(member_header) < 10:
            return None
        flags = member_header[3]
        cursor = 0x30 + 10
        if flags & 0x04:
            file.seek(cursor, io.SEEK_SET)
            extra_len = int.from_bytes(file.read(2), "little")
            cursor += 2 + extra_len
        if not flags & 0x08:
            return None
        file.seek(cursor, io.SEEK_SET)
        raw = file.read(4096).split(b"\0", 1)[0]
        try:
            name = raw.decode("ascii")
        except UnicodeDecodeError:
            return None
        name = Path(name).name
        return name or None

    def _member_len(self, fs: FileSystem, file: File, data_end: int, name: str):
        """Locate the gzip member end with a streaming decompressor pass."""
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        offset = 0x30
        file.seek(offset, io.SEEK_SET)
        try:
            while offset < data_end and not inflater.eof:
                block = file.read(min(1 << 20, data_end - offset))
                if not block:
                    break
                inflater.decompress(block)
                offset += len(block)
        except zlib.error:
            fs.record_problem(
                ExtractionProblem(
                    problem=(
                        "Cannot verify aPKG member digest: "
                        "gzip member does not decompress"
                    ),
                    resolution="payload extracted anyway",
                    path=name,
                )
            )
            return None
        if not inflater.eof:
            fs.record_problem(
                ExtractionProblem(
                    problem="Cannot verify aPKG member digest: truncated member",
                    resolution="payload extracted anyway",
                    path=name,
                )
            )
            return None
        return offset - len(inflater.unused_data) - 0x30

    def _member_md5(self, file: File, member_len: int):
        """Hash the member bytes."""
        file.seek(0x30, io.SEEK_SET)
        hasher = hashlib.md5(usedforsecurity=False)
        remaining = member_len
        while remaining:
            block = file.read(min(remaining, 1 << 20))
            if not block:
                break
            hasher.update(block)
            remaining -= len(block)
        return hasher.hexdigest()

    def _verify_member_digest(
        self, fs: FileSystem, file: File, data_end: int, name: str
    ):
        # the region after the gzip member starts with the ASCII hex MD5
        # digest of the member itself
        member_len = self._member_len(fs, file, data_end, name)
        if member_len is None:
            return
        post_len = data_end - 0x30 - member_len
        if post_len == 0:
            return
        file.seek(0x30 + member_len, io.SEEK_SET)
        digest_raw = file.read(min(32, post_len))
        try:
            expected = digest_raw.decode("ascii")
        except UnicodeDecodeError:
            expected = ""
        if len(expected) != 32 or any(
            c not in "0123456789abcdef" for c in expected.lower()
        ):
            fs.record_problem(
                ExtractionProblem(
                    problem="Cannot verify aPKG member digest: malformed digest",
                    resolution="payload extracted anyway",
                    path=name,
                )
            )
            return

        if self._member_md5(file, member_len) != expected.lower():
            fs.record_problem(
                ExtractionProblem(
                    problem="aPKG member digest mismatch",
                    resolution="payload extracted anyway",
                    path=name,
                )
            )

    def _verify_signature(self, fs: FileSystem, file: File, data_end: int):
        # the 48-byte trailer header and the 256-byte signature sit inside
        # the chunk when calculate_chunk's probe found a decryptable RSA
        # block; the signature covers package[0 : data_end + 48]
        try:
            file.seek(data_end + TRAILER_HEADER_LEN, io.SEEK_SET)
            signature = file.read(TRAILER_SIG_LEN)
        except (SeekError, EOFError):
            signature = b""
        digest = _decrypt_signature(signature)
        if digest is None:
            fs.record_problem(
                ExtractionProblem(
                    problem="aPKG signature trailer missing or unreadable",
                    resolution="payload extracted anyway",
                )
            )
            return
        file.seek(0, io.SEEK_SET)
        hasher = hashlib.sha256()
        remaining = data_end + TRAILER_HEADER_LEN
        while remaining:
            block = file.read(min(remaining, 1 << 20))
            if not block:
                break
            hasher.update(block)
            remaining -= len(block)
        if hasher.digest() != digest:
            fs.record_problem(
                ExtractionProblem(
                    problem="aPKG signature verification failed",
                    resolution="payload extracted anyway",
                )
            )


class IRobotApkgHandler(StructHandler):
    NAME = "irobot_apkg"

    PATTERNS = [
        HexString(
            """
            61 50 4b 47 // "aPKG"
        """
        ),
    ]
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "apkg_header_t"
    EXTRACTOR = IRobotApkgExtractor()

    DOC = HandlerDoc(
        name="iRobot aPKG",
        description=(
            "iRobot aPKG containers wrap classic robot firmware packages "
            "(marconi, aero, ningbo, congo, roomba9xx, elpaso) and "
            "SigmaStar-based packages (100/200/400/500/700 series). "
            "Entry-table payloads are carved out by label, sequential-table "
            "payloads by entry id, and SigmaStar packages yield the embedded "
            "gzip member, verified against the package's MD5 digest. The "
            "package trailer is verified as an RSA-2048 signature over the "
            "whole package against the OTA public key the robots' own "
            "updater ships; verification failures are reported as "
            "extraction problems."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="iRobot",
        references=[
            Reference(
                title="iRobot firmware archive aPKG analysis",
                url="https://github.com/BookCatKid/irobot-firmware-archive/blob/6dee59f86f5991d18b9bd06c089277128ca8aa22/src/irobot_firmware/analyze.py",
            ),
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, endian=Endian.LITTLE)
        container = ApkgContainer.parse(file, start_offset, header)
        end_offset = start_offset + container.data_end

        # a genuine trailer decrypts to a PKCS#1 v1.5 block under the OTA
        # Prod key; without that padding the trailing bytes are not an
        # iRobot trailer and stay outside the chunk
        try:
            file.seek(end_offset + TRAILER_HEADER_LEN, io.SEEK_SET)
            signature = file.read(TRAILER_SIG_LEN)
        except (SeekError, EOFError):
            signature = b""
        if _decrypt_signature(signature) is not None:
            end_offset += TRAILER_LEN

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
