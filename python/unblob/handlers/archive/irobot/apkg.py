import hashlib
import io
import struct
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
    convert_int32,
    deduplicate_name,
)
from unblob.handlers.compression.gzip import read_gzip_embedded_name
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
        uint32 payload_length; /* bytes after the header, before the signature */
        uint32 signature_length;
        char name[32];        /* package name, NUL padded */
    } apkg_header_t;

    typedef struct apkg_entry {
        uint32 component_type;
        uint32 offset;        /* entry payload offset inside the container */
        uint32 payload_size;
        char version[76];     /* NUL padded version string */
    } apkg_entry_t;

    typedef struct apkg_table {
        uint32 entry_count;
        apkg_entry_t entries[10];
        char magic[4];
    } apkg_table_t;

    typedef struct apkg_metapackage {
        uint32 variant;
        uint32 url_length;
        uint32 certificate_length;
    } apkg_metapackage_t;

    typedef struct sigmastar_metadata {
        char md5[32];
        char md5_reserved[480];
        char product_sku[32];
        char sku_reserved[480];
    } sigmastar_metadata_t;

    typedef struct apkg_sequence_entry {
        uint32 id;
        uint32 unknown;
        uint32 payload_size;
    } apkg_sequence_entry_t;

    typedef struct apkg_sequence_table {
        uint32 entry_count;
        apkg_sequence_entry_t entries[entry_count];
        uint32 first_size;
        uint32 marker_tag;
    } apkg_sequence_table_t;
"""

APKG_HEADER_LEN = 0x30
TABLE_VARIANT_COUNT_OFFSET = APKG_HEADER_LEN
TABLE_VARIANT_ENTRY_CAPACITY = 10
TABLE_VARIANT_LEN = 0x378
SIGMASTAR_METADATA_LEN = 0x400

SEQ_VARIANT_TAG = 0x0B03
SEQ_CRC_START = 0x48
SEQ_CRC_SIZE = 4
SEQ_VARIANT_COUNT_OFFSET = 0x50
SEQ_VARIANT_ENTRY_OFFSET = 0x54
SEQ_VARIANT_ENTRY_SIZE = 12
# The first entry includes an eight-byte block header.
SEQ_VARIANT_MARKER_SIZE = 8

# A parser resource limit, not a standardized on-disk maximum.
MAX_SEQUENTIAL_ENTRY_COUNT = 64

TRAILER_SIG_LEN = 256

# OTA production RSA-2048 public key (DER SubjectPublicKeyInfo).
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
    if (
        separator < 10
        or len(block) - separator - 1 != 32
        or block[2:separator] != b"\xff" * (separator - 2)
    ):
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
    crc_offset: int | None = None

    @classmethod
    def parse(cls, file: File, start_offset: int, header) -> "ApkgContainer":
        data_end = len(header) + header.payload_length
        if header.payload_length < 8:
            raise InvalidInputFormat("Invalid aPKG payload length.")

        file.seek(start_offset + len(header), io.SEEK_SET)
        marker = file.read(8)
        if marker.startswith(b"\x1f\x8b\x08"):
            return cls(data_end=data_end, entries=[], sigmastar=True)

        seq_marker = convert_int32(marker[:4], Endian.LITTLE)
        seq_tag = convert_int32(marker[4:8], Endian.LITTLE)
        if seq_marker == header.payload_length and seq_tag == SEQ_VARIANT_TAG:
            return cls._parse_sequential(file, start_offset, data_end)

        if seq_marker in (0, 1) and header.payload_length >= 20:
            # Skip the certificate length to inspect the start of the URL.
            file.read(4)
            if file.read(8) == b"https://":
                return cls._parse_metapackage(file, start_offset, data_end)

        return cls._parse_entry_table(file, start_offset, data_end)

    @classmethod
    def _parse_metapackage(
        cls, file: File, start_offset: int, data_end: int
    ) -> "ApkgContainer":
        parser = StructParser(C_DEFINITIONS)
        file.seek(start_offset + APKG_HEADER_LEN, io.SEEK_SET)
        meta = parser.parse("apkg_metapackage_t", file, Endian.LITTLE)
        url_offset = APKG_HEADER_LEN + len(meta)
        cert_offset = url_offset + meta.url_length
        cert_end = cert_offset + meta.certificate_length
        if meta.url_length < 9 or cert_end > data_end:
            raise InvalidInputFormat("Invalid aPKG metapackage lengths.")
        file.seek(start_offset + cert_offset - 1, io.SEEK_SET)
        if file.read(1) != b"\0":
            raise InvalidInputFormat("Unterminated aPKG firmware URL.")
        pem_header = b"-----BEGIN CERTIFICATE-----"
        if meta.certificate_length <= len(pem_header):
            raise InvalidInputFormat("Missing aPKG metapackage certificate.")
        if file.read(len(pem_header)) != pem_header:
            raise InvalidInputFormat("Invalid aPKG metapackage certificate.")
        file.seek(start_offset + cert_end - 1, io.SEEK_SET)
        if file.read(1) != b"\0":
            raise InvalidInputFormat("Unterminated aPKG metapackage certificate.")
        if meta.variant == 0 and cert_end != data_end:
            raise InvalidInputFormat("Unexpected data in aPKG metapackage.")
        entries = [
            ApkgEntry(0, url_offset, meta.url_length, "firmware-url"),
            ApkgEntry(1, cert_offset, meta.certificate_length, "certificate.pem"),
        ]
        if cert_end < data_end:
            entries.append(ApkgEntry(2, cert_end, data_end - cert_end, "metadata.bin"))
        return cls(data_end=data_end, entries=entries, sigmastar=False)

    @classmethod
    def _parse_entry_table(
        cls, file: File, start_offset: int, data_end: int
    ) -> "ApkgContainer":
        table_end = APKG_HEADER_LEN + TABLE_VARIANT_LEN
        if table_end > data_end:
            raise InvalidInputFormat("aPKG entry table exceeds container data.")
        parser = StructParser(C_DEFINITIONS)
        file.seek(start_offset + TABLE_VARIANT_COUNT_OFFSET, io.SEEK_SET)
        table = parser.parse("apkg_table_t", file, Endian.LITTLE)
        if table.magic != b"FWPK":
            raise InvalidInputFormat("Invalid aPKG entry table magic.")
        if not 1 <= table.entry_count <= TABLE_VARIANT_ENTRY_CAPACITY:
            raise InvalidInputFormat(f"Invalid aPKG entry count: {table.entry_count}.")
        entries = []
        for entry in table.entries[: table.entry_count]:
            if entry.payload_size == 0:
                raise InvalidInputFormat("aPKG entry with zero size.")
            if entry.offset < table_end or entry.offset + entry.payload_size > data_end:
                raise InvalidInputFormat(
                    "aPKG entry points outside the container data."
                )
            version = entry.version.split(b"\0", 1)[0].decode("ascii", "replace")
            entries.append(
                ApkgEntry(
                    id=entry.component_type,
                    offset=entry.offset,
                    size=entry.payload_size,
                    name=version or None,
                )
            )
        return cls(data_end=data_end, entries=entries, sigmastar=False)

    @classmethod
    def _parse_sequential(
        cls, file: File, start_offset: int, data_end: int
    ) -> "ApkgContainer":
        file.seek(start_offset + SEQ_VARIANT_COUNT_OFFSET, io.SEEK_SET)
        entry_count = convert_int32(file.read(4), Endian.LITTLE)
        if not 1 <= entry_count <= MAX_SEQUENTIAL_ENTRY_COUNT:
            raise InvalidInputFormat(
                f"Invalid aPKG sequential entry count: {entry_count}."
            )
        table_end = SEQ_VARIANT_ENTRY_OFFSET + entry_count * SEQ_VARIANT_ENTRY_SIZE
        if table_end + SEQ_VARIANT_MARKER_SIZE > data_end:
            raise InvalidInputFormat("aPKG entry table exceeds container data.")

        parser = StructParser(C_DEFINITIONS)
        file.seek(start_offset + SEQ_VARIANT_COUNT_OFFSET, io.SEEK_SET)
        table = parser.parse("apkg_sequence_table_t", file, Endian.LITTLE)
        if (
            table.marker_tag != SEQ_VARIANT_TAG
            or table.first_size != table.entries[0].payload_size
        ):
            raise InvalidInputFormat("Invalid aPKG sequential block marker.")

        payload_offset = table_end + SEQ_VARIANT_MARKER_SIZE
        entries = cls._sequential_entries(
            table.entries, payload_offset, data_end - SEQ_CRC_SIZE
        )
        crc_offset = entries[-1].offset + entries[-1].size
        return cls(
            data_end=data_end, entries=entries, sigmastar=False, crc_offset=crc_offset
        )

    @staticmethod
    def _sequential_entries(raw_entries, payload_offset: int, data_end: int):
        entries = []
        for index, entry in enumerate(raw_entries):
            # The first declared size includes the block header.
            size = entry.payload_size - (SEQ_VARIANT_MARKER_SIZE if index == 0 else 0)
            if size <= 0 or payload_offset >= data_end:
                raise InvalidInputFormat("Invalid aPKG sequential entry size.")
            if payload_offset + size > data_end:
                raise InvalidInputFormat(
                    "aPKG sequential entry exceeds container data."
                )
            entries.append(
                ApkgEntry(id=entry.id, offset=payload_offset, size=size, name=None)
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
                    APKG_HEADER_LEN,
                    container.data_end - APKG_HEADER_LEN,
                )
                self._verify_member_digest(fs, file, container.data_end, name)
            else:
                seen: set[str] = set()
                for entry in container.entries:
                    name = self._entry_name(entry, seen)
                    fs.carve(Path(name), file, entry.offset, entry.size)
            if container.crc_offset is not None:
                self._verify_sequential_crc(fs, file, container.crc_offset)
            self._verify_signature(fs, file, container.data_end)
        return ExtractResult(reports=fs.problems)

    def _entry_name(self, entry: ApkgEntry, seen: set[str]) -> str:
        base = f"entry-{entry.id}"
        if entry.name:
            candidate = "".join(
                c if c.isalnum() or c in "+._-" else "_" for c in entry.name
            )
            if candidate not in (".", ".."):
                base = candidate
        return deduplicate_name(base, seen)

    def _gzip_original_name(self, file: File) -> str:
        try:
            file.seek(APKG_HEADER_LEN, io.SEEK_SET)
            name = read_gzip_embedded_name(file, max_name_length=4096, encoding="ascii")
        except (SeekError, EOFError, struct.error):
            return ""
        return name if name != ".." else ""

    def _member_md5(self, file: File, member_len: int):
        """Hash the member bytes."""
        file.seek(APKG_HEADER_LEN, io.SEEK_SET)
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
        # The last two 512-byte sections hold the MD5 and product SKU.
        member_len = data_end - APKG_HEADER_LEN - SIGMASTAR_METADATA_LEN
        if member_len <= 0:
            fs.record_problem(
                ExtractionProblem(
                    problem="Cannot verify aPKG member digest: missing metadata",
                    resolution="payload extracted anyway",
                    path=name,
                )
            )
            return
        file.seek(APKG_HEADER_LEN + member_len, io.SEEK_SET)
        metadata = self._struct_parser.parse(
            "sigmastar_metadata_t", file, Endian.LITTLE
        )
        digest_raw = metadata.md5
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

    def _verify_sequential_crc(self, fs: FileSystem, file: File, crc_offset: int):
        file.seek(crc_offset, io.SEEK_SET)
        expected = convert_int32(file.read(SEQ_CRC_SIZE), Endian.LITTLE)
        file.seek(SEQ_CRC_START, io.SEEK_SET)
        remaining = crc_offset - SEQ_CRC_START
        crc = 0
        while remaining:
            block = file.read(min(remaining, 1 << 20))
            if not block:
                break
            crc = zlib.crc32(block, crc)
            remaining -= len(block)
        if remaining or crc != expected:
            fs.record_problem(
                ExtractionProblem(
                    problem="aPKG sequential CRC-32 mismatch",
                    resolution="payload extracted anyway",
                )
            )

    def _verify_signature(self, fs: FileSystem, file: File, data_end: int):
        # The signature covers the header and the declared payload.
        try:
            file.seek(data_end, io.SEEK_SET)
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
        remaining = data_end
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
            01 00 00 00 // version
            [4]         // payload length
            00 01 00 00 // RSA-2048 signature length
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
            "Entry-table payloads are named by version string, sequential-table "
            "payloads by entry id with CRC-32 verification, and SigmaStar packages yield the embedded "
            "gzip member, verified against the package's MD5 digest. Signed "
            "metapackages yield the firmware URL, TLS certificate and any "
            "additional metadata. The "
            "package trailer is verified as an RSA-2048 signature over the "
            "header and payload against the OTA production public key; "
            "verification failures are reported as "
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
            file.seek(end_offset, io.SEEK_SET)
            signature = file.read(TRAILER_SIG_LEN)
        except (SeekError, EOFError):
            signature = b""
        if _decrypt_signature(signature) is not None:
            end_offset += header.signature_length

        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
