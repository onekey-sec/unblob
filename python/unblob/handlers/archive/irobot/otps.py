import hashlib
import io
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from structlog import get_logger

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    convert_int32,
    deduplicate_name,
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
    typedef struct otps_header {
        char magic[4];     /* "Otps" */
        uint32 total_len;  /* length of everything after this field */
    } otps_header_t;

    typedef struct otps_tlv_header {
        char tag[4];
        uint32 length;
    } otps_tlv_header_t;

    typedef struct otps_tlv {
        char tag[4];
        uint32 length;
        char value[length];
    } otps_tlv_t;
"""

HEADER_LEN = 8
MAX_TLV_ELEMENTS = 512  # extraction resource limit
HASH_CHUNK_SIZE = 1024 * 1024
SHA256_LEN = 32

# Capacities of the OTA metadata fields in the bootloader.
MAX_CERT_SIZE = 2048
MAX_SIGNATURE_SIZE = 512
MAX_SALG_SIZE = 32
MAX_KEYT_SIZE = 64


class Tag(bytes, Enum):
    COMMENT = b"cmnt"
    SIGNED_DATA = b"Sdat"
    SIGNATURE = b"Sign"
    ALGORITHM = b"salg"
    BLOB = b"blob"
    CERTIFICATE = b"cert"
    HASH = b"hash"
    SIZE = b"size"
    KEY_TYPE = b"keyt"
    CONTENT_ID = b"cnid"
    IMAGE_TYPE = b"type"
    SEQUENCE_ID = b"sqid"
    UNIQUE_ID = b"uqid"
    CONTROL_FLAGS = b"flag"
    EXTENT_TYPE = b"exty"
    MEDIA_ID = b"mdid"
    OFFSET = b"offs"
    ADDRESS = b"addr"
    LOAD_TYPE = b"ldty"
    LOAD_MEDIA = b"ldmd"
    LOAD_ADDRESS = b"ldad"
    EXTENDED_HEADER = b"Iexh"
    AUTH = b"Auth"
    ITEM_SIGNATURE = b"Otis"
    ITEM_ENTRY = b"Otie"
    INDEX = b"indx"
    DATA = b"data"
    ITEM = b"Otim"
    CONTENTS = b"Otpc"


TOP_LEVEL_TAGS = {Tag.COMMENT, Tag.SIGNED_DATA, Tag.SIGNATURE}

# Only bounded metadata leaves are materialized. Container and payload
# TLVs can span hundreds of megabytes and must remain offsets into the file.
VALUE_LIMITS = {
    Tag.ALGORITHM: MAX_SALG_SIZE,
    Tag.BLOB: MAX_SIGNATURE_SIZE,
    Tag.CERTIFICATE: MAX_CERT_SIZE,
    Tag.HASH: SHA256_LEN,
    Tag.SIZE: 4,
    Tag.KEY_TYPE: MAX_KEYT_SIZE,
    Tag.IMAGE_TYPE: 16,
    Tag.INDEX: 1,
}

# DER encoding of the sha256WithRSAEncryption algorithm OID
SIGNATURE_ALGORITHM_OID = bytes.fromhex("300d06092a864886f70d01010b0500")

# Image types are GUIDs in network byte order.
IMAGE_TYPE_NAMES = {
    UUID("bff252f3-8f2f-44d4-bfc2-beb79d9e64ab"): "TZ",
    UUID("90d2f0ae-8f2f-44d4-bfc2-beb79d9e64ab"): "RPM",
    UUID("35b9f7e9-8f2f-44d4-bfc2-beb79d9e64ab"): "ABOOT",
    UUID("634d2774-8f2f-44d4-bfc2-beb79d9e64ab"): "ABL",
    UUID("ce0fe581-8f2f-44d4-bfc2-beb79d9e64ab"): "SYSTEM",
    UUID("b0cc6048-8f2f-44d4-bfc2-beb79d9e64ab"): "KERNEL",
    UUID("1f76807b-8f2f-44d4-bfc2-beb79d9e64ab"): "STUBL",
    UUID("5e42d53f-8f2f-44d4-bfc2-beb79d9e64ab"): "ROBOT",
    UUID("42c33156-8f2f-44d4-bfc2-beb79d9e64ab"): "CMNLIB",
    UUID("6e65d511-8f2f-44d4-bfc2-beb79d9e64ab"): "CMNLIB64",
    UUID("a734f68f-8f2f-44d4-bfc2-beb79d9e64ab"): "DEVCFG",
    UUID("a8ae0ded-8f2f-44d4-bfc2-beb79d9e64ab"): "KM",
    UUID("8418d52a-8f2f-44d4-bfc2-beb79d9e64ab"): "PMIC",
    UUID("8e255438-8f2f-44d4-bfc2-beb79d9e64ab"): "STORSEC",
    UUID("fe77ca68-8f2f-44d4-bfc2-beb79d9e64ab"): "UEFI_SEC",
}

# Fallback for metadata without an image type.
KEY_TYPE_NAMES = {
    "A": "TZ",
    "B": "RPM",
    "C": "ABOOT",
    "D": "SYSTEM",
    "E": "KERNEL",
    "F": "STUBL",
    "H": "CMNLIB64",
    "J": "DEVCFG",
    "K": "KM",
    "L": "PMIC",
    "M": "STORSEC",
    "N": "UEFI_SEC",
}


@dataclass(frozen=True)
class Tlv:
    tag: bytes
    value_offset: int
    end_offset: int
    value: bytes = b""

    @property
    def length(self) -> int:
        return self.end_offset - self.value_offset


def _iter_tlvs(
    file: File, start: int, end: int, *, read_values: set[Tag] | None = None
):
    """Yield parsed TLVs, keeping large values as bounded file ranges."""
    parser = StructParser(C_DEFINITIONS)
    offset = start
    count = 0
    while offset < end:
        count += 1
        if count > MAX_TLV_ELEMENTS or offset + HEADER_LEN > end:
            raise InvalidInputFormat("Malformed Otps TLV stream.")
        file.seek(offset, io.SEEK_SET)
        header = parser.parse("otps_tlv_header_t", file, Endian.LITTLE)
        value_offset = file.tell()
        value_end = value_offset + header.length
        if value_end > end:
            # Core only checks the outer chunk, not nested TLV boundaries.
            raise InvalidInputFormat("Otps TLV element exceeds its container.")
        value = b""
        if read_values and header.tag in read_values:
            if header.length > VALUE_LIMITS[header.tag]:
                raise InvalidInputFormat(f"Otps {header.tag!r} field is too large.")
            file.seek(offset, io.SEEK_SET)
            value = parser.parse("otps_tlv_t", file, Endian.LITTLE).value
        yield Tlv(header.tag, value_offset, value_end, value)
        offset = value_end


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


def _rsa_key_from_certificate(der: bytes):
    """Extract the RSA public key from a DER encoded X.509 certificate.

    The certificates inside real packages use non-canonical encodings (for
    instance a UTF8String countryName) that strict X.509 parsers reject, so
    the subjectPublicKeyInfo is located with a minimal DER walk instead.
    """
    try:
        _, cert, _ = _der_tlv(der, 0)  # Certificate
        _, tbs, _ = _der_tlv(cert, 0)  # tbsCertificate
        offset = 0
        _, _, offset = _der_tlv(tbs, offset)  # [0] version
        # serialNumber, signature, issuer, validity, subject
        for _ in range(5):
            _, _, offset = _der_tlv(tbs, offset)
        _, spki, _ = _der_tlv(tbs, offset)  # subjectPublicKeyInfo
        _, _, pos = _der_tlv(spki, 0)  # AlgorithmIdentifier
        _, bits, _ = _der_tlv(spki, pos)  # subjectPublicKey BIT STRING
        _, seq, _ = _der_tlv(bits[1:], 0)  # RSAPublicKey, skip unused-bits byte
        _, modulus, pos = _der_tlv(seq, 0)
        _, exponent, _ = _der_tlv(seq, pos)
        return rsa.RSAPublicNumbers(
            int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")
        ).public_key()
    except (IndexError, ValueError) as exc:
        raise InvalidInputFormat("Malformed Otps certificate.") from exc


def _hash_region(file: File, offset: int, size: int) -> bytes:
    file.seek(offset, io.SEEK_SET)
    hasher = hashlib.sha256()
    remaining = size
    while remaining:
        block = file.read(min(remaining, HASH_CHUNK_SIZE))
        if not block:
            break
        hasher.update(block)
        remaining -= len(block)
    return hasher.digest()


@dataclass(frozen=True)
class OtpsSignature:
    salg: bytes | None  # DER encoded signature algorithm OID
    blob: bytes


def _parse_sign(file: File, start: int, end: int) -> OtpsSignature:
    salg = blob = None
    for tlv in _iter_tlvs(file, start, end, read_values={Tag.ALGORITHM, Tag.BLOB}):
        if tlv.tag == Tag.ALGORITHM:
            salg = tlv.value
        elif tlv.tag == Tag.BLOB:
            blob = tlv.value
    if blob is None:
        raise InvalidInputFormat("Otps Sign element lacks its blob.")
    return OtpsSignature(salg=salg, blob=blob)


def _parse_auth_cert(file: File, start: int, end: int) -> bytes | None:
    for tlv in _iter_tlvs(file, start, end, read_values={Tag.CERTIFICATE}):
        if tlv.tag == Tag.CERTIFICATE:
            return tlv.value
    return None


def _parse_otis_iexh(file: File, start: int, end: int) -> dict:
    """Collect the fields we care about from an Otis item extended header."""
    fields = {}
    for tlv in _iter_tlvs(
        file, start, end, read_values={Tag.HASH, Tag.SIZE, Tag.INDEX}
    ):
        if tlv.tag == Tag.HASH:
            if tlv.length != SHA256_LEN:
                raise InvalidInputFormat("Invalid Otps item hash size.")
            fields["hash"] = tlv.value.hex()
        elif tlv.tag == Tag.SIZE:
            fields["size"] = convert_int32(tlv.value, Endian.LITTLE)
        elif tlv.tag == Tag.INDEX:
            if tlv.length != 1:
                raise InvalidInputFormat("Invalid Otps signed extent index size.")
            fields["index"] = tlv.value[0]
    return fields


def _parse_item_sdat(file: File, start: int, end: int):
    """Return (meta, certificate) of an item Sdat element's children."""
    meta: dict = {"extents": {}}
    cert = None
    for tlv in _iter_tlvs(
        file,
        start,
        end,
        read_values={Tag.IMAGE_TYPE, Tag.KEY_TYPE},
    ):
        if tlv.tag == Tag.IMAGE_TYPE:
            if tlv.length != 16:
                raise InvalidInputFormat("Invalid Otps image type GUID.")
            meta["image_type"] = UUID(bytes=tlv.value)
        elif tlv.tag == Tag.KEY_TYPE:
            keyt = tlv.value.split(b"\0", 1)[0].decode("ascii", "replace")
            # Unknown key types pass through, so keep them filesystem-safe.
            letter = keyt.rsplit(" ", 1)[-1]
            name = KEY_TYPE_NAMES.get(letter, letter)
            name = "".join(c if c.isalnum() or c in "+._-" else "_" for c in name)
            meta["name"] = name if name not in (".", "..") else ""
        elif tlv.tag == Tag.EXTENDED_HEADER:
            extent = _parse_otis_iexh(file, tlv.value_offset, tlv.end_offset)
            index = extent.get("index")
            if index is None or index in meta["extents"]:
                raise InvalidInputFormat(
                    "Missing or duplicate Otps signed extent index."
                )
            meta["extents"][index] = extent
        elif tlv.tag == Tag.AUTH:
            cert = _parse_auth_cert(file, tlv.value_offset, tlv.end_offset)
    return meta, cert


def _parse_otis(
    file: File, start: int, end: int
) -> tuple[dict, tuple[int, int], OtpsSignature, bytes | None]:
    """Return (meta, sdat_range, signature, certificate) of an Otis element."""
    meta: dict = {}
    sdat = signature = cert = None
    for tlv in _iter_tlvs(file, start, end):
        if tlv.tag == Tag.SIGNED_DATA:
            sdat = (tlv.value_offset, tlv.end_offset)
            meta, cert = _parse_item_sdat(file, *sdat)
        elif tlv.tag == Tag.SIGNATURE:
            signature = _parse_sign(file, tlv.value_offset, tlv.end_offset)
    if sdat is None or signature is None:
        raise InvalidInputFormat("Otim item lacks signed data or signature.")
    return meta, sdat, signature, cert


@dataclass(frozen=True)
class OtpsItem:
    index: int
    name: str
    payload_offset: int
    payload_size: int
    expected_sha256: str | None
    declared_size: int | None
    sdat_offset: int
    sdat_size: int
    signature: OtpsSignature
    certificate: bytes | None


def _parse_otie(file: File, start: int, end: int):
    """Return (index, payload_offset, payload_size) of an Otim's Otie element."""
    index = payload_offset = payload_size = None
    for tlv in _iter_tlvs(file, start, end, read_values={Tag.INDEX}):
        if tlv.tag == Tag.INDEX:
            if tlv.length != 1 or index is not None:
                raise InvalidInputFormat("Invalid Otie index.")
            index = tlv.value[0]
        elif tlv.tag == Tag.DATA:
            if payload_offset is not None:
                raise InvalidInputFormat("Duplicate Otie payload.")
            payload_offset = tlv.value_offset
            payload_size = tlv.length
    return index, payload_offset, payload_size


def _item_name(meta: dict, index: int, seen: set) -> str:
    """Pick a unique output name for an item.

    Deduplication is deterministic: an index suffix first, then a counter
    for pathological repeats.
    """
    image_type = meta.get("image_type")
    if image_type is not None:
        name = IMAGE_TYPE_NAMES.get(image_type, f"image-{image_type}")
    else:
        name = meta.get("name") or f"item-{index}"
    return deduplicate_name(
        name, seen, duplicate_base=f"{name}-{index}", start_suffix=2
    )


def _parse_otim(
    file: File, otim_start: int, otim_end: int, seen: set
) -> list[OtpsItem]:
    meta: dict = {}
    entries: dict[int, tuple[int, int]] = {}
    sdat = signature = cert = None
    for tlv in _iter_tlvs(file, otim_start, otim_end):
        if tlv.tag == Tag.ITEM_SIGNATURE:
            if sdat is not None:
                raise InvalidInputFormat("Duplicate Otim signature element.")
            meta, sdat, signature, cert = _parse_otis(
                file, tlv.value_offset, tlv.end_offset
            )
        elif tlv.tag == Tag.ITEM_ENTRY:
            index, offset, size = _parse_otie(file, tlv.value_offset, tlv.end_offset)
            if index is None or offset is None or size is None or index in entries:
                raise InvalidInputFormat("Missing or duplicate Otim payload entry.")
            entries[index] = (offset, size)
    if sdat is None or signature is None:
        raise InvalidInputFormat("Otim item lacks its Otis element.")
    return _match_extents(meta, entries, sdat, signature, cert, seen)


def _match_extents(
    meta: dict,
    entries: dict[int, tuple[int, int]],
    sdat: tuple[int, int],
    signature: OtpsSignature,
    cert: bytes | None,
    seen: set,
) -> list[OtpsItem]:
    extents = meta["extents"]
    if not entries or entries.keys() != extents.keys():
        raise InvalidInputFormat("Otim payload indices do not match signed extents.")
    items = []
    for index, (payload_offset, payload_size) in entries.items():
        extent = extents[index]
        declared = extent.get("size")
        if declared is not None and declared != payload_size:
            raise InvalidInputFormat(
                "Otim payload size does not match its signed metadata."
            )
        items.append(
            OtpsItem(
                index=index,
                name=_item_name(meta, index, seen),
                payload_offset=payload_offset,
                payload_size=payload_size,
                expected_sha256=extent.get("hash"),
                declared_size=declared,
                sdat_offset=sdat[0],
                sdat_size=sdat[1] - sdat[0],
                signature=signature,
                certificate=cert,
            )
        )
    return items


@dataclass(frozen=True)
class OtpsPackage:
    sdat_offset: int
    sdat_size: int
    signature: OtpsSignature
    certificate: bytes
    items: list[OtpsItem]


def _parse_items(file: File, otpc_start: int, otpc_end: int):
    items = []
    seen = set()
    for tlv in _iter_tlvs(file, otpc_start, otpc_end):
        if tlv.tag != Tag.ITEM:
            raise InvalidInputFormat("Unexpected element inside Otps Otpc.")
        items.extend(_parse_otim(file, tlv.value_offset, tlv.end_offset, seen))
    if not items:
        raise InvalidInputFormat("Otps Otpc holds no items.")
    return items


def _parse_package_sdat(file: File, start: int, end: int):
    """Return the certificate and content range."""
    cert = otpc = None
    for tlv in _iter_tlvs(file, start, end):
        if tlv.tag == Tag.AUTH:
            cert = _parse_auth_cert(file, tlv.value_offset, tlv.end_offset)
        elif tlv.tag == Tag.CONTENTS:
            otpc = (tlv.value_offset, tlv.end_offset)
    if cert is None:
        raise InvalidInputFormat("Otps Sdat block lacks the signing certificate.")
    if otpc is None:
        raise InvalidInputFormat("Otps Sdat block lacks the Otpc content.")
    return cert, otpc


def _find_package_elements(file: File, start: int, end: int):
    """Return (sdat_range, signature) of the top-level Sdat and Sign."""
    sdat = signature = None
    for tlv in _iter_tlvs(file, start, end):
        if tlv.tag not in TOP_LEVEL_TAGS:
            raise InvalidInputFormat(f"Unexpected Otps element: {tlv.tag!r}.")
        if tlv.tag == Tag.SIGNED_DATA and sdat is None:
            sdat = (tlv.value_offset, tlv.end_offset)
        elif tlv.tag == Tag.SIGNATURE and signature is None:
            signature = _parse_sign(file, tlv.value_offset, tlv.end_offset)
        elif tlv.tag in (Tag.SIGNED_DATA, Tag.SIGNATURE):
            raise InvalidInputFormat(f"Multiple {tlv.tag!r} blocks in Otps package.")
    if sdat is None:
        raise InvalidInputFormat("Otps package lacks the Sdat block.")
    if signature is None:
        raise InvalidInputFormat("Otps package lacks the Sign block.")
    return sdat, signature


def _parse_package(file: File, start: int, end: int) -> OtpsPackage:
    sdat, signature = _find_package_elements(file, start, end)

    cert, otpc = _parse_package_sdat(file, *sdat)
    items = _parse_items(file, *otpc)
    return OtpsPackage(
        sdat_offset=sdat[0],
        sdat_size=sdat[1] - sdat[0],
        signature=signature,
        certificate=cert,
        items=items,
    )


class IRobotOtpsExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("otps_header_t", file, Endian.LITTLE)
            package = _parse_package(file, HEADER_LEN, HEADER_LEN + header.total_len)
            keys: dict[bytes, rsa.RSAPublicKey] = {}
            self._verify_signature(
                fs,
                file,
                keys,
                package.certificate,
                package.signature,
                package.sdat_offset,
                package.sdat_size,
                "package",
            )
            for item in package.items:
                fs.carve(
                    Path(item.name),
                    file,
                    item.payload_offset,
                    item.payload_size,
                )
                self._verify_signature(
                    fs,
                    file,
                    keys,
                    item.certificate or package.certificate,
                    item.signature,
                    item.sdat_offset,
                    item.sdat_size,
                    item.name,
                )
                if item.expected_sha256:
                    digest = _hash_region(
                        file, item.payload_offset, item.payload_size
                    ).hex()
                    if digest != item.expected_sha256:
                        fs.record_problem(
                            ExtractionProblem(
                                problem=(f"SHA-256 mismatch for Otps item {item.name}"),
                                resolution="payload extracted anyway",
                                path=item.name,
                            )
                        )
        return ExtractResult(reports=fs.problems)

    def _verify_signature(
        self,
        fs: FileSystem,
        file: File,
        keys: dict,
        cert_der: bytes,
        signature: OtpsSignature,
        sdat_offset: int,
        sdat_size: int,
        name: str,
    ):
        if signature.salg is not None and signature.salg != SIGNATURE_ALGORITHM_OID:
            fs.record_problem(
                ExtractionProblem(
                    problem=(
                        f"Unsupported Otps signature algorithm for {name}: "
                        f"{signature.salg.hex()}"
                    ),
                    resolution="payload extracted anyway",
                    path=name if name != "package" else None,
                )
            )
            return
        key = keys.get(cert_der)
        if key is None:
            try:
                key = _rsa_key_from_certificate(cert_der)
            except InvalidInputFormat:
                fs.record_problem(
                    ExtractionProblem(
                        problem=f"Malformed Otps certificate for {name}",
                        resolution="signature not verified",
                        path=name if name != "package" else None,
                    )
                )
                return
            keys[cert_der] = key
        digest = _hash_region(file, sdat_offset, sdat_size)
        try:
            key.verify(
                signature.blob,
                digest,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
        except InvalidSignature:
            fs.record_problem(
                ExtractionProblem(
                    problem=f"Otps {name} signature verification failed",
                    resolution="payload extracted anyway",
                    path=name if name != "package" else None,
                )
            )


class IRobotOtpsHandler(StructHandler):
    NAME = "irobot_otps"

    PATTERNS = [
        HexString(
            """
            4f 74 70 73 // "Otps"
        """
        ),
    ]
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "otps_header_t"
    EXTRACTOR = IRobotOtpsExtractor()

    DOC = HandlerDoc(
        name="iRobot Otps",
        description=(
            "iRobot Otps signed OTA packages are used by Qualcomm-based "
            "robots (sapphire, soho, stingray, lewis, sanmarino, wichita). "
            "The package is a TLV stream holding a signed data block whose "
            "Otpc content lists one Otim group per component. Signed extent indices "
            "identify their corresponding payloads. Each item's "
            "payload is carved under its component name (TZ, RPM, ABOOT, "
            "SYSTEM, KERNEL, ...), verified against the SHA-256 declared in "
            "its signed metadata, and both the package and item RSA "
            "signatures are verified against the certificate embedded in "
            "the package; verification failures are reported as extraction "
            "problems."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="iRobot",
        references=[
            Reference(
                title="iRobot firmware archive Otie/Otim analysis",
                url="https://github.com/BookCatKid/irobot-firmware-archive/blob/6dee59f86f5991d18b9bd06c089277128ca8aa22/src/irobot_firmware/analyze.py",
            ),
        ],
        limitations=[
            "Signature checks use the embedded certificates; certificate "
            "trust chains and device-authorized certificate lists are not validated."
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, endian=Endian.LITTLE)
        if header.total_len < HEADER_LEN:
            raise InvalidInputFormat(f"Invalid Otps length: {header.total_len}.")

        _parse_package(
            file,
            start_offset + HEADER_LEN,
            start_offset + HEADER_LEN + header.total_len,
        )

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + HEADER_LEN + header.total_len,
        )
