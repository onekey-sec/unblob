"""iRobot Otps firmware container.

Otps is the signed OTA package format used by the Qualcomm-based iRobot
generations (sapphire, soho, stingray, lewis, sanmarino, wichita), produced by
iRobot's ``otagen`` tool.

The whole file is a little-endian TLV stream where every element is a
4-byte tag, a uint32 length and a value:

    | Otps | total_len | cmnt* | Sdat | Sign |

Inside ``Sdat``:

    | cnid | salg | Auth{cert} | Otpc |

``Otpc`` holds one ``Otim`` group per flashed component. Each ``Otim`` wraps
an ``Otis`` (the item's signed data: an ``Sdat`` metadata block and a
``Sign`` element) and an ``Otie`` (the item entry: ``indx`` + ``data``
payload). The item metadata carries the component's ``keyt`` letter (A..N,
mapped to TZ, RPM, ABOOT, SYSTEM, KERNEL, ...), a ``size`` and a SHA-256
``hash`` of the payload.

``Sign`` elements are ``{salg, blob}`` pairs: ``salg`` is the DER encoded
sha256WithRSAEncryption OID and ``blob`` a 512-byte RSA-4096 signature over
the preceding ``Sdat`` element's value (the package signature covers the
whole package ``Sdat``; each item signature covers the item's ``Sdat``).
Signatures are verified during extraction against the RSA key of the
embedded ``cert`` certificate; the certificate uses non-canonical encodings
rejected by strict X.509 parsers, so its public key is extracted with a
minimal DER walk instead.

The chunk ends at the declared ``total_len``; a small ``__PACKET INFO__``
text footer can follow the package (wichita) and is left to the generic
handling.

Format reference: https://github.com/BookCatKid/irobot-firmware-archive
"""

import hashlib
import io
from dataclasses import dataclass
from pathlib import Path

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
"""

HEADER_LEN = 8
MAX_TLV_ELEMENTS = 512
HASH_CHUNK_SIZE = 1024 * 1024

# top-level tags observed across the preserved package catalog
TOP_LEVEL_TAGS = {b"cmnt", b"Sdat", b"Sign"}

# DER encoding of the sha256WithRSAEncryption algorithm OID
SIGNATURE_ALGORITHM_OID = bytes.fromhex("300d06092a864886f70d01010b0500")

# "key type X" letters found in Otis metadata, mapped to component names.
KEY_TYPE_NAMES = {
    "A": "TZ",
    "B": "RPM",
    "C": "ABOOT",
    "D": "SYSTEM",
    "E": "KERNEL",
    "F": "STUBL",
    "G": "CMNLIB",
    "H": "CMNLIB64",
    "J": "DEVCFG",
    "K": "KM",
    "L": "PMIC",
    "M": "STORSEC",
    "N": "UEFI_SEC",
}


def _iter_tlvs(file: File, start: int, end: int):
    """Yield (tag, value_offset, next_offset) for each TLV in [start, end)."""
    offset = start
    count = 0
    while offset < end:
        count += 1
        if count > MAX_TLV_ELEMENTS or offset + 8 > end:
            raise InvalidInputFormat("Malformed Otps TLV stream.")
        file.seek(offset, io.SEEK_SET)
        raw = file.read(8)
        tag, length = raw[:4], int.from_bytes(raw[4:], "little")
        value_end = offset + 8 + length
        if value_end > end:
            raise InvalidInputFormat("Otps TLV element exceeds its container.")
        yield tag, offset + 8, value_end
        offset = value_end


def _read_u32(file: File, offset: int) -> int:
    file.seek(offset, io.SEEK_SET)
    return int.from_bytes(file.read(4), "little")


def _read_bytes(file: File, offset: int, size: int) -> bytes:
    file.seek(offset, io.SEEK_SET)
    return file.read(size)


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
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag == b"salg":
            salg = _read_bytes(file, value, next_offset - value)
        elif tag == b"blob":
            blob = _read_bytes(file, value, next_offset - value)
    if blob is None:
        raise InvalidInputFormat("Otps Sign element lacks its blob.")
    return OtpsSignature(salg=salg, blob=blob)


def _parse_auth_cert(file: File, start: int, end: int) -> bytes | None:
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag == b"cert":
            return _read_bytes(file, value, next_offset - value)
    return None


def _parse_otis_iexh(file: File, start: int, end: int) -> dict:
    """Collect the fields we care about from an Otis item extended header."""
    fields = {}
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag == b"hash":
            fields["hash"] = _read_bytes(file, value, next_offset - value).hex()
        elif tag == b"size":
            fields["size"] = _read_u32(file, value)
        elif tag == b"cmnt":
            fields["cmnt"] = (
                _read_bytes(file, value, next_offset - value)
                .split(b"\0", 1)[0]
                .decode("ascii", "replace")
            )
    return fields


def _parse_item_sdat(file: File, start: int, end: int):
    """Return (meta, certificate) of an item Sdat element's children."""
    meta: dict = {}
    cert = None
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag == b"keyt":
            keyt = (
                _read_bytes(file, value, next_offset - value)
                .split(b"\0", 1)[0]
                .decode("ascii", "replace")
            )
            # observed values look like "key type J"; an unknown letter
            # passes through, so keep it filesystem-safe
            letter = keyt.rsplit(" ", 1)[-1]
            name = KEY_TYPE_NAMES.get(letter, letter)
            name = "".join(c if c.isalnum() or c in "+._-" else "_" for c in name)
            meta["name"] = name if name not in (".", "..") else ""
        elif tag == b"Iexh":
            meta.update(_parse_otis_iexh(file, value, next_offset))
        elif tag == b"Auth":
            cert = _parse_auth_cert(file, value, next_offset)
    return meta, cert


def _parse_otis(
    file: File, start: int, end: int
) -> tuple[dict, tuple[int, int], OtpsSignature, bytes | None]:
    """Return (meta, sdat_range, signature, certificate) of an Otis element."""
    meta: dict = {}
    sdat = signature = cert = None
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag == b"Sdat":
            sdat = (value, next_offset)
            meta, cert = _parse_item_sdat(file, value, next_offset)
        elif tag == b"Sign":
            signature = _parse_sign(file, value, next_offset)
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
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag == b"indx":
            if next_offset - value > 4:
                raise InvalidInputFormat("Invalid Otie index size.")
            index = int.from_bytes(
                _read_bytes(file, value, next_offset - value), "little"
            )
        elif tag == b"data":
            payload_offset = value
            payload_size = next_offset - value
    return index, payload_offset, payload_size


def _item_name(meta: dict, index: int, seen: set) -> str:
    """Pick a unique output name for an item.

    Deduplication is deterministic: an index suffix first, then a counter
    for pathological repeats.
    """
    name = meta.get("name") or f"item-{index}"
    if name in seen:
        base = f"{name}-{index}"
        name = base
        suffix = 1
        while name in seen:
            suffix += 1
            name = f"{base}-{suffix}"
    seen.add(name)
    return name


def _parse_otim(file: File, otim_start: int, otim_end: int, seen: set) -> OtpsItem:
    meta: dict = {}
    index = payload_offset = payload_size = None
    sdat = signature = cert = None
    for tag, value, next_offset in _iter_tlvs(file, otim_start, otim_end):
        if tag == b"Otis":
            meta, sdat, signature, cert = _parse_otis(file, value, next_offset)
        elif tag == b"Otie":
            index, payload_offset, payload_size = _parse_otie(file, value, next_offset)
    if sdat is None or signature is None:
        raise InvalidInputFormat("Otim item lacks its Otis element.")
    if index is None or payload_offset is None or payload_size is None:
        raise InvalidInputFormat("Otim item lacks index or payload.")
    declared = meta.get("size")
    if declared is not None and declared != payload_size:
        raise InvalidInputFormat(
            "Otim payload size does not match its signed metadata."
        )
    name = _item_name(meta, index, seen)
    return OtpsItem(
        index=index,
        name=name,
        payload_offset=payload_offset,
        payload_size=payload_size,
        expected_sha256=meta.get("hash"),
        declared_size=declared,
        sdat_offset=sdat[0],
        sdat_size=sdat[1] - sdat[0],
        signature=signature,
        certificate=cert,
    )


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
    for tag, otim_start, otim_end in _iter_tlvs(file, otpc_start, otpc_end):
        if tag != b"Otim":
            raise InvalidInputFormat("Unexpected element inside Otps Otpc.")
        items.append(_parse_otim(file, otim_start, otim_end, seen))
    if not items:
        raise InvalidInputFormat("Otps Otpc holds no items.")
    return items


def _parse_package_sdat(file: File, start: int, end: int):
    """Return (certificate, otpc_range) of the package Sdat's children."""
    cert = otpc = None
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag == b"Auth":
            cert = _parse_auth_cert(file, value, next_offset)
        elif tag == b"Otpc":
            otpc = (value, next_offset)
    if cert is None:
        raise InvalidInputFormat("Otps Sdat block lacks the signing certificate.")
    if otpc is None:
        raise InvalidInputFormat("Otps Sdat block lacks the Otpc content.")
    return cert, otpc


def _find_package_elements(file: File, start: int, end: int):
    """Return (sdat_range, signature) of the top-level Sdat and Sign."""
    sdat = signature = None
    for tag, value, next_offset in _iter_tlvs(file, start, end):
        if tag not in TOP_LEVEL_TAGS:
            raise InvalidInputFormat(f"Unexpected Otps element: {tag!r}.")
        if tag == b"Sdat" and sdat is None:
            sdat = (value, next_offset)
        elif tag == b"Sign" and signature is None:
            signature = _parse_sign(file, value, next_offset)
        elif tag in (b"Sdat", b"Sign"):
            raise InvalidInputFormat(f"Multiple {tag!r} blocks in Otps package.")
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
            "Otpc content lists one Otim group per component. Each item's "
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
        limitations=[],
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
