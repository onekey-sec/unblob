import datetime
import hashlib
import struct
from pathlib import Path
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from unblob.file_utils import File, InvalidInputFormat, SeekError
from unblob.handlers.archive.irobot.otps import (
    MAX_CERT_SIZE,
    IRobotOtpsExtractor,
    IRobotOtpsHandler,
)
from unblob.report import ExtractionProblem

PKG_OID = bytes.fromhex("060c2b06010401838c3c04010104")
ITEM_OID = bytes.fromhex("060c2b06010401838c3c04010105")
SALG = bytes.fromhex("300d06092a864886f70d01010b0500")

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_NAME = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Otps Cert"),
    ]
)
CERT = (
    x509.CertificateBuilder()
    .subject_name(_NAME)
    .issuer_name(_NAME)
    .public_key(_KEY.public_key())
    .serial_number(1)
    .not_valid_before(datetime.datetime(2020, 1, 1))
    .not_valid_after(datetime.datetime(2040, 1, 1))
    .sign(_KEY, hashes.SHA256())
    .public_bytes(serialization.Encoding.DER)
)


def tlv(tag: bytes, value: bytes) -> bytes:
    return tag + struct.pack("<I", len(value)) + value


def sign(data: bytes) -> bytes:
    sig = _KEY.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return tlv(b"Sign", tlv(b"salg", SALG) + tlv(b"blob", sig))


def item(
    index: int,
    keyt: bytes,
    payload: bytes,
    sha: bytes | None = None,
    *,
    bad_sig: bool = False,
    image_type: bytes | None = None,
) -> bytes:
    if sha is None:
        sha = hashlib.sha256(payload).digest()
    iexh = (
        tlv(b"indx", bytes([index]))
        + tlv(b"size", struct.pack("<I", len(payload)))
        + tlv(b"hash", sha)
        + tlv(b"cmnt", keyt.lower() + b"\0")
    )
    sdat = (
        tlv(b"cnid", ITEM_OID)
        + tlv(b"salg", SALG)
        + tlv(b"Auth", tlv(b"cert", CERT))
        + (tlv(b"type", image_type) if image_type is not None else b"")
        + tlv(b"keyt", b"key type " + keyt + b"\0")
        + tlv(b"Iexh", iexh)
    )
    # sign other data to produce a valid-looking but wrong signature
    otis = tlv(b"Sdat", sdat) + sign(b"not the sdat" if bad_sig else sdat)
    otie = tlv(b"indx", bytes([index])) + tlv(b"data", payload)
    return tlv(b"Otim", tlv(b"Otis", otis) + tlv(b"Otie", otie))


def otps(
    items: list[bytes],
    trailer: bytes = b"",
    *,
    do_sign: bool = True,
    cert: bytes = CERT,
) -> bytes:
    otpc = tlv(b"Otpc", b"".join(items))
    sdat = (
        tlv(b"cnid", PKG_OID)
        + tlv(b"salg", SALG)
        + tlv(b"Auth", tlv(b"cert", cert))
        + otpc
    )
    body = (
        tlv(b"cmnt", b"Generated with otagen v2.0\0")
        + tlv(b"Sdat", sdat)
        + (
            sign(sdat)
            if do_sign
            else tlv(b"Sign", tlv(b"salg", SALG) + tlv(b"blob", b"\xbb" * 256))
        )
    )
    return b"Otps" + struct.pack("<I", len(body)) + body + trailer


PAYLOAD_TZ = b"\x7fELF" + b"t" * 100
PAYLOAD_RPM = b"\x7fELF" + b"r" * 200

handler = IRobotOtpsHandler()


def _chunk(blob: bytes, start_offset: int = 0):
    file = File.from_bytes(blob)
    file.seek(start_offset)
    chunk = handler.calculate_chunk(file, start_offset)
    assert chunk is not None
    return chunk


def test_chunk_covers_declared_length():
    blob = otps([item(0, b"A", PAYLOAD_TZ), item(1, b"B", PAYLOAD_RPM)])
    chunk = _chunk(blob)
    total = struct.unpack_from("<I", blob[4:8])[0]
    assert chunk.start_offset == 0
    assert chunk.end_offset == 8 + total == len(blob)


def test_packet_info_trailer_is_outside_chunk():
    trailer = b"\x00__PACKET INFO__\nOS_VERSION=linux\n" + b"\0" * 100
    blob = otps([item(0, b"A", PAYLOAD_TZ)], trailer)
    chunk = _chunk(blob)
    assert chunk.end_offset == len(blob) - len(trailer)


def test_embedded_chunk():
    blob = otps([item(0, b"A", PAYLOAD_TZ)])
    prefix = b"\xde\xad" * 32
    chunk = _chunk(prefix + blob, len(prefix))
    assert chunk.start_offset == len(prefix)
    assert chunk.end_offset == len(prefix) + len(blob)


def test_extract(tmp_path: Path):
    blob = otps([item(0, b"A", PAYLOAD_TZ), item(1, b"B", PAYLOAD_RPM)])
    inpath = tmp_path / "in.irobot_otps"
    inpath.write_bytes(blob)
    result = IRobotOtpsExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "TZ").read_bytes() == PAYLOAD_TZ
    assert (tmp_path / "RPM").read_bytes() == PAYLOAD_RPM
    # valid package and item signatures produce no problems
    assert result.reports == []


def test_extract_records_hash_mismatch(tmp_path: Path):
    bad_sha = b"\x00" * 32
    blob = otps([item(0, b"A", PAYLOAD_TZ, sha=bad_sha)])
    inpath = tmp_path / "in.irobot_otps"
    inpath.write_bytes(blob)
    result = IRobotOtpsExtractor().extract(inpath, tmp_path)
    # payload is still carved
    assert (tmp_path / "TZ").read_bytes() == PAYLOAD_TZ
    problems = [p for p in result.reports if isinstance(p, ExtractionProblem)]
    assert len(problems) == 1
    assert "SHA-256 mismatch" in problems[0].problem


def test_extract_records_signature_mismatch(tmp_path: Path):
    # the item signature does not match its Sdat; the package signature
    # still covers the final bytes and verifies
    blob = otps([item(0, b"A", PAYLOAD_TZ, bad_sig=True)])
    inpath = tmp_path / "in.irobot_otps"
    inpath.write_bytes(blob)
    result = IRobotOtpsExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "TZ").read_bytes() == PAYLOAD_TZ
    problems = [p for p in result.reports if isinstance(p, ExtractionProblem)]
    assert len(problems) == 1
    assert "TZ signature verification failed" in problems[0].problem


def test_extract_records_package_signature_mismatch(tmp_path: Path):
    # do_sign writes a garbage signature blob instead of signing the Sdat
    blob = otps([item(0, b"A", PAYLOAD_TZ)], do_sign=False)
    inpath = tmp_path / "in.irobot_otps"
    inpath.write_bytes(blob)
    result = IRobotOtpsExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "TZ").read_bytes() == PAYLOAD_TZ
    problems = [p for p in result.reports if isinstance(p, ExtractionProblem)]
    assert len(problems) == 1
    assert "package signature verification failed" in problems[0].problem


def test_extract_unknown_key_type(tmp_path: Path):
    blob = otps([item(0, b"Z", PAYLOAD_TZ)])
    inpath = tmp_path / "in.irobot_otps"
    inpath.write_bytes(blob)
    IRobotOtpsExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "Z").read_bytes() == PAYLOAD_TZ


def _retag(blob: bytes, tag: bytes, new_tag: bytes, *, last=False) -> bytes:
    """Rename the first (or last) occurrence of a TLV tag."""
    idx = (blob.rfind if last else blob.find)(tag)
    return blob[:idx] + new_tag + blob[idx + 4 :]


def _declare_len(blob: bytes, tag: bytes, length: int, *, last=False) -> bytes:
    """Lie about an element's declared length."""
    idx = (blob.rfind if last else blob.find)(tag)
    return blob[: idx + 4] + struct.pack("<I", length) + blob[idx + 8 :]


def _set_u32(blob: bytes, tag: bytes, value: int) -> bytes:
    """Overwrite the u32 value of a 4-byte element."""
    idx = blob.find(tag)
    return blob[: idx + 8] + struct.pack("<I", value) + blob[idx + 12 :]


@pytest.mark.parametrize(
    "mutate",
    [
        # total_len too small
        lambda b: b[:4] + struct.pack("<I", 4) + b[8:],
        # unknown top-level tag
        lambda b: b[:8] + b"junk" + b[12:],
        # no Sdat block
        lambda b: _retag(b, b"Sdat", b"cmnt"),
        # Otim missing Otie
        lambda b: _retag(b, b"Otie", b"jUnk"),
        # declared item size mismatch vs data length
        lambda b: _set_u32(b, b"size", 999),
        # a second Sdat block inside the package
        lambda b: _retag(b, b"Sign", b"Sdat", last=True),
        # package missing the Sign block
        lambda b: _retag(b, b"Sign", b"jUnk", last=True),
        # signed extent index disagrees with the payload index
        lambda b: b[: b.rfind(b"indx") + 8] + b"\x01" + b[b.rfind(b"indx") + 9 :],
        # package missing the signing certificate
        lambda b: _retag(b, b"cert", b"xxxx"),
        # item missing its Sign element
        lambda b: _retag(b, b"Sign", b"jUnk"),
        # Iexh size field declared with 8 bytes instead of 4
        lambda b: _declare_len(b, b"size", 8),
        # Iexh hash field declared with 16 bytes instead of 32
        lambda b: _declare_len(b, b"hash", 16),
        # Otie index declared with 0 or 5 bytes
        lambda b: _declare_len(b, b"indx", 0, last=True),
        lambda b: _declare_len(b, b"indx", 5, last=True),
    ],
)
def test_invalid(mutate):
    blob = bytes(mutate(bytearray(otps([item(0, b"A", PAYLOAD_TZ)]))))
    file = File.from_bytes(blob)
    file.seek(0)
    with pytest.raises(InvalidInputFormat):
        handler.calculate_chunk(file, 0)


def test_oversized_certificate_rejected():
    # the declared cert length fits the TLV bounds but exceeds the bound
    # for values read into memory
    blob = otps([item(0, b"A", PAYLOAD_TZ)], cert=b"\x30" * (MAX_CERT_SIZE + 1))
    file = File.from_bytes(blob)
    file.seek(0)
    with pytest.raises(InvalidInputFormat):
        handler.calculate_chunk(file, 0)


def test_truncated():
    blob = otps([item(0, b"A", PAYLOAD_TZ)])
    file = File.from_bytes(blob[:0x40])
    file.seek(0)
    # truncated reads surface as SeekError/EOFError, which unblob treats
    # like InvalidInputFormat
    with pytest.raises((InvalidInputFormat, EOFError, SeekError)):
        handler.calculate_chunk(file, 0)


@pytest.mark.parametrize(
    "image_type, name",
    [
        ("5e42d53f-8f2f-44d4-bfc2-beb79d9e64ab", "ROBOT"),
        ("42c33156-8f2f-44d4-bfc2-beb79d9e64ab", "CMNLIB"),
        ("634d2774-8f2f-44d4-bfc2-beb79d9e64ab", "ABL"),
        (
            "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "image-aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        ),
    ],
)
def test_image_type_controls_name(tmp_path: Path, image_type: str, name: str):
    blob = otps([item(0, b"G", PAYLOAD_TZ, image_type=UUID(image_type).bytes)])
    inpath = tmp_path / "in.irobot_otps"
    inpath.write_bytes(blob)
    result = IRobotOtpsExtractor().extract(inpath, tmp_path)
    assert (tmp_path / name).read_bytes() == PAYLOAD_TZ
    assert not result.reports


def test_invalid_image_type_guid():
    blob = otps([item(0, b"G", PAYLOAD_TZ, image_type=b"short")])
    with pytest.raises(InvalidInputFormat):
        _chunk(blob)


def test_multiple_extents_matched_by_index(tmp_path: Path):
    extents = b"".join(
        tlv(
            b"Iexh",
            tlv(b"indx", bytes([index]))
            + tlv(b"size", struct.pack("<I", len(payload)))
            + tlv(b"hash", hashlib.sha256(payload).digest()),
        )
        for index, payload in [(3, PAYLOAD_TZ), (5, PAYLOAD_RPM)]
    )
    sdat = (
        tlv(b"cnid", ITEM_OID)
        + tlv(b"salg", SALG)
        + tlv(b"keyt", b"key type A\0")
        + tlv(b"Auth", tlv(b"cert", CERT))
        + extents
    )
    otis = tlv(b"Otis", tlv(b"Sdat", sdat) + sign(sdat))
    entries = b"".join(
        tlv(b"Otie", tlv(b"indx", bytes([index])) + tlv(b"data", payload))
        for index, payload in [(5, PAYLOAD_RPM), (3, PAYLOAD_TZ)]
    )
    path = tmp_path / "multi.otps"
    path.write_bytes(otps([tlv(b"Otim", otis + entries)]))
    result = IRobotOtpsExtractor().extract(path, tmp_path)
    assert not result.reports
    assert (tmp_path / "TZ").read_bytes() == PAYLOAD_RPM
    assert (tmp_path / "TZ-3").read_bytes() == PAYLOAD_TZ
