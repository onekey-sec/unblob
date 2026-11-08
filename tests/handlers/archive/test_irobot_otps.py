import datetime
import hashlib
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from unblob.file_utils import File, InvalidInputFormat, SeekError
from unblob.handlers.archive.irobot.otps import IRobotOtpsExtractor, IRobotOtpsHandler
from unblob.report import ExtractionProblem

OID = bytes.fromhex("060c2b06010401838c3c04010105")
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
        tlv(b"cnid", OID)
        + tlv(b"salg", SALG)
        + tlv(b"Auth", tlv(b"cert", CERT))
        + tlv(b"keyt", b"key type " + keyt + b"\0")
        + tlv(b"Iexh", iexh)
    )
    # sign other data to produce a valid-looking but wrong signature
    otis = tlv(b"Sdat", sdat) + sign(b"not the sdat" if bad_sig else sdat)
    otie = tlv(b"indx", bytes([index])) + tlv(b"data", payload)
    return tlv(b"Otim", tlv(b"Otis", otis) + tlv(b"Otie", otie))


def otps(items: list[bytes], trailer: bytes = b"", *, do_sign: bool = True) -> bytes:
    otpc = tlv(b"Otpc", b"".join(items))
    sdat = (
        tlv(b"cnid", OID) + tlv(b"salg", SALG) + tlv(b"Auth", tlv(b"cert", CERT)) + otpc
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
    trailer = b"\x00__PACKET_INFO__\nOS_VERSION=linux\n" + b"\0" * 100
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


@pytest.mark.parametrize(
    "mutate",
    [
        # total_len too small
        lambda b: b[:4] + struct.pack("<I", 4) + b[8:],
        # unknown top-level tag
        lambda b: b[:8] + b"junk" + b[12:],
        # no Sdat block
        lambda b: otps_rebuild(b, drop_sdat=True),
        # Otim missing Otie
        lambda b: otps_rebuild(b, drop_otie=True),
        # declared item size mismatch vs data length
        lambda b: otps_rebuild(b, size_lie=True),
        # a second Sdat block inside the package
        lambda b: otps_rebuild(b, dup_sdat=True),
        # package missing the Sign block
        lambda b: otps_rebuild(b, drop_sign=True),
        # package missing the signing certificate
        lambda b: otps_rebuild(b, drop_cert=True),
        # item missing its Sign element
        lambda b: otps_rebuild(b, drop_item_sign=True),
    ],
)
def test_invalid(mutate):
    blob = bytes(mutate(bytearray(otps([item(0, b"A", PAYLOAD_TZ)]))))
    file = File.from_bytes(blob)
    file.seek(0)
    with pytest.raises(InvalidInputFormat):
        handler.calculate_chunk(file, 0)


def otps_rebuild(
    blob: bytes,
    *,
    drop_sdat=False,
    drop_otie=False,
    size_lie=False,
    dup_sdat=False,
    drop_sign=False,
    drop_cert=False,
    drop_item_sign=False,
) -> bytes:
    """Rebuild small invalid variants."""
    if drop_sdat:
        # replace 'Sdat' tag of the top-level element with 'cmnt'
        idx = blob.find(b"Sdat", 8)
        return blob[:idx] + b"cmnt" + blob[idx + 4 :]
    if drop_otie:
        idx = blob.find(b"Otie")
        return blob[:idx] + b"jUnk" + blob[idx + 4 :]
    if size_lie:
        idx = blob.find(b"size")
        return (
            blob[: idx + 4]
            + struct.pack("<I", 4)
            + struct.pack("<I", 999)
            + blob[idx + 16 :]
        )
    if dup_sdat:
        # turn the trailing Sign element into a second Sdat
        idx = blob.rfind(b"Sign")
        return blob[:idx] + b"Sdat" + blob[idx + 4 :]
    if drop_sign:
        idx = blob.rfind(b"Sign")
        return blob[:idx] + b"jUnk" + blob[idx + 4 :]
    if drop_cert:
        idx = blob.find(b"cert")
        return blob[:idx] + b"xxxx" + blob[idx + 4 :]
    if drop_item_sign:
        # the first Sign element belongs to the item's Otis
        idx = blob.find(b"Sign")
        return blob[:idx] + b"jUnk" + blob[idx + 4 :]
    return blob


def test_truncated():
    blob = otps([item(0, b"A", PAYLOAD_TZ)])
    file = File.from_bytes(blob[:0x40])
    file.seek(0)
    # truncated reads surface as SeekError/EOFError, which unblob treats
    # like InvalidInputFormat
    with pytest.raises((InvalidInputFormat, EOFError, SeekError)):
        handler.calculate_chunk(file, 0)
