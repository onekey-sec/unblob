import hashlib
import struct
from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat, SeekError
from unblob.handlers.archive.irobot.otps import IRobotOtpsExtractor, IRobotOtpsHandler
from unblob.report import ExtractionProblem

CERT = b"\x30\x82" + b"\x01" * 100
OID = bytes.fromhex("060c2b06010401838c3c04010105")
SALG = bytes.fromhex("300d06092a864886f70d01010b0500")


def tlv(tag: bytes, value: bytes) -> bytes:
    return tag + struct.pack("<I", len(value)) + value


def item(index: int, keyt: bytes, payload: bytes, sha: bytes | None = None) -> bytes:
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
    otis = tlv(b"Sdat", sdat) + b"\xaa" * 551  # signature tail
    otie = tlv(b"indx", bytes([index])) + tlv(b"data", payload)
    return tlv(b"Otim", tlv(b"Otis", otis) + tlv(b"Otie", otie))


def otps(items: list[bytes], trailer: bytes = b"") -> bytes:
    otpc = tlv(b"Otpc", b"".join(items))
    sdat = (
        tlv(b"cnid", OID) + tlv(b"salg", SALG) + tlv(b"Auth", tlv(b"cert", CERT)) + otpc
    )
    body = (
        tlv(b"cmnt", b"Generated with otagen v2.0\0")
        + tlv(b"Sdat", sdat)
        + tlv(b"Sign", b"\xbb" * 512)
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
    IRobotOtpsExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "TZ").read_bytes() == PAYLOAD_TZ
    assert (tmp_path / "RPM").read_bytes() == PAYLOAD_RPM


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
    ],
)
def test_invalid(mutate):
    blob = bytes(mutate(bytearray(otps([item(0, b"A", PAYLOAD_TZ)]))))
    file = File.from_bytes(blob)
    file.seek(0)
    with pytest.raises(InvalidInputFormat):
        handler.calculate_chunk(file, 0)


def otps_rebuild(
    blob: bytes, *, drop_sdat=False, drop_otie=False, size_lie=False, dup_sdat=False
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
    return blob


def test_truncated():
    blob = otps([item(0, b"A", PAYLOAD_TZ)])
    file = File.from_bytes(blob[:0x40])
    file.seek(0)
    # truncated reads surface as SeekError/EOFError, which unblob treats
    # like InvalidInputFormat
    with pytest.raises((InvalidInputFormat, EOFError, SeekError)):
        handler.calculate_chunk(file, 0)
