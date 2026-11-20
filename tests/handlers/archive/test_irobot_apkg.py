import gzip
import hashlib
import re
import struct
import zlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import unblob.handlers.archive.irobot.apkg as apkg_module
from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.irobot.apkg import IRobotApkgExtractor, IRobotApkgHandler
from unblob.report import ExtractionProblem

SIGNATURE_TRAILER = b"\xcc" * 256

# test signing key; the handler's embedded Prod key is swapped for it via
# the prod_key fixture
_PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_NUMBERS = _PRIV.private_numbers()
_TEST_N, _TEST_D = _NUMBERS.public_numbers.n, _NUMBERS.d


@pytest.fixture
def prod_key(monkeypatch):
    monkeypatch.setattr(apkg_module, "_PROD_N", _TEST_N)
    monkeypatch.setattr(apkg_module, "_PROD_E", _NUMBERS.public_numbers.e)


def _rsa_sign(digest: bytes) -> bytes:
    # PKCS#1 v1.5 block carrying the raw 32-byte digest, no DigestInfo
    block = b"\x00\x01" + b"\xff" * (256 - 3 - 32) + b"\x00" + digest
    return pow(int.from_bytes(block, "big"), _TEST_D, _TEST_N).to_bytes(256, "big")


def _trailer(body: bytes, signed: bool) -> bytes:
    if not signed:
        return SIGNATURE_TRAILER
    return _rsa_sign(hashlib.sha256(body).digest())


def header(data_end: int, name: bytes = b"test-pkg") -> bytes:
    return (
        b"aPKG" + struct.pack("<III", 1, data_end - 0x30, 0x100) + name.ljust(32, b"\0")
    )


def entry_table_pkg(entries, *, signed=False) -> bytes:
    """Build an entry-table variant package.

    entries: list of (id, label, payload); entries at 0x400-aligned
    offsets, data_end right after the last payload.
    """
    table = struct.pack("<I", len(entries))
    offset = 0x400
    parts = []
    for entry_id, label, payload in entries:
        table += struct.pack("<III", entry_id, offset, len(payload)) + label.ljust(
            76, b"\0"
        )
        parts.append((offset, payload))
        offset += -(-len(payload) // 0x400) * 0x400
    data_end = parts[-1][0] + len(parts[-1][1])
    blob = header(data_end) + table.ljust(4 + 10 * 88, b"\0") + b"FWPK"
    for off, payload in parts:
        blob = blob.ljust(off, b"\0") + payload
    return blob + _trailer(blob, signed)


def sequential_pkg(entries, last_overshoot: int = 0, *, signed=False) -> bytes:
    """Build a sequential-table variant package.

    The first declared size includes the eight-byte block header.
    """
    count = len(entries)
    payload_offset = 0x54 + count * 12 + 8
    data_end = payload_offset + sum(len(p) for _, _, p in entries) + 4
    head = (
        header(data_end)
        + struct.pack("<I", data_end - 0x30)
        + struct.pack("<I", 0x0B03)
        + b"\0" * 16
        + struct.pack("<I", 0x14020811)
        + struct.pack("<I", 18)
        + struct.pack("<I", count)
    )
    for i, (entry_id, field, payload) in enumerate(entries):
        declared = len(payload) + (8 if i == 0 else 0)
        declared += last_overshoot if i == count - 1 else 0
        head += struct.pack("<III", entry_id, field, declared)
    head += struct.pack("<II", len(entries[0][2]) + 8, 0x0B03)
    body = head + b"".join(p for _, _, p in entries)
    body += struct.pack("<I", zlib.crc32(body[0x48:]))
    return body + _trailer(body, signed)


def sigmastar_pkg(payload: bytes, name: bytes = b"C3_test", *, signed=False) -> bytes:
    member = gzip.compress(payload, mtime=0)
    # the post-member region starts with the ASCII hex MD5 of the member
    post = (
        hashlib.md5(member, usedforsecurity=False)
        .hexdigest()
        .encode()
        .ljust(512, b"\0")
    )
    post += b"TESTSKU".ljust(512, b"\0")
    data_end = 0x30 + len(member) + len(post)
    body = header(data_end, name) + member + post
    return body + _trailer(body, signed)


handler = IRobotApkgHandler()


def _chunk(blob: bytes, start_offset: int = 0):
    file = File.from_bytes(blob)
    file.seek(start_offset)
    chunk = handler.calculate_chunk(file, start_offset)
    assert chunk is not None
    return chunk


def test_entry_table_chunk_unsigned_trailer_stays_outside():
    blob = entry_table_pkg(
        [
            (1, b"version1", b"A" * 100),
            (2, b"version2", b"B" * 200),
            (3, b"version2", b"C" * 50),
        ]
    )
    chunk = _chunk(blob)
    data_end = 0x30 + struct.unpack_from("<I", blob[8:12])[0]
    assert chunk.start_offset == 0
    assert chunk.end_offset == data_end == len(blob) - len(SIGNATURE_TRAILER)


@pytest.mark.usefixtures("prod_key")
def test_signed_chunk_covers_trailer():
    blob = entry_table_pkg([(1, b"version1", b"A" * 100)], signed=True)
    chunk = _chunk(blob)
    assert chunk.start_offset == 0
    assert chunk.end_offset == len(blob)


@pytest.mark.usefixtures("prod_key")
def test_signed_chunk_embedded_at_nonzero_offset():
    blob = entry_table_pkg([(1, b"version1", b"A" * 100)], signed=True)
    prefix = b"\xde\xad" * 16
    chunk = _chunk(prefix + blob, len(prefix))
    assert chunk.start_offset == len(prefix)
    assert chunk.end_offset == len(prefix) + len(blob)


def test_entry_table_extract(tmp_path: Path):
    p1, p2, p3 = b"A" * 100, b"B" * 200, b"C" * 50
    blob = entry_table_pkg(
        [(1, b"version1", p1), (2, b"version2", p2), (3, b"version2", p3)]
    )
    data_end = 0x30 + struct.unpack_from("<I", blob[8:12])[0]
    inpath = tmp_path / "in.irobot_apkg"
    inpath.write_bytes(blob[:data_end])
    result = IRobotApkgExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "version1").read_bytes() == p1
    assert (tmp_path / "version2").read_bytes() == p2
    # duplicated labels are disambiguated
    assert (tmp_path / "version2-1").read_bytes() == p3
    # the fake trailer is not an iRobot signature
    problems = [p for p in result.reports if isinstance(p, ExtractionProblem)]
    assert len(problems) == 1
    assert "signature trailer" in problems[0].problem


@pytest.mark.usefixtures("prod_key")
def test_signed_extract_reports_nothing(tmp_path: Path):
    blob = entry_table_pkg(
        [(1, b"version1", b"A" * 100), (2, b"version2", b"B" * 200)], signed=True
    )
    inpath = tmp_path / "in.irobot_apkg"
    inpath.write_bytes(blob)
    result = IRobotApkgExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "version1").read_bytes() == b"A" * 100
    assert result.reports == []


@pytest.mark.usefixtures("prod_key")
def test_signature_mismatch_records_problem(tmp_path: Path):
    blob = bytearray(entry_table_pkg([(1, b"version1", b"A" * 100)], signed=True))
    blob[0x400] = ord("Z")  # corrupt a payload byte inside the signed range
    inpath = tmp_path / "in.irobot_apkg"
    inpath.write_bytes(bytes(blob))
    result = IRobotApkgExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "version1").read_bytes() == b"Z" + b"A" * 99
    problems = [p for p in result.reports if isinstance(p, ExtractionProblem)]
    assert len(problems) == 1
    assert "signature verification failed" in problems[0].problem


def test_sequential_chunk_and_extract(tmp_path: Path):
    entries = [
        (1, 0x40200, b"P" * 0x100),
        (3, 0x40300, b"Q" * 0x80),
        (2, 0x40400, b"R" * 0x40),
        (5, 0xF0001, b"S" * 0x200),
    ]
    blob = sequential_pkg(entries)
    chunk = _chunk(blob)
    data_end = 0x30 + struct.unpack_from("<I", blob[8:12])[0]
    assert chunk.start_offset == 0
    assert chunk.end_offset == data_end

    inpath = tmp_path / "in.irobot_apkg"
    inpath.write_bytes(blob[:data_end])
    IRobotApkgExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "entry-1").read_bytes() == b"P" * 0x100
    assert (tmp_path / "entry-3").read_bytes() == b"Q" * 0x80
    assert (tmp_path / "entry-2").read_bytes() == b"R" * 0x40
    assert (tmp_path / "entry-5").read_bytes() == b"S" * 0x200


@pytest.mark.usefixtures("prod_key")
def test_sigmastar_chunk_and_extract(tmp_path: Path):
    payload = b"#!/bin/sh\necho update\n" + b"\x00" * 100
    blob = sigmastar_pkg(payload, signed=True)
    chunk = _chunk(blob)
    assert chunk.end_offset == len(blob)

    inpath = tmp_path / "in.irobot_apkg"
    inpath.write_bytes(blob)
    result = IRobotApkgExtractor().extract(inpath, tmp_path)
    carved = next(
        p.read_bytes()
        for p in tmp_path.iterdir()
        if p.is_file() and p.name in ("payload.bin", "SStarOta.bin")
    )
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    assert inflater.decompress(carved) == payload
    # embedded MD5 digest and signature both verify, no problems
    assert result.reports == []


@pytest.mark.usefixtures("prod_key")
def test_sigmastar_digest_mismatch(tmp_path: Path):
    payload = b"payload contents\n" * 8
    blob = bytearray(sigmastar_pkg(payload, signed=True))
    data_end = 0x30 + struct.unpack_from("<I", blob[8:12])[0]
    # corrupt one hex character of the embedded digest, which sits right
    # after the gzip member; the corruption also breaks the signature
    inf = zlib.decompressobj(16 + zlib.MAX_WBITS)
    inf.decompress(bytes(blob[0x30:data_end]))
    member_end = 0x30 + (data_end - 0x30) - len(inf.unused_data)
    blob[member_end] = ord("9") if blob[member_end] == ord("0") else ord("0")
    inpath = tmp_path / "in.irobot_apkg"
    inpath.write_bytes(bytes(blob))
    result = IRobotApkgExtractor().extract(inpath, tmp_path)
    problems = [p.problem for p in result.reports if isinstance(p, ExtractionProblem)]
    assert len(problems) == 2
    assert any("digest mismatch" in p for p in problems)
    assert any("signature verification failed" in p for p in problems)


def test_embedded_chunk_at_nonzero_offset():
    blob = entry_table_pkg([(1, b"version1", b"A" * 100)])
    prefix = b"\xde\xad" * 16
    chunk = _chunk(prefix + blob, len(prefix))
    data_end = 0x30 + struct.unpack_from("<I", blob[8:12])[0]
    assert chunk.start_offset == len(prefix)
    assert chunk.end_offset == len(prefix) + data_end


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b[:8] + struct.pack("<I", 0x10) + b[12:],  # table exceeds payload
        # entry-table count out of range
        lambda b: b[:0x30] + struct.pack("<I", 0) + b[0x34:],
        lambda b: b[:0x30] + struct.pack("<I", 1000) + b[0x34:],
        # entry-table count exceeds the fixed table capacity
        lambda b: b[:0x30] + struct.pack("<I", 11) + b[0x34:],
        lambda b: b[:0x3A4] + b"XXXX" + b[0x3A8:],
        # entry with zero size
        lambda b: b[:0x34] + struct.pack("<III", 1, 0x400, 0) + b[0x34 + 12 :],
        # entry pointing before the table end
        lambda b: b[:0x38] + struct.pack("<I", 0x20) + b[0x3C:],
        # entry pointing past data_end
        lambda b: b[:0x3C] + struct.pack("<I", 0xFFFFFF) + b[0x40:],
    ],
)
def test_invalid_entry_table(mutate):
    blob = mutate(bytearray(entry_table_pkg([(1, b"version1", b"A" * 100)])))
    file = File.from_bytes(bytes(blob))
    file.seek(0)
    with pytest.raises(InvalidInputFormat):
        handler.calculate_chunk(file, 0)


@pytest.mark.parametrize(
    "mutate",
    [
        # bad 0x0b03 tag at 0x34
        lambda b: b[:0x34] + struct.pack("<I", 0x0B04) + b[0x38:],
        # count out of range
        lambda b: b[:0x50] + struct.pack("<I", 0) + b[0x54:],
        lambda b: b[:0x50] + struct.pack("<I", 500) + b[0x54:],
        # marker size mismatch (marker is at table_end = 0x54+24 = 0x6c.. wait)
        # for 2 entries the marker sits at 0x54+24=0x6c; corrupt it
        lambda b: b[:0x70] + struct.pack("<I", 0x0B04) + b[0x74:],
        lambda b: b[:0x6C] + struct.pack("<I", 0x9999) + b[0x70:],
    ],
)
def test_invalid_sequential(mutate):
    base = bytearray(
        sequential_pkg([(1, 0x40200, b"P" * 0x100), (2, 0x40400, b"Q" * 0x80)])
    )
    file = File.from_bytes(bytes(mutate(base)))
    file.seek(0)
    with pytest.raises(InvalidInputFormat):
        handler.calculate_chunk(file, 0)


def test_invalid_sigmastar_gzip_method():
    blob = bytearray(sigmastar_pkg(b"x" * 10))
    blob[0x32] = 0x07  # not deflate
    file = File.from_bytes(bytes(blob))
    file.seek(0)
    with pytest.raises(InvalidInputFormat):
        handler.calculate_chunk(file, 0)


def test_truncated_pkg():
    blob = entry_table_pkg([(1, b"version1", b"A" * 100)])
    file = File.from_bytes(blob[:0x38])
    file.seek(0)
    with pytest.raises((InvalidInputFormat, EOFError)):
        handler.calculate_chunk(file, 0)


@pytest.mark.parametrize("offset, value", [(4, 2), (12, 0x99)])
def test_invalid_header_pattern(offset, value):
    blob = bytearray(entry_table_pkg([(1, b"version1", b"A" * 100)]))
    struct.pack_into("<I", blob, offset, value)
    assert not re.match(handler.PATTERNS[0].as_regex(), blob, re.DOTALL)


def test_valid_header_pattern():
    blob = entry_table_pkg([(1, b"version1", b"A" * 100)])
    assert re.match(handler.PATTERNS[0].as_regex(), blob, re.DOTALL)


def test_sequential_entry_cannot_exceed_payload():
    blob = sequential_pkg(
        [(1, 0x40200, b"P" * 0x100), (2, 0x40400, b"Q" * 0x80)],
        last_overshoot=1,
    )
    with pytest.raises(InvalidInputFormat):
        _chunk(blob)


def test_sequential_first_size_includes_block_header(tmp_path: Path):
    blob = sequential_pkg(
        [(1, 0x40200, b"A" * 16), (2, 0x40400, b"B" * 20)], signed=False
    )
    assert struct.unpack_from("<I", blob, 0x5C)[0] == 24
    inpath = tmp_path / "in.irobot_apkg"
    inpath.write_bytes(blob)
    IRobotApkgExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "entry-1").read_bytes() == b"A" * 16
    assert (tmp_path / "entry-2").read_bytes() == b"B" * 20


@pytest.mark.usefixtures("prod_key")
def test_sequential_crc(tmp_path: Path):
    blob = sequential_pkg([(1, 0x40200, b"P" * 64)], signed=True)
    path = tmp_path / "sample.apkg"
    path.write_bytes(blob)
    assert not IRobotApkgExtractor().extract(path, tmp_path / "valid").reports
    body = bytearray(blob[:-256])
    body[-5] ^= 1
    path.write_bytes(body + _trailer(body, True))
    result = IRobotApkgExtractor().extract(path, tmp_path / "bad")
    assert len(result.reports) == 1
    assert "CRC-32 mismatch" in result.reports[0].problem


@pytest.mark.parametrize("variant", [0, 1])
@pytest.mark.usefixtures("prod_key")
def test_metapackage_extract(tmp_path: Path, variant: int):
    url = b"https://example.com/test.signed\0"
    cert = b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n\0"
    metadata = b"deployment metadata" if variant else b""
    payload = struct.pack("<III", variant, len(url), len(cert)) + url + cert + metadata
    body = header(0x30 + len(payload)) + payload
    blob = body + _trailer(body, True)
    assert _chunk(blob).end_offset == len(blob)
    path = tmp_path / "meta.apkg"
    path.write_bytes(blob)
    assert not IRobotApkgExtractor().extract(path, tmp_path).reports
    assert (tmp_path / "firmware-url").read_bytes() == url
    assert (tmp_path / "certificate.pem").read_bytes() == cert
    if variant:
        assert (tmp_path / "metadata.bin").read_bytes() == metadata
