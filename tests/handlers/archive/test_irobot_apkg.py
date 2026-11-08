import gzip
import hashlib
import struct
import zlib
from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.irobot.apkg import IRobotApkgExtractor, IRobotApkgHandler
from unblob.report import ExtractionProblem

SIGNATURE_TRAILER = b"\xcc" * 304


def header(data_end: int, name: bytes = b"test-pkg") -> bytes:
    return b"aPKG" + struct.pack("<III", 1, data_end, 0x100) + name.ljust(32, b"\0")


def entry_table_pkg(entries) -> bytes:
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
    blob = header(data_end) + table
    for off, payload in parts:
        blob = blob.ljust(off, b"\0") + payload
    return blob + SIGNATURE_TRAILER


def sequential_pkg(entries, last_overshoot: int = 0) -> bytes:
    """Build a sequential-table variant package.

    entries: list of (id, field, payload). Declared sizes equal the
    payloads except the last one, which may overshoot by last_overshoot.
    """
    count = len(entries)
    payload_offset = 0x54 + count * 12 + 8
    data_end = payload_offset + sum(len(p) for _, _, p in entries)
    head = (
        header(data_end)
        + struct.pack("<I", data_end)
        + struct.pack("<I", 0x0B03)
        + b"\0" * 16
        + struct.pack("<I", 0x14020811)
        + struct.pack("<I", 18)
        + struct.pack("<I", count)
    )
    for i, (entry_id, field, payload) in enumerate(entries):
        declared = len(payload) + (last_overshoot if i == count - 1 else 0)
        head += struct.pack("<III", entry_id, field, declared)
    head += struct.pack("<II", len(entries[0][2]), 0x0B03)
    return head + b"".join(p for _, _, p in entries) + SIGNATURE_TRAILER


def sigmastar_pkg(payload: bytes, name: bytes = b"C3_test") -> bytes:
    member = gzip.compress(payload, mtime=0)
    # the post-member region starts with the ASCII hex MD5 of the member
    post = hashlib.md5(member, usedforsecurity=False).hexdigest().encode() + b"\0" * 64
    data_end = 0x30 + len(member) + len(post)
    return header(data_end, name) + member + post + SIGNATURE_TRAILER


handler = IRobotApkgHandler()


def _chunk(blob: bytes, start_offset: int = 0):
    file = File.from_bytes(blob)
    file.seek(start_offset)
    chunk = handler.calculate_chunk(file, start_offset)
    assert chunk is not None
    return chunk


def test_entry_table_chunk():
    blob = entry_table_pkg(
        [
            (1, b"version1", b"A" * 100),
            (2, b"version2", b"B" * 200),
            (3, b"version2", b"C" * 50),
        ]
    )
    chunk = _chunk(blob)
    data_end = struct.unpack_from("<I", blob[8:12])[0]
    assert chunk.start_offset == 0
    assert chunk.end_offset == data_end == len(blob) - len(SIGNATURE_TRAILER)


def test_entry_table_extract(tmp_path: Path):
    p1, p2, p3 = b"A" * 100, b"B" * 200, b"C" * 50
    blob = entry_table_pkg(
        [(1, b"version1", p1), (2, b"version2", p2), (3, b"version2", p3)]
    )
    data_end = struct.unpack_from("<I", blob[8:12])[0]
    inpath = tmp_path / "in.irobot_apkg"
    inpath.write_bytes(blob[:data_end])
    IRobotApkgExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "version1").read_bytes() == p1
    assert (tmp_path / "version2").read_bytes() == p2
    # duplicated labels are disambiguated
    assert (tmp_path / "version2-1").read_bytes() == p3


def test_sequential_chunk_and_extract(tmp_path: Path):
    entries = [
        (1, 0x40200, b"P" * 0x100),
        (3, 0x40300, b"Q" * 0x80),
        (2, 0x40400, b"R" * 0x40),
        (5, 0xF0001, b"S" * 0x200),
    ]
    # last declared size overshoots the stored payload, as on real packages
    blob = sequential_pkg(entries, last_overshoot=0x20)
    chunk = _chunk(blob)
    data_end = struct.unpack_from("<I", blob[8:12])[0]
    assert chunk.start_offset == 0
    assert chunk.end_offset == data_end

    inpath = tmp_path / "in.irobot_apkg"
    inpath.write_bytes(blob[:data_end])
    IRobotApkgExtractor().extract(inpath, tmp_path)
    assert (tmp_path / "entry-1").read_bytes() == b"P" * 0x100
    assert (tmp_path / "entry-3").read_bytes() == b"Q" * 0x80
    assert (tmp_path / "entry-2").read_bytes() == b"R" * 0x40
    # last entry carved up to data_end
    assert (tmp_path / "entry-5").read_bytes() == b"S" * 0x200


def test_sigmastar_chunk_and_extract(tmp_path: Path):
    payload = b"#!/bin/sh\necho update\n" + b"\x00" * 100
    blob = sigmastar_pkg(payload)
    chunk = _chunk(blob)
    data_end = struct.unpack_from("<I", blob[8:12])[0]
    assert chunk.end_offset == data_end

    inpath = tmp_path / "in.irobot_apkg"
    inpath.write_bytes(blob[:data_end])
    result = IRobotApkgExtractor().extract(inpath, tmp_path)
    carved = next(
        p.read_bytes()
        for p in tmp_path.iterdir()
        if p.is_file() and p.name in ("payload.bin", "SStarOta.bin")
    )
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    assert inflater.decompress(carved) == payload
    # the embedded MD5 digest matches the member, no problems recorded
    assert result.reports == []


def test_sigmastar_digest_mismatch(tmp_path: Path):
    payload = b"payload contents\n" * 8
    blob = bytearray(sigmastar_pkg(payload))
    data_end = struct.unpack_from("<I", blob[8:12])[0]
    # corrupt one hex character of the embedded digest, which sits right
    # after the gzip member
    inf = zlib.decompressobj(16 + zlib.MAX_WBITS)
    inf.decompress(bytes(blob[0x30:data_end]))
    member_end = 0x30 + (data_end - 0x30) - len(inf.unused_data)
    blob[member_end] ^= 0x01 if blob[member_end] != ord("0") else 0x00
    blob[member_end] = ord("9") if blob[member_end] == ord("0") else ord("0")
    inpath = tmp_path / "in.irobot_apkg"
    inpath.write_bytes(bytes(blob[:data_end]))
    result = IRobotApkgExtractor().extract(inpath, tmp_path)
    problems = [p for p in result.reports if isinstance(p, ExtractionProblem)]
    assert len(problems) == 1
    assert "digest mismatch" in problems[0].problem


def test_embedded_chunk_at_nonzero_offset():
    blob = entry_table_pkg([(1, b"version1", b"A" * 100)])
    prefix = b"\xde\xad" * 16
    chunk = _chunk(prefix + blob, len(prefix))
    data_end = struct.unpack_from("<I", blob[8:12])[0]
    assert chunk.start_offset == len(prefix)
    assert chunk.end_offset == len(prefix) + data_end


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b[:4] + struct.pack("<I", 2) + b[8:],  # bad version
        lambda b: b[:12] + struct.pack("<I", 0x99) + b[16:],  # bad field_0c
        lambda b: b[:8] + struct.pack("<I", 0x10) + b[12:],  # data_end <= 0x30
        # entry-table count out of range
        lambda b: b[:0x30] + struct.pack("<I", 0) + b[0x34:],
        lambda b: b[:0x30] + struct.pack("<I", 1000) + b[0x34:],
        # entry-table count fits but table overruns data_end
        lambda b: b[:0x30] + struct.pack("<I", 40) + b[0x34:],
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
    with pytest.raises(InvalidInputFormat):
        handler.calculate_chunk(file, 0)
