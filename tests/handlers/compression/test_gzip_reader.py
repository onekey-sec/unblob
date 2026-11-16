import gzip
import io
import random
import struct
import zlib

import pytest

from unblob.file_utils import DEFAULT_BUFSIZE, File, InvalidInputFormat
from unblob.handlers.compression import _gzip_reader
from unblob.handlers.compression._gzip_reader import SingleMemberGzipReader
from unblob.handlers.compression.gzip import GZIP2_STRICT_TRAILER_MAX_SIZE, GZIPHandler


class MonitoredDecompressor:
    def __init__(self, reader):
        self.inner = reader._decompressor  # noqa: SLF001
        self.drains = 0

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def decompress(self, data, max_length):
        if not getattr(self.inner, "needs_input", True):
            assert data == b"", "New compressed input supplied before draining buffers"
            self.drains += 1
        return self.inner.decompress(data, max_length)


@pytest.mark.parametrize("legacy", [False, True], ids=["native", "unconsumed-tail"])
@pytest.mark.parametrize(
    "size", [0, DEFAULT_BUFSIZE, DEFAULT_BUFSIZE + 1, 8 * DEFAULT_BUFSIZE]
)
def test_read_single_member(legacy: bool, size: int, monkeypatch):
    payload = b"x" * size
    member = gzip.compress(payload)
    following = gzip.compress(b"next member") + b"garbage"
    stream = io.BytesIO(member + following)
    reader = SingleMemberGzipReader(stream)
    assert reader.read_header()
    if legacy:
        monkeypatch.setattr(
            reader, "_decompressor", zlib.decompressobj(-zlib.MAX_WBITS)
        )
    monitor = MonitoredDecompressor(reader)
    monkeypatch.setattr(reader, "_decompressor", monitor)
    chunks = []

    while not monitor.eof:
        chunk = reader.read_all()
        assert len(chunk) <= DEFAULT_BUFSIZE
        chunks.append(chunk)

    assert b"".join(chunks) == payload
    assert reader.crc == zlib.crc32(payload)
    assert reader.size == size
    assert reader.unused_data == member[-8:] + following
    assert stream.tell() - len(reader.unused_data) + 8 == len(member)
    if hasattr(monitor, "needs_input") and size > DEFAULT_BUFSIZE:
        assert monitor.drains > 0


def test_handler_drains_buffered_input(monkeypatch):
    # Repeated random blocks mix expansion with incompressible data, so blindly
    # reading compressed buffers keeps supplying input while zlib buffers it.
    rng = random.Random(0)  # noqa: S311 - reproducible synthetic compression input
    payload = b"".join(rng.randbytes(16 * 1024) * 2 for _ in range(32))
    member = gzip.compress(payload)
    members = []
    original = SingleMemberGzipReader.read_header

    def read_header(reader):
        result = original(reader)
        monitor = MonitoredDecompressor(reader)
        members.append((reader, monitor))
        monkeypatch.setattr(reader, "_decompressor", monitor)
        return result

    monkeypatch.setattr(SingleMemberGzipReader, "read_header", read_header)
    prefix = b"prefix"
    following = gzip.compress(b"second member")
    with File.from_bytes(prefix + member + following + b"garbage") as file:
        file.seek(len(prefix))
        chunk = GZIPHandler().calculate_chunk(file, len(prefix))

    assert chunk is not None
    assert chunk.start_offset == len(prefix)
    assert chunk.end_offset == len(prefix + member + following)
    reader, monitor = members[0]
    assert reader.size == len(payload)
    assert reader.crc == zlib.crc32(payload)
    assert monitor.inner.eof
    if hasattr(monitor, "needs_input"):
        assert monitor.drains > 0


@pytest.mark.parametrize("cut", [9, 10, 12])
def test_truncated_deflate_stream(cut: int):
    reader = SingleMemberGzipReader(
        io.BytesIO(gzip.compress(b"x" * DEFAULT_BUFSIZE)[:-cut])
    )
    assert reader.read_header()
    with pytest.raises(EOFError, match="before the end-of-stream marker"):
        reader.read_until_eof()


@pytest.mark.parametrize("field", [0, 1], ids=["crc", "size"])
def test_trailer_validation_after_draining(field: int, monkeypatch):
    # Exercise draining while keeping the member within the handler's existing
    # strict trailer-validation threshold.
    monkeypatch.setattr(_gzip_reader, "DEFAULT_BUFSIZE", 8192)
    payload = b"x" * GZIP2_STRICT_TRAILER_MAX_SIZE
    member = gzip.compress(payload)
    trailer = list(struct.unpack("<II", member[-8:]))
    trailer[field] ^= 1
    content = member[:-8] + struct.pack("<II", *trailer)
    with (
        File.from_bytes(content) as file,
        pytest.raises(InvalidInputFormat, match="trailer"),
    ):
        GZIPHandler().calculate_chunk(file, 0)


@pytest.mark.parametrize("cut", [1, 4, 8])
def test_truncated_trailer_after_draining(cut: int):
    member = gzip.compress(b"x" * (DEFAULT_BUFSIZE + 1))
    with (
        File.from_bytes(member[:-cut]) as file,
        pytest.raises(InvalidInputFormat, match="Truncated gzip trailer"),
    ):
        GZIPHandler().calculate_chunk(file, 0)


@pytest.mark.parametrize(
    "payloads",
    [
        pytest.param((b"",), id="single"),
        pytest.param((b"", b"next"), id="first"),
        pytest.param((b"previous", b""), id="last"),
        pytest.param((b"previous", b"", b"next"), id="middle"),
    ],
)
def test_empty_member_chunk(payloads: tuple[bytes, ...]):
    members = b"".join(gzip.compress(payload) for payload in payloads)
    with File.from_bytes(members + b"garbage") as file:
        chunk = GZIPHandler().calculate_chunk(file, 0)
    assert chunk is not None
    assert chunk.end_offset == len(members)
