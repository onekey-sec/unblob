import struct
import zlib

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.installshield_pftw import (
    KEY_MAGIC,
    InstallShieldPftwHandler,
    _decode_slices,
    _inflate_slices,
    _member_block_size,
    _member_path,
)

HEADER_SIZE = 0x2E
FILE_ATTRIBUTES_SIZE = 0x138
STREAM_FILE_ATTRIBUTES_SIZE = 0x18

SIG_PFTW = b"InstallShield\x00"
SIG_STREAM = b"ISSetupStream\x00"

_NIBBLE_SWAP = bytes((i << 4 | i >> 4) & 0xFF for i in range(256))

handler = InstallShieldPftwHandler()


def _header(magic: bytes = SIG_PFTW, num_files: int = 1, type_: int = 0) -> bytes:
    return struct.pack(
        "<14sHI8sH16s", magic, num_files, type_, b"\x00" * 8, 0, b"\x00" * 16
    )


def _file_attributes(
    name: bytes, file_len: int, encoded_flags: int = 0, inflate: int = 0
) -> bytes:
    return struct.pack(
        "<260sII I 8s H 30s",
        name,
        encoded_flags,
        0,
        file_len,
        b"\x00" * 8,
        inflate,
        b"\x00" * 30,
    )


def _classic_package(members: list[tuple[bytes, bytes]]) -> bytes:
    blob = _header(num_files=len(members))
    for name, data in members:
        blob += _file_attributes(name, len(data)) + data
    return blob


def _stream_attrs(
    name_len: int, file_len: int, encoded_flags: int = 0, inflate: int = 0
) -> bytes:
    return struct.pack(
        "<II2sI8sH",
        name_len,
        encoded_flags,
        b"\x00" * 2,
        file_len,
        b"\x00" * 8,
        inflate,
    )


def _stream_package(
    members: list[tuple[bytes, bytes]], type_: int, header_type: int | None = None
) -> bytes:
    """Build an ISSetupStream package; members are (utf-16 name bytes, data)."""
    blob = _header(
        magic=SIG_STREAM,
        num_files=len(members),
        type_=type_ if header_type is None else header_type,
    )
    for name_bytes, data in members:
        attrs = _stream_attrs(len(name_bytes), len(data))
        if type_ == 4:
            attrs += b"\x00" * STREAM_FILE_ATTRIBUTES_SIZE
        blob += attrs + name_bytes + data
    return blob


def _encode_member(data: bytes, seed: bytes, block_size: int) -> bytes:
    """Member obfuscation, the exact inverse of _decode_slices."""
    mask = bytes(
        ~(b ^ KEY_MAGIC[i % len(KEY_MAGIC)]) & 0xFF for i, b in enumerate(seed)
    )
    parts = []
    for start in range(0, len(data), block_size):
        block = data[start : start + block_size]
        parts.append(
            bytes(b ^ mask[i % len(mask)] for i, b in enumerate(block)).translate(
                _NIBBLE_SWAP
            )
        )
    return b"".join(parts)


CLASSIC_PACKAGE = _classic_package(
    [(b"setup.ini", b"[Startup]\r\n"), (b"app.exe", b"MZ\x90\x00")]
)
STREAM_PACKAGE = _stream_package(
    [
        ("setup.ini".encode("utf-16-le"), b"[Startup]\r\n"),
        ("app.exe".encode("utf-16-le"), b"MZ\x90\x00"),
    ],
    type_=2,
)
STREAM4_PACKAGE = _stream_package(
    [("setup.ini".encode("utf-16-le"), b"[Startup]\r\n")], type_=4
)


@pytest.mark.parametrize(
    "contents",
    [
        pytest.param(CLASSIC_PACKAGE, id="classic"),
        pytest.param(STREAM_PACKAGE, id="stream"),
        pytest.param(STREAM4_PACKAGE, id="stream-type4"),
        pytest.param(
            _stream_package(
                [("a.exe".encode("utf-16-le"), b"MZ")], type_=1, header_type=0
            ),
            id="stream-type0",
        ),
    ],
)
def test_chunk_calculation(contents):
    # the parser positions the file itself
    chunk = handler.calculate_chunk(File.from_bytes(contents), 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == len(contents)


def test_chunk_calculation_with_prefix():
    prefix = b"MZ" * 16
    chunk = handler.calculate_chunk(
        File.from_bytes(prefix + CLASSIC_PACKAGE + b"trailing"), len(prefix)
    )

    assert chunk is not None
    assert chunk.start_offset == len(prefix)
    assert chunk.end_offset == len(prefix) + len(CLASSIC_PACKAGE)


@pytest.mark.parametrize(
    "contents, error",
    [
        pytest.param(
            b"NotInstallShield" + CLASSIC_PACKAGE[16:],
            "no InstallShield signature",
            id="bad-magic",
        ),
        pytest.param(
            _header(num_files=0) + CLASSIC_PACKAGE[HEADER_SIZE:],
            "no members",
            id="no-members",
        ),
        pytest.param(
            _header(magic=SIG_STREAM, type_=5) + STREAM_PACKAGE[HEADER_SIZE:],
            "unsupported layout type 5",
            id="stream-type-too-new",
        ),
        pytest.param(
            _header(type_=5) + CLASSIC_PACKAGE[HEADER_SIZE:],
            "unsupported layout type 5",
            id="classic-type-too-new",
        ),
        pytest.param(
            _header()
            + _file_attributes(b"\x00" * 260, 4)
            + b"data"
            + CLASSIC_PACKAGE[HEADER_SIZE + FILE_ATTRIBUTES_SIZE + 4 :],
            "empty member name",
            id="empty-member-name",
        ),
        pytest.param(
            _header() + _file_attributes(b"setup.ini", 100) + b"data",
            "member data lies beyond the package",
            id="member-data-truncated",
        ),
        pytest.param(
            _header(magic=SIG_STREAM, type_=2) + _stream_attrs(0, 4) + b"data",
            "invalid stream member name length 0",
            id="stream-empty-name",
        ),
        pytest.param(
            _header(magic=SIG_STREAM, type_=2) + _stream_attrs(4096, 4) + b"data",
            "invalid stream member name length 4096",
            id="stream-name-too-long",
        ),
        pytest.param(
            _header(magic=SIG_STREAM, type_=2)
            + _stream_attrs(7, 4)
            + b"n\x00a\x00m\x00e",
            "invalid stream member name length 7",
            id="stream-name-odd-length",
        ),
        pytest.param(
            _header(magic=SIG_STREAM, type_=2)
            + _stream_attrs(20, 4)
            + b"n\x00a\x00m\x00",
            "member name lies beyond the package",
            id="stream-name-truncated",
        ),
        pytest.param(
            _header(magic=SIG_STREAM, type_=2)
            + _stream_attrs(4, 4)
            + b"\x00\xd8\x00\x00"  # lone UTF-16 surrogate
            + b"data",
            "invalid UTF-16 member name",
            id="stream-name-bad-utf16",
        ),
        pytest.param(
            _header(magic=SIG_STREAM, type_=2)
            + _stream_attrs(4, 4)
            + b"\x00\x00\x00\x00"  # decodes to a lone NUL
            + b"data",
            "empty member name",
            id="stream-name-only-nul",
        ),
    ],
)
def test_invalid_chunk(contents, error):
    with pytest.raises(InvalidInputFormat, match=error):
        handler.calculate_chunk(File.from_bytes(contents), 0)


def test_stream_name_trailing_nul():
    """A NUL inside the stored name ends it, like a C string."""
    contents = _stream_package([("a.exe\x00".encode("utf-16-le"), b"MZ")], type_=2)
    chunk = handler.calculate_chunk(File.from_bytes(contents), 0)
    assert chunk is not None
    assert chunk.end_offset == len(contents)


@pytest.mark.parametrize(
    "contents",
    [
        pytest.param(SIG_PFTW, id="header-only"),
        pytest.param(CLASSIC_PACKAGE[: HEADER_SIZE + 0x100], id="record-truncated"),
        pytest.param(
            STREAM_PACKAGE[: HEADER_SIZE + STREAM_FILE_ATTRIBUTES_SIZE + 2],
            id="stream-name-partial",
        ),
    ],
)
def test_truncated_chunk(contents):
    with pytest.raises((EOFError, InvalidInputFormat)):
        handler.calculate_chunk(File.from_bytes(contents), 0)


@pytest.mark.parametrize(
    "encoded_flags, is_stream, expected",
    [
        pytest.param(0x4, False, 1024, id="m1024"),
        pytest.param(0x6, False, 1024, id="m1024-with-2"),
        pytest.param(0x4, True, 1024, id="stream-m1024"),
        pytest.param(0x2, False, 64, id="mfile"),
        pytest.param(0x2, True, None, id="stream-flag2-not-decoded"),
        pytest.param(0, False, None, id="stored"),
    ],
)
def test_member_block_size(encoded_flags, is_stream, expected):
    assert _member_block_size(encoded_flags, 64, is_stream=is_stream) == expected


def _decode(data: bytes, seed: bytes, block_size: int) -> bytes:
    return b"".join(
        _decode_slices(File.from_bytes(data), 0, len(data), seed, block_size)
    )


def test_decode_m1024():
    content = bytes(range(256)) * 8  # spans several 1024-byte blocks
    seed = b"setup.ini"
    encoded = _encode_member(content, seed, 1024)

    assert _decode(encoded, seed, 1024) == content


def test_decode_mfile():
    content = bytes(range(256)) * 8
    seed = b"setup.ini"
    encoded = _encode_member(content, seed, len(content))

    assert _decode(encoded, seed, len(content)) == content


def test_decode_known_vector():
    # name "a": key = ~(0x61 ^ 0x13) = 0x8D;
    # plain 0x78 encodes as nibbleswap(0x78 ^ 0x8D) = nibbleswap(0xF5) = 0x5F
    assert _decode(b"\x5f", b"a", 1024) == b"\x78"


def test_decode_empty():
    file = File.from_bytes(b"anything")
    assert b"".join(_decode_slices(file, 0, 0, b"name", 1024)) == b""


def test_inflate_slices():
    content = b"inflated content" * 100
    compressed = zlib.compress(content)
    chunks = [compressed[i : i + 17] for i in range(0, len(compressed), 17)]
    assert b"".join(_inflate_slices(chunks)) == content


def test_inflate_slices_invalid():
    with pytest.raises(zlib.error):
        b"".join(_inflate_slices([b"not zlib"]))


def test_inflate_slices_truncated():
    with pytest.raises(zlib.error, match="truncated"):
        b"".join(_inflate_slices([zlib.compress(b"content")[:5]]))


def test_extract_reports_broken_member(tmp_path):
    """A member that fails to inflate writes decoded data and a problem."""
    content = b"broken" * 100
    broken = zlib.compress(content)[:-4]  # truncated zlib stream
    package = _header() + _file_attributes(b"bad.ini", len(broken), inflate=1) + broken
    inpath = tmp_path / "package.pftw"
    inpath.write_bytes(package)
    outdir = tmp_path / "out"

    result = handler.EXTRACTOR.extract(inpath, outdir)

    assert (outdir / "bad.ini").read_bytes() == broken
    assert len(result.reports) == 1
    assert "inflate" in result.reports[0].problem


@pytest.mark.parametrize(
    "name, index, expected",
    [
        pytest.param(b"setup.ini", 0, "setup.ini", id="plain-name"),
        pytest.param(
            b"lang\\0x0409.ini", 0, "lang/0x0409.ini", id="windows-path-separator"
        ),
        pytest.param("unicode 0x0409.ini", 0, "unicode 0x0409.ini", id="unicode-name"),
        pytest.param(b"", 3, "member_3", id="empty-name"),
        pytest.param(b".", 1, "member_1", id="dot-name"),
        pytest.param(b"/abs/path", 0, "abs/path", id="leading-slash"),
    ],
)
def test_member_path(name, index, expected):
    assert _member_path(name, index).as_posix() == expected
