import struct
import zlib
from pathlib import Path

import pytest
import zstandard

from unblob import file_utils
from unblob.file_utils import File, InvalidInputFormat, SeekError
from unblob.handlers.archive.qt_rcc import (
    COMPRESSED_ZLIB_FLAG,
    COMPRESSED_ZSTD_FLAG,
    DIRECTORY_FLAG,
    QtRccExtractor,
    QtRccHandler,
)
from unblob.report import ExtractionProblem

MAGIC = b"qres"
DIR = DIRECTORY_FLAG
ZLIB = COMPRESSED_ZLIB_FLAG
ZSTD = COMPRESSED_ZSTD_FLAG


def name_entry(name: bytes) -> bytes:
    return struct.pack(">HI", len(name) // 2, 0) + name


def utf16(name: str) -> bytes:
    return name.encode("utf-16-be")


def _store(payload: bytes, comp: int) -> bytes:
    if comp == ZLIB:
        return struct.pack(">I", len(payload)) + zlib.compress(payload)
    if comp == ZSTD:
        return zstandard.ZstdCompressor().compress(payload)
    return payload


def make_rcc(entries, version=3, file_flags=0) -> bytes:
    """Build an rcc file from {name: bytes|(payload, flags)|{subdir: ...}}."""
    nodes = []
    names = b""
    datas = b""

    def add_name(name: str) -> int:
        nonlocal names
        off = len(names)
        names += name_entry(utf16(name))
        return off

    def add_dir(name: str, content: dict) -> int:
        idx = len(nodes)
        nodes.append(None)
        children = []
        for k, v in content.items():
            if isinstance(v, dict):
                children.append(add_dir(k, v))
            else:
                payload, comp = v if isinstance(v, tuple) else (v, 0)
                children.append(add_file(k, payload, comp))
        noff = add_name(name) if name else 0
        nodes[idx] = (
            noff,
            DIR,
            struct.pack(">II", len(children), children[0] if children else 0),
        )
        return idx

    def add_file(name: str, payload: bytes, comp: int) -> int:
        nonlocal datas
        idx = len(nodes)
        payload = _store(payload, comp)
        doff = len(datas)
        datas += struct.pack(">I", len(payload)) + payload
        nodes.append((add_name(name), comp, struct.pack(">HHI", 0, 1, doff)))
        return idx

    add_dir("", entries)

    node_len = 14 + (8 if version >= 2 else 0)
    tree = b""
    for noff, flags, body in nodes:
        tree += struct.pack(">IH", noff, flags) + body + b"\x00" * (node_len - 14)

    header_len = 24 if version >= 3 else 20
    data_off = header_len
    names_off = data_off + len(datas)
    tree_off = names_off + len(names)
    header = MAGIC + struct.pack(">IIII", version, tree_off, data_off, names_off)
    if version >= 3:
        header += struct.pack(">I", file_flags)
    return header + datas + names + tree


SAMPLE = {
    "file.txt": b"hello world!\n",
    "icon.png": b"\x89PNG fake png content",
    "logo.svg": (b"<svg>compressible svg content</svg>" * 20, ZLIB),
    "subdir": {
        "file.txt": b"sub file!\n",
        "data.bin": (bytes.fromhex("deadbeef") * 50, ZSTD),
    },
}
SAMPLE_V3 = make_rcc(SAMPLE, version=3, file_flags=ZLIB | ZSTD)

handler = QtRccHandler()


def _calc(content: bytes, offset: int = 0):
    file = File.from_bytes(content)
    file.seek(offset)
    return handler.calculate_chunk(file, offset)


@pytest.mark.parametrize(
    "version, file_flags",
    [(1, 0), (2, 0), (3, 0), (3, ZLIB), (3, ZSTD), (3, ZLIB | ZSTD)],
)
def test_chunk_calculation_versions(version, file_flags):
    contents = make_rcc(SAMPLE, version=version, file_flags=file_flags)
    chunk = _calc(contents)
    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == len(contents)


def test_chunk_calculation_embedded():
    contents = b"garbage" + SAMPLE_V3 + b"trailing"
    chunk = _calc(contents, 7)
    assert chunk is not None
    assert chunk.start_offset == 7
    assert chunk.end_offset == 7 + len(SAMPLE_V3)


def test_chunk_calculation_trailing_data_after_resource():
    # an rcc embedded in a bigger file must end at its own extent, not EOF
    contents = SAMPLE_V3 + b"\x00" * 100
    chunk = _calc(contents)
    assert chunk is not None
    assert chunk.end_offset == len(SAMPLE_V3)


def _patch(contents: bytes, offset: int, data: bytes) -> bytes:
    patched = bytearray(contents)
    patched[offset : offset + len(data)] = data
    return bytes(patched)


@pytest.mark.parametrize(
    "contents",
    [
        # truncated header
        MAGIC,
        MAGIC + b"\x00" * 8,
        # unsupported versions
        make_rcc(SAMPLE, version=0),
        make_rcc(SAMPLE, version=4),
        # version 3 file flags outside the known mask
        make_rcc(SAMPLE, version=3, file_flags=0x02),
        make_rcc(SAMPLE, version=3, file_flags=0x08),
        make_rcc(SAMPLE, version=3, file_flags=0x10),
        # section offsets pointing into the header
        _patch(SAMPLE_V3, 8, (8).to_bytes(4, "big")),
        _patch(SAMPLE_V3, 12, (0).to_bytes(4, "big")),
        _patch(SAMPLE_V3, 16, (16).to_bytes(4, "big")),
        # root node is a file, not a directory
        _patch(SAMPLE_V3, int.from_bytes(SAMPLE_V3[8:12], "big") + 4, b"\x00\x00"),
        # unknown node flag bits
        _patch(SAMPLE_V3, int.from_bytes(SAMPLE_V3[8:12], "big") + 4, b"\x00\x08"),
        # node with both compression algorithms
        _patch(
            SAMPLE_V3,
            int.from_bytes(SAMPLE_V3[8:12], "big") + 4,
            (ZLIB | ZSTD).to_bytes(2, "big"),
        ),
        # first_child out of bounds
        _patch(
            SAMPLE_V3,
            int.from_bytes(SAMPLE_V3[8:12], "big") + 10,
            (0xFFFF).to_bytes(4, "big"),
        ),
        # child_count beyond the node area
        _patch(
            SAMPLE_V3,
            int.from_bytes(SAMPLE_V3[8:12], "big") + 6,
            (0x1000).to_bytes(4, "big"),
        ),
        # truncated file: cut inside the tree section
        SAMPLE_V3[: int.from_bytes(SAMPLE_V3[8:12], "big") + 20],
        # truncated file: cut inside the data section
        SAMPLE_V3[:100],
        # data entry length claiming past EOF
        _patch(SAMPLE_V3, 24, (0xFFFFFF).to_bytes(4, "big")),
        # data entry pointing outside the file
        _patch(
            SAMPLE_V3,
            # file node 1: data_offset field (tree + node_len + 10)
            int.from_bytes(SAMPLE_V3[8:12], "big") + 22 + 10,
            (0xFFFFFF).to_bytes(4, "big"),
        ),
        # name_offset past the names section
        _patch(
            SAMPLE_V3,
            int.from_bytes(SAMPLE_V3[8:12], "big") + 22,
            (0xFFFFFF).to_bytes(4, "big"),
        ),
        # name_len claiming more than the file holds
        _patch(
            SAMPLE_V3,
            int.from_bytes(SAMPLE_V3[16:20], "big"),
            (0xFFFF).to_bytes(2, "big"),
        ),
    ],
    ids=[
        "magic-only",
        "short-header",
        "version-0",
        "version-4",
        "file-flags-dir-bit",
        "file-flags-unknown-bit",
        "file-flags-high-bit",
        "tree-offset-in-header",
        "data-offset-in-header",
        "names-offset-in-header",
        "root-not-dir",
        "node-unknown-flag",
        "node-two-compressions",
        "child-index-out-of-bounds",
        "child-count-out-of-bounds",
        "truncated-tree",
        "truncated-data",
        "data-len-past-eof",
        "data-offset-past-eof",
        "name-offset-past-eof",
        "name-len-past-eof",
    ],
)
def test_invalid_chunk(contents):
    file = File.from_bytes(contents)
    with pytest.raises((InvalidInputFormat, EOFError, SeekError)):
        handler.calculate_chunk(file, 0)


def _dir_cycle_rcc() -> bytes:
    """Two dirs referencing each other: node0 -> [1], node1 -> [0]."""
    names = name_entry(utf16("child"))
    tree = struct.pack(">IHIIQ", 0, DIR, 1, 1, 0) + struct.pack(
        ">IHIIQ", 0, DIR, 1, 0, 0
    )
    data_off = 24
    names_off = data_off
    tree_off = names_off + len(names)
    header = MAGIC + struct.pack(">IIIII", 3, tree_off, data_off, names_off, 0)
    return header + names + tree


def test_node_referenced_twice():
    with pytest.raises(InvalidInputFormat, match="referenced twice"):
        _calc(_dir_cycle_rcc())


def _bad_name_rcc(name_bytes: bytes) -> bytes:
    """Two-node rcc: root dir + one file node with a crafted name entry."""
    names = name_bytes
    tree = struct.pack(">IHIIQ", 0, DIR, 1, 1, 0) + struct.pack(
        ">IHHHIQ", 0, 0, 0, 1, 0, 0
    )
    # file node points at a data entry
    data = struct.pack(">I", 4) + b"data"
    header_len = 24
    data_off = header_len
    names_off = data_off + len(data)
    tree_off = names_off + len(names)
    return (
        MAGIC
        + struct.pack(">IIIII", 3, tree_off, data_off, names_off, 0)
        + data
        + names
        + tree
    )


@pytest.mark.parametrize(
    "name_bytes",
    [
        pytest.param(b"\x00", id="truncated-header"),
        # name_len larger than the whole file
        pytest.param(struct.pack(">HI", 0xFFFF, 0) + b"a" * 4, id="truncated-name"),
        pytest.param(struct.pack(">HI", 0, 0), id="empty"),
        pytest.param(struct.pack(">HI", 1, 0) + utf16("."), id="dot"),
        pytest.param(struct.pack(">HI", 1, 0) + utf16("/"), id="slash"),
        # NUL in a name: impossible in real resources, unsafe on every fs
        pytest.param(struct.pack(">HI", 3, 0) + utf16("a\x00b"), id="nul"),
    ],
)
def test_invalid_names(name_bytes):
    with pytest.raises(InvalidInputFormat):
        _calc(_bad_name_rcc(name_bytes))


def test_extract(tmp_path: Path):
    inpath = tmp_path / "in.qt_rcc"
    inpath.write_bytes(SAMPLE_V3)

    result = QtRccExtractor().extract(inpath, tmp_path)

    assert (tmp_path / "file.txt").read_bytes() == SAMPLE["file.txt"]
    assert (tmp_path / "icon.png").read_bytes() == SAMPLE["icon.png"]
    assert (tmp_path / "logo.svg").read_bytes() == SAMPLE["logo.svg"][0]
    assert (tmp_path / "subdir" / "file.txt").read_bytes() == SAMPLE["subdir"][
        "file.txt"
    ]
    assert (tmp_path / "subdir" / "data.bin").read_bytes() == SAMPLE["subdir"][
        "data.bin"
    ][0]
    assert not result.reports


def test_extract_zlib_size_mismatch(tmp_path: Path):
    # declared uncompressed size does not match the actual stream
    payload = b"mismatch me" * 10
    rcc = make_rcc({"f": (payload, ZLIB)}, version=3, file_flags=ZLIB)
    # bump the declared size stored at data_offset + 4
    rcc = _patch(rcc, 24 + 4, (len(payload) + 5).to_bytes(4, "big"))
    inpath = tmp_path / "in.qt_rcc"
    inpath.write_bytes(rcc)

    result = QtRccExtractor().extract(inpath, tmp_path)

    assert (tmp_path / "f").read_bytes() == payload
    assert len(result.reports) == 1
    assert isinstance(result.reports[0], ExtractionProblem)
    assert "size mismatch" in result.reports[0].problem


def test_extract_corrupt_zlib(tmp_path: Path):
    rcc = make_rcc({"f": (b"payload" * 50, ZLIB)}, version=3, file_flags=ZLIB)
    # corrupt the zlib stream near its start (after the 4-byte ulen prefix)
    rcc = _patch(rcc, 24 + 4 + 4, b"\xff\xff\xff")
    inpath = tmp_path / "in.qt_rcc"
    inpath.write_bytes(rcc)

    result = QtRccExtractor().extract(inpath, tmp_path)

    assert not (tmp_path / "f").exists()
    assert len(result.reports) == 1
    assert isinstance(result.reports[0], ExtractionProblem)
    assert "zlib" in result.reports[0].problem


def test_extract_duplicate_names(tmp_path: Path):
    # two file nodes sharing a name: second one is renamed
    names = name_entry(utf16("same.txt")) + name_entry(utf16("same.txt"))
    tree = (
        struct.pack(">IHIIQ", 0, DIR, 2, 1, 0)
        + struct.pack(">IHHHIQ", 0, 0, 0, 1, 0, 0)
        + struct.pack(">IHHHIQ", len(name_entry(utf16("same.txt"))), 0, 0, 1, 8, 0)
    )
    data = struct.pack(">I", 4) + b"one!" + struct.pack(">I", 4) + b"two!"
    header_len = 24
    data_off = header_len
    names_off = data_off + len(data)
    tree_off = names_off + len(names)
    rcc = (
        MAGIC
        + struct.pack(">IIIII", 3, tree_off, data_off, names_off, 0)
        + data
        + names
        + tree
    )
    inpath = tmp_path / "in.qt_rcc"
    inpath.write_bytes(rcc)
    outdir = tmp_path / "out"
    outdir.mkdir()

    result = QtRccExtractor().extract(inpath, outdir)

    contents = {p.name: p.read_bytes() for p in outdir.iterdir() if p.is_file()}
    assert sorted(contents.values()) == [b"one!", b"two!"]
    assert len(contents) == 2
    assert len(result.reports) == 1
    assert isinstance(result.reports[0], ExtractionProblem)
    assert "Duplicate" in result.reports[0].problem


def test_extract_file_dir_name_collision(tmp_path: Path):
    # a file and a dir sharing a name: the dir is renamed
    name2 = name_entry(utf16("collide"))
    name3 = name_entry(utf16("inner.txt"))
    names = name2 + name2 + name3
    tree = (
        struct.pack(">IHIIQ", 0, DIR, 2, 1, 0)
        # file node named "collide"
        + struct.pack(">IHHHIQ", 0, 0, 0, 1, 0, 0)
        # dir node named "collide" with child node 3
        + struct.pack(">IHIIQ", len(name2), DIR, 1, 3, 0)
        # inner file node named "inner.txt"
        + struct.pack(">IHHHIQ", len(name2) * 2, 0, 0, 1, 8, 0)
    )
    data = struct.pack(">I", 4) + b"file" + struct.pack(">I", 5) + b"inner"
    header_len = 24
    data_off = header_len
    names_off = data_off + len(data)
    tree_off = names_off + len(names)
    rcc = (
        MAGIC
        + struct.pack(">IIIII", 3, tree_off, data_off, names_off, 0)
        + data
        + names
        + tree
    )
    inpath = tmp_path / "in.qt_rcc"
    inpath.write_bytes(rcc)
    outdir = tmp_path / "out"
    outdir.mkdir()

    result = QtRccExtractor().extract(inpath, outdir)

    assert (outdir / "collide").is_file()
    assert (outdir / "collide-2" / "inner.txt").read_bytes() == b"inner"
    assert len(result.reports) == 1


def test_extract_unwritable_file_name(tmp_path: Path, monkeypatch):
    # names legal in the format but illegal on the local filesystem
    # (e.g. EILSEQ on macOS) are reported, not fatal
    rcc = make_rcc({"good.txt": b"ok", "bad.txt": b"ko"}, version=3)
    inpath = tmp_path / "in.qt_rcc"
    inpath.write_bytes(rcc)
    outdir = tmp_path / "out"
    outdir.mkdir()

    real_carve = file_utils.FileSystem.carve

    def failing_carve(self, path, *args, **kwargs):
        if path.name == "bad.txt":
            raise OSError(92, "Illegal byte sequence")
        return real_carve(self, path, *args, **kwargs)

    monkeypatch.setattr(file_utils.FileSystem, "carve", failing_carve)

    result = QtRccExtractor().extract(inpath, outdir)

    assert (outdir / "good.txt").read_bytes() == b"ok"
    assert not (outdir / "bad.txt").exists()
    assert len(result.reports) == 1
    assert isinstance(result.reports[0], ExtractionProblem)
    assert "Cannot write RCC entry" in result.reports[0].problem


def test_extract_uncreatable_dir_skips_subtree(tmp_path: Path, monkeypatch):
    # an mkdir failure reports once and skips the whole subtree
    rcc = make_rcc({"top": b"ok", "dir": {"inner.txt": b"inner"}}, version=3)
    inpath = tmp_path / "in.qt_rcc"
    inpath.write_bytes(rcc)
    outdir = tmp_path / "out"
    outdir.mkdir()

    real_mkdir = file_utils.FileSystem.mkdir

    def failing_mkdir(self, path, **kwargs):
        if path.name == "dir":
            raise OSError(36, "File name too long")
        return real_mkdir(self, path, **kwargs)

    monkeypatch.setattr(file_utils.FileSystem, "mkdir", failing_mkdir)

    result = QtRccExtractor().extract(inpath, outdir)

    assert (outdir / "top").read_bytes() == b"ok"
    assert not (outdir / "dir").exists()
    assert len(result.reports) == 1
    assert isinstance(result.reports[0], ExtractionProblem)
    assert "Cannot create RCC directory" in result.reports[0].problem
