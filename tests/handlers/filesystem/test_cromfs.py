import stat
import struct
from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat, SeekError
from unblob.finder import search_chunks
from unblob.handlers import BUILTIN_HANDLERS
from unblob.handlers.filesystem.cromfs import (
    MAGIC,
    CromFS,
    CromFSExtractor,
    CROMFSHandler,
    decompress_lzf,
)

FIXTURES = Path(__file__).parents[2] / "integration/filesystem/cromfs"


def make_image(payload=b"hello", *, endian="<", name=b"file", block=None):
    if block is None:
        block = b"ZV\0" + struct.pack(">H", len(payload)) + payload if payload else b""
    name_offset = 62
    data_offset = name_offset + len(name) + 1
    size = data_offset + len(block)
    return bytearray(
        struct.pack(endian + "IHHIII", MAGIC, 2, bool(payload), 20, size, 512)
        + struct.pack(endian + "HHIIII", stat.S_IFLNK | 0o555, 0, 40, 0, 42, 20)
        + b".\0"
        + struct.pack(
            endian + "HHIIII",
            stat.S_IFREG | 0o444,
            0,
            name_offset,
            len(payload),
            0,
            data_offset,
        )
        + name
        + b"\0"
        + block
    )


def parse(image):
    return CromFS(File.from_bytes(image))


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("padding", [0, 17])
def test_detect_embedded_image(endian, padding):
    data = make_image(endian=endian)
    file = File.from_bytes(b"X" * padding + data + b"trailer")
    file.seek(padding)
    chunk = CROMFSHandler().calculate_chunk(file, padding)
    assert chunk is not None
    assert (chunk.start_offset, chunk.end_offset) == (padding, padding + len(data))
    assert CROMFSHandler in BUILTIN_HANDLERS


@pytest.mark.parametrize("endian", ["little", "big"])
def test_upstream_generator_images(endian, tmp_path):
    source = FIXTURES / endian / "__input__/sample.cromfs"
    with File.from_path(source) as file:
        image = CromFS(file)
        assert len(list(image.entries())) == 6
    reports = CromFSExtractor().extract(source, tmp_path)
    assert not reports.reports
    assert (
        tmp_path / "nested/message.txt"
    ).read_bytes() == b"Hello from NuttX CROMFS!\n" * 60
    assert len((tmp_path / "raw.bin").read_bytes()) == 1024
    assert (tmp_path / "empty.txt").read_bytes() == b""
    assert (tmp_path / "empty-dir").is_dir()
    assert (tmp_path / "caf\u00e9.txt").read_bytes() == b"Unicode filename\n"


@pytest.mark.parametrize(
    "compressed, expected",
    [
        (b"\x02abc", b"abc"),
        (b"\x00a\x20\x00", b"aaaa"),
        (b"\x00a\xe0\x02\x00", b"a" * 12),
    ],
)
def test_lzf_literals_and_overlapping_references(compressed, expected):
    assert decompress_lzf(compressed, len(expected)) == expected


@pytest.mark.parametrize(
    "compressed, size",
    [
        (b"\x02a", 3),
        (b"\x02abc", 2),
        (b"\x02abc", 4),
        (b"\xe0", 4),
        (b"\xe0\x01", 4),
        (b"\x20", 4),
        (b"\x20\x00", 3),
        (b"\x00a\x20\x01", 4),
        (b"\x00a\x20\x00", 3),
    ],
)
def test_invalid_lzf(compressed, size):
    with pytest.raises(InvalidInputFormat):
        decompress_lzf(compressed, size)


@pytest.mark.parametrize("size", [1, 4, 19, 20, 41])
def test_truncated_image(size):
    with pytest.raises((InvalidInputFormat, EOFError, SeekError)):
        parse(make_image()[:size]).parse()


@pytest.mark.parametrize(
    "offset, fmt, value",
    [
        (4, "H", 0),
        (4, "H", 100),
        (8, "I", 0),
        (8, "I", 5000),
        (12, "I", 20),
        (16, "I", 0),
        (16, "I", 65536),
        (20, "H", stat.S_IFREG),
        (22, "H", 1),
        (24, "I", 0),
        (24, "I", 5000),
        (36, "I", 42),
    ],
)
def test_invalid_volume_and_root(offset, fmt, value):
    data = make_image()
    struct.pack_into("<" + fmt, data, offset, value)
    with pytest.raises((InvalidInputFormat, EOFError, SeekError)):
        parse(data).parse()


@pytest.mark.parametrize(
    "name", [b"../escape", b"/absolute", b"a\\b", b"", b".", b"..", b"a" * 256]
)
def test_reject_invalid_names(name):
    image = parse(make_image(name=name))
    with pytest.raises(InvalidInputFormat):
        list(image.entries())


def test_reject_unterminated_name():
    data = make_image(payload=b"", name=b"file")
    data[-1] = ord("x")
    with pytest.raises(InvalidInputFormat):
        list(parse(data).entries())


@pytest.mark.parametrize("offset, value", [(32, 20), (54, 42)])
def test_reject_peer_cycles(offset, value):
    data = make_image()
    struct.pack_into("<I", data, offset, value)
    with pytest.raises(InvalidInputFormat, match="cycle"):
        list(parse(data).entries())


def test_reject_directory_cycle():
    data = make_image()
    struct.pack_into("<H", data, 42, stat.S_IFDIR)
    struct.pack_into("<I", data, 58, 20)
    with pytest.raises(InvalidInputFormat, match="cycle"):
        list(parse(data).entries())


@pytest.mark.parametrize(
    "block",
    [
        b"XX\0\0\x05hello",
        b"ZV\x02\0\x05hello",
        b"ZV\0\0\0",
        b"ZV\0\0\x06hello!",
        b"ZV\0\0\x05hi",
        b"ZV\x01\0\x02",
        b"ZV\x01\0\x02\0\x05\x20\x00",
    ],
)
def test_invalid_blocks(block):
    image = parse(make_image(block=block))
    with pytest.raises(InvalidInputFormat):
        list(image.chunks(image.node(42)))


def test_file_exceeds_block_count():
    data = make_image()
    struct.pack_into("<H", data, 6, 0)
    image = parse(data)
    with pytest.raises(InvalidInputFormat, match="block count"):
        list(image.chunks(image.node(42)))


def test_empty_files_have_no_blocks():
    image = parse(make_image(payload=b""))
    assert list(image.chunks(image.node(42))) == []


def add_link(data, name=b"alias", target=42):
    offset = len(data)
    struct.pack_into("<I", data, 54, offset)
    data.extend(
        struct.pack("<HHIIII", stat.S_IFLNK | 0o555, 0, offset + 20, 0, 0, target)
    )
    data.extend(name + b"\0")
    struct.pack_into("<H", data, 4, 3)
    struct.pack_into("<I", data, 12, len(data))
    return offset


def test_extract_file_hard_link(tmp_path):
    data = make_image()
    add_link(data)
    source = tmp_path / "image.cromfs"
    source.write_bytes(data)
    destination = tmp_path / "output"
    destination.mkdir()
    result = CromFSExtractor().extract(source, destination)
    assert not result.reports
    assert (destination / "alias").read_bytes() == b"hello"
    assert (destination / "alias").stat().st_ino == (destination / "file").stat().st_ino


def test_reject_hard_link_cycle():
    data = make_image()
    offset = add_link(data)
    struct.pack_into("<I", data, offset + 16, offset)
    with pytest.raises(InvalidInputFormat, match="cycle"):
        parse(data).resolve(offset)


def test_reject_hard_link_to_directory_opener():
    with pytest.raises(InvalidInputFormat, match="directory opener"):
        parse(make_image()).resolve(20)


def test_empty_filesystem():
    data = (
        struct.pack(
            "<IHHIIIHHIIII",
            MAGIC,
            1,
            0,
            20,
            42,
            512,
            stat.S_IFLNK | 0o555,
            0,
            40,
            0,
            0,
            20,
        )
        + b".\0"
    )
    assert list(parse(data).entries()) == []


def test_mixed_compressed_and_raw_blocks():
    data = make_image(
        payload=b"aaaahello",
        block=b"ZV\x01\0\x04\0\x04\x00a\x20\x00ZV\0\0\x05hello",
    )
    struct.pack_into("<H", data, 6, 2)
    image = parse(data)
    assert b"".join(image.chunks(image.node(42))) == b"aaaahello"


def test_block_count_exceeded():
    image = parse(make_image(payload=b"ab", block=b"ZV\0\0\x01aZV\0\0\x01b"))
    with pytest.raises(InvalidInputFormat, match="block count exceeded"):
        list(image.chunks(image.node(42)))


def test_duplicate_paths():
    data = make_image()
    add_link(data, name=b"file")
    with pytest.raises(InvalidInputFormat, match="Duplicate"):
        list(parse(data).entries())


@pytest.mark.parametrize(
    "offset, fmt, value", [(42, "H", stat.S_IFCHR), (44, "H", 1), (4, "H", 1)]
)
def test_invalid_nonroot_node(offset, fmt, value):
    data = make_image()
    struct.pack_into("<" + fmt, data, offset, value)
    with pytest.raises(InvalidInputFormat):
        list(parse(data).entries())


def test_hard_link_chain():
    data = make_image()
    first = add_link(data)
    second = add_link(data, name=b"second", target=first)
    struct.pack_into("<H", data, 4, 4)
    node = parse(data).resolve(second)
    assert node.offset == 42
    assert stat.S_ISREG(node.mode)


def test_extract_unlisted_hard_link_target(tmp_path):
    data = make_image()
    offset = add_link(data)
    struct.pack_into("<I", data, 32, offset)
    struct.pack_into("<I", data, 54, 0)
    source = tmp_path / "image"
    source.write_bytes(data)
    output = tmp_path / "output"
    output.mkdir()
    result = CromFSExtractor().extract(source, output)
    assert not result.reports
    assert (output / "alias").read_bytes() == b"hello"
    assert not (output / "file").exists()


def test_extract_directory_alias(tmp_path):
    data = make_image(payload=b"")
    struct.pack_into("<H", data, 42, stat.S_IFDIR | 0o555)
    struct.pack_into("<I", data, 58, 0)
    add_link(data)
    source = tmp_path / "image"
    source.write_bytes(data)
    output = tmp_path / "output"
    output.mkdir()
    result = CromFSExtractor().extract(source, output)
    assert not result.reports
    assert (output / "alias").is_symlink()
    assert (output / "alias").resolve() == output / "file"


def test_reject_unreachable_directory_alias(tmp_path):
    data = make_image(payload=b"")
    struct.pack_into("<H", data, 42, stat.S_IFDIR | 0o555)
    struct.pack_into("<I", data, 58, 0)
    offset = add_link(data)
    struct.pack_into("<I", data, 32, offset)
    struct.pack_into("<I", data, 54, 0)
    source = tmp_path / "image"
    source.write_bytes(data)
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(InvalidInputFormat, match="unreachable"):
        CromFSExtractor().extract(source, output)


@pytest.mark.parametrize("field, value", [(0, 0), (12, 5000)])
def test_finder_rejects_invalid_magic_and_image_overflow(field, value, task_result):
    data = make_image()
    struct.pack_into("<I", data, field, value)
    with File.from_bytes(data) as file:
        assert search_chunks(file, file.size(), (CROMFSHandler,), task_result) == []
    assert not task_result.reports


def test_block_cannot_read_following_firmware_bytes():
    data = make_image()
    struct.pack_into("<I", data, 12, len(data) - 5)
    image = parse(data)
    with pytest.raises(InvalidInputFormat, match="past the image"):
        list(image.chunks(image.node(42)))


def test_short_payload_read_raises_eof():
    image = parse(make_image()[:-4])
    with pytest.raises(EOFError, match="Truncated"):
        list(image.chunks(image.node(42)))


def test_entries_expose_node_offsets_paths_and_tree_parents():
    with File.from_path(FIXTURES / "little/__input__/sample.cromfs") as file:
        image = CromFS(file)
        entries = list(image.entries())
        entry = next(
            node for node in entries if node.path == Path("nested/message.txt")
        )
        assert entry.name == Path("message.txt")
        assert image.tree[str(entry.offset)].data is entry
        assert image.tree[str(entry.parent_offset)].data.path == Path("nested")
        assert list(image.entries()) == entries


def test_forward_hard_link_preserves_file_identity(tmp_path):
    data = make_image()
    offset = add_link(data)
    # Place the alias before its target in the physical peer chain.
    struct.pack_into("<I", data, 32, offset)
    struct.pack_into("<I", data, offset + 12, 42)
    struct.pack_into("<I", data, 54, 0)
    source = tmp_path / "image"
    source.write_bytes(data)
    output = tmp_path / "output"
    output.mkdir()
    CromFSExtractor().extract(source, output)
    assert (output / "alias").read_bytes() == b"hello"
    assert (output / "alias").stat().st_ino == (output / "file").stat().st_ino


def test_forward_directory_alias(tmp_path):
    data = make_image(payload=b"")
    struct.pack_into("<H", data, 42, stat.S_IFDIR | 0o555)
    struct.pack_into("<I", data, 58, 0)
    offset = add_link(data)
    struct.pack_into("<I", data, 32, offset)
    struct.pack_into("<I", data, offset + 12, 42)
    struct.pack_into("<I", data, 54, 0)
    source = tmp_path / "image"
    source.write_bytes(data)
    output = tmp_path / "output"
    output.mkdir()
    result = CromFSExtractor().extract(source, output)
    assert not result.reports
    assert (output / "alias").is_symlink()
    assert (output / "alias").resolve() == output / "file"
