"""NuttX CROMFS, as written by tools/gencromfs.c."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from treelib.tree import Tree

from ...file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    get_endian,
)
from ...models import (
    Extractor,
    ExtractResult,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    ValidChunk,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

MAGIC = 0x4D4F5243
HEADER_SIZE = 20
NODE_SIZE = 20
MAX_NAME_SIZE = 256
LZF_RAW_HEADER_SIZE = 5
LZF_COMPRESSED_HEADER_SIZE = 7
ROOT_ID = -1

_STRUCT_PARSER = StructParser(r"""
    struct cromfs_volume {
        uint32 magic;
        uint16 node_count;
        uint16 block_count;
        uint32 root_offset;
        uint32 image_size;
        uint32 block_size;
    };
    struct cromfs_node {
        uint16 mode;
        uint16 padding;
        uint32 name_offset;
        uint32 size;
        uint32 peer_offset;
        uint32 data_offset;
    };
    struct lzf_raw_header {
        char magic[2];
        uint8 kind;
        uint16 length;
    };
    struct lzf_compressed_header {
        char magic[2];
        uint8 kind;
        uint16 length;
        uint16 uncompressed_size;
    };
""")


def decompress_lzf(data: bytes, size: int) -> bytes:
    """Decode one bounded LZF block, including overlapping back references."""
    output = bytearray()
    position = 0
    while position < len(data):
        control = data[position]
        position += 1
        if control < 32:
            length = control + 1
            if position + length > len(data) or len(output) + length > size:
                raise InvalidInputFormat("Invalid CROMFS LZF literal")
            output.extend(data[position : position + length])
            position += length
        else:
            length, distance, position = _lzf_reference(data, position, control)
            if distance > len(output) or len(output) + length > size:
                raise InvalidInputFormat("Invalid CROMFS LZF reference")
            for _ in range(length):
                output.append(output[-distance])
    if len(output) != size:
        raise InvalidInputFormat("CROMFS LZF size mismatch")
    return bytes(output)


def _lzf_reference(data: bytes, position: int, control: int) -> tuple[int, int, int]:
    length = control >> 5
    if length == 7:
        if position == len(data):
            raise InvalidInputFormat("Truncated CROMFS LZF length")
        length += data[position]
        position += 1
    if position == len(data):
        raise InvalidInputFormat("Truncated CROMFS LZF reference")
    distance = ((control & 31) << 8) + data[position] + 1
    return length + 2, distance, position + 1


@dataclass
class CromFSNode:
    offset: int
    mode: int
    name: Path
    size: int
    peer_offset: int
    data_offset: int
    padding: int = 0
    parent_offset: int = ROOT_ID
    path: Path = field(default_factory=Path)

    def validate(self):
        if self.padding or stat.S_IFMT(self.mode) not in (
            stat.S_IFREG,
            stat.S_IFDIR,
            stat.S_IFLNK,
        ):
            raise InvalidInputFormat("Invalid CROMFS node type")
        if (
            not self.name.name
            or len(self.name.parts) != 1
            or self.name.is_absolute()
            or "\\" in str(self.name)
            or self.name == Path("..")
        ):
            raise InvalidInputFormat("Invalid CROMFS filename")


class CromFS:
    def __init__(self, file: File, start_offset: int = 0):
        self.file = file
        self.start_offset = start_offset
        file.seek(start_offset)
        self.endian = get_endian(file, MAGIC)
        self.header = _STRUCT_PARSER.parse("cromfs_volume", file, self.endian)
        self.validate_header()
        self.nodes: dict[int, CromFSNode] = {}
        self.tree = Tree()
        self.tree.create_node(identifier=str(ROOT_ID))
        self._parsed = False

    @property
    def size(self) -> int:
        return self.header.image_size

    def validate_header(self):
        if (
            not self.header.node_count
            or self.size < HEADER_SIZE + NODE_SIZE + 2
            or not 0 < self.header.block_size <= 0xFFFF
            or self.header.node_count > (self.size - HEADER_SIZE) // (NODE_SIZE + 2)
            or not HEADER_SIZE <= self.header.root_offset <= self.size - NODE_SIZE
        ):
            raise InvalidInputFormat("Invalid CROMFS volume header")

    def read_at(self, offset: int, size: int) -> bytes:
        # File protects seeks, but permits short reads. The volume boundary also
        # matters when unrelated firmware bytes follow an embedded image.
        if offset + size > self.size:
            raise InvalidInputFormat("CROMFS read extends past the image")
        self.file.seek(self.start_offset + offset)
        data = self.file.read(size)
        if len(data) != size:
            raise EOFError("Truncated CROMFS image")
        return data

    def node(self, offset: int) -> CromFSNode:
        if offset not in self.nodes:
            header = _STRUCT_PARSER.parse(
                "cromfs_node", self.read_at(offset, NODE_SIZE), self.endian
            )
            self.file.seek(self.start_offset + header.name_offset)
            # Only accept a terminator inside this image, even if firmware follows.
            name_data = self.file.read(MAX_NAME_SIZE).split(b"\0", 1)
            if (
                len(name_data) != 2
                or not name_data[0]
                or header.name_offset + len(name_data[0]) >= self.size
            ):
                raise InvalidInputFormat("Unterminated CROMFS filename")
            self.nodes[offset] = CromFSNode(
                offset=offset,
                mode=header.mode,
                name=Path(name_data[0].decode("utf-8", errors="surrogateescape")),
                size=header.size,
                peer_offset=header.peer_offset,
                data_offset=header.data_offset,
                padding=header.padding,
            )
        return self.nodes[offset]

    def root_node(self) -> CromFSNode:
        root = self.node(self.header.root_offset)
        if (
            root.name != Path(".")
            or not stat.S_ISLNK(root.mode)
            or root.padding
            or root.data_offset != root.offset
        ):
            raise InvalidInputFormat("Invalid CROMFS root node")
        return root

    def parse(self):
        if self._parsed:
            return
        root = self.root_node()
        pending = [root]
        visited: set[int] = set()
        paths: set[Path] = set()
        while pending:
            node = pending.pop()
            if node.offset in visited:
                raise InvalidInputFormat("CROMFS directory cycle or shared node")
            visited.add(node.offset)
            if node.peer_offset:
                peer = self.node(node.peer_offset)
                peer.parent_offset = node.parent_offset
                pending.append(peer)
            if node.name in (Path("."), Path("..")) and stat.S_ISLNK(node.mode):
                continue
            self.add_entry(node, paths)
            if stat.S_ISDIR(node.mode) and node.data_offset:
                child = self.node(node.data_offset)
                child.parent_offset = node.offset
                pending.append(child)
        if len(visited) > self.header.node_count:
            raise InvalidInputFormat("CROMFS node count exceeded")
        self._parsed = True

    def add_entry(self, node: CromFSNode, paths: set[Path]):
        node.validate()
        parent = self.tree[str(node.parent_offset)].data
        node.path = (parent.path if parent else Path()) / node.name
        if node.path in paths:
            raise InvalidInputFormat("Duplicate CROMFS path")
        paths.add(node.path)
        self.tree.create_node(
            identifier=str(node.offset), parent=str(node.parent_offset), data=node
        )

    def entries(self) -> Iterator[CromFSNode]:
        self.parse()
        for offset in self.tree.expand_tree(mode=Tree.DEPTH, sorting=False):
            node = self.tree[offset].data
            if node is not None:
                yield node

    def resolve(self, offset: int) -> CromFSNode:
        visited: set[int] = set()
        while True:
            if offset in visited:
                raise InvalidInputFormat("CROMFS hard link cycle")
            visited.add(offset)
            node = self.node(offset)
            if not stat.S_ISLNK(node.mode):
                node.validate()
                return node
            if node.name in (Path("."), Path("..")):
                raise InvalidInputFormat("CROMFS hard link targets a directory opener")
            offset = node.data_offset

    def chunks(self, node: CromFSNode) -> Iterator[bytes]:
        remaining = node.size
        offset = node.data_offset
        blocks = 0
        if remaining > self.header.block_count * self.header.block_size:
            raise InvalidInputFormat("CROMFS file exceeds volume block count")
        while remaining:
            header = _STRUCT_PARSER.parse(
                "lzf_raw_header", self.read_at(offset, LZF_RAW_HEADER_SIZE), Endian.BIG
            )
            if header.magic != b"ZV" or header.kind not in (0, 1):
                raise InvalidInputFormat("Invalid CROMFS LZF block header")
            header_size = LZF_RAW_HEADER_SIZE
            size = header.length
            if header.kind == 1:
                header = _STRUCT_PARSER.parse(
                    "lzf_compressed_header",
                    self.read_at(offset, LZF_COMPRESSED_HEADER_SIZE),
                    Endian.BIG,
                )
                header_size = LZF_COMPRESSED_HEADER_SIZE
                size = header.uncompressed_size
            if (
                not 0 < size <= min(self.header.block_size, remaining)
                or not header.length
            ):
                raise InvalidInputFormat("Invalid CROMFS LZF block size")
            blocks += 1
            if blocks > self.header.block_count:
                raise InvalidInputFormat("CROMFS block count exceeded")
            data = self.read_at(offset + header_size, header.length)
            yield decompress_lzf(data, size) if header.kind == 1 else data
            offset += header_size + header.length
            remaining -= size

    def extract(self, fs: FileSystem):
        written: dict[int, Path] = {}
        for node in self.entries():
            if stat.S_ISDIR(node.mode):
                fs.mkdir(node.path, parents=True, exist_ok=True)
            elif stat.S_ISREG(node.mode):
                self.extract_file(node, node.path, fs, written)
            else:
                self.extract_link(node, fs, written)

    def extract_file(
        self, node: CromFSNode, path: Path, fs: FileSystem, written: dict[int, Path]
    ):
        if node.offset not in written:
            fs.write_chunks(path, self.chunks(node))
            written[node.offset] = path
        elif written[node.offset] != path:
            fs.create_hardlink(written[node.offset], path)

    def extract_link(self, node: CromFSNode, fs: FileSystem, written: dict[int, Path]):
        target = self.resolve(node.data_offset)
        if stat.S_ISREG(target.mode):
            # The entire tree is known, so a forward target can be materialized
            # on demand instead of deferring every link to a second pass.
            path = target.path if self.tree.contains(str(target.offset)) else node.path
            self.extract_file(target, path, fs, written)
            self.extract_file(target, node.path, fs, written)
        else:
            if not self.tree.contains(str(target.offset)):
                raise InvalidInputFormat("CROMFS directory link target is unreachable")
            fs.create_symlink(
                Path(os.path.relpath(target.path, node.path.parent)), node.path
            )


class CromFSExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            CromFS(file).extract(fs)
        return ExtractResult(reports=fs.problems)


class CROMFSHandler(Handler):
    NAME = "cromfs"
    PATTERNS = [HexString("43 52 4F 4D"), HexString("4D 4F 52 43")]
    EXTRACTOR = CromFSExtractor()
    DOC = HandlerDoc(
        name="NuttX CROMFS",
        description="NuttX CROMFS is a read-only embedded file system with independently LZF-compressed blocks. Both little-endian and big-endian images are supported.",
        handler_type=HandlerType.FILESYSTEM,
        vendor="Apache NuttX",
        references=[
            Reference(
                title="NuttX CROMFS image generator",
                url="https://github.com/apache/nuttx/blob/master/tools/gencromfs.c",
            ),
            Reference(
                title="NuttX CROMFS implementation",
                url="https://github.com/apache/nuttx/blob/master/fs/cromfs/fs_cromfs.c",
            ),
        ],
        limitations=["Directory hard links are extracted as relative symbolic links."],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        image = CromFS(file, start_offset)
        image.root_node()
        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + image.size
        )
