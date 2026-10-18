from __future__ import annotations

import io
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
    Reference,
    Regex,
    ValidChunk,
)
from ...report import ExtractionProblem

if TYPE_CHECKING:
    from collections.abc import Iterator

MAGIC = 0x4D4F5243
MAX_NAME_SIZE = 256
ROOT_ID = -1

# https://github.com/apache/nuttx/blob/6bdd71565ad4d0095b73f09ab81c4f570b2aeec5/tools/gencromfs.c
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
        uint32 file_size;
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

    def __post_init__(self):
        if self.padding:
            raise InvalidInputFormat("Invalid CROMFS node padding")
        if self.name in (Path("."), Path("..")):
            if not stat.S_ISLNK(self.mode):
                raise InvalidInputFormat("Invalid CROMFS directory link")
            return
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
        file.seek(start_offset, io.SEEK_SET)
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
        header_size = self.header.size
        node_size = _STRUCT_PARSER.cparser_le.cromfs_node.size
        if (
            not self.header.node_count
            or self.size < header_size + node_size + 2
            or self.header.node_count > (self.size - header_size) // (node_size + 2)
            or not header_size <= self.header.root_offset <= self.size - node_size
        ):
            raise InvalidInputFormat("Invalid CROMFS volume header")

    def node(self, offset: int) -> CromFSNode:
        if offset not in self.nodes:
            if len(self.nodes) >= self.header.node_count:
                raise InvalidInputFormat("CROMFS node count exceeded")
            self.file.seek(self.start_offset + offset, io.SEEK_SET)
            header = _STRUCT_PARSER.parse("cromfs_node", self.file, self.endian)
            name_start = self.start_offset + header.name_offset
            name_end = min(name_start + MAX_NAME_SIZE, self.start_offset + self.size)
            name, separator, _ = self.file[name_start:name_end].partition(b"\0")
            if not separator or not name:
                raise InvalidInputFormat("Unterminated CROMFS filename")
            self.nodes[offset] = CromFSNode(
                offset=offset,
                mode=header.mode,
                name=Path(name.decode("utf-8", errors="surrogateescape")),
                size=header.file_size,
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
                # A peer is the next sibling in the same directory.
                peer = self.node(node.peer_offset)
                peer.parent_offset = node.parent_offset
                pending.append(peer)
            if node.name in (Path("."), Path("..")):
                continue
            parent = self.tree[str(node.parent_offset)].data
            node.path = (parent.path if parent else Path()) / node.name
            if node.path in paths:
                raise InvalidInputFormat("Duplicate CROMFS path")
            paths.add(node.path)
            self.tree.create_node(
                identifier=str(node.offset),
                parent=str(node.parent_offset),
                data=node,
            )
            if stat.S_ISDIR(node.mode) and node.data_offset:
                child = self.node(node.data_offset)
                child.parent_offset = node.offset
                pending.append(child)
        self._parsed = True

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
                return node
            if node.name in (Path("."), Path("..")):
                raise InvalidInputFormat("CROMFS hard link targets a directory opener")
            offset = node.data_offset

    def chunks(self, node: CromFSNode) -> Iterator[bytes]:
        remaining = node.size
        offset = node.data_offset
        blocks = 0
        while remaining:
            self.file.seek(self.start_offset + offset, io.SEEK_SET)
            # LZF stores block lengths in network byte order in either volume endian.
            header = _STRUCT_PARSER.parse("lzf_raw_header", self.file, Endian.BIG)
            if header.magic != b"ZV" or header.kind not in (0, 1):
                raise InvalidInputFormat("Invalid CROMFS LZF block header")
            size = header.length
            if header.kind == 1:
                self.file.seek(self.start_offset + offset, io.SEEK_SET)
                header = _STRUCT_PARSER.parse(
                    "lzf_compressed_header",
                    self.file,
                    Endian.BIG,
                )
                size = header.uncompressed_size
            if (
                not 0 < size <= min(self.header.block_size, remaining)
                or not header.length
            ):
                raise InvalidInputFormat("Invalid CROMFS LZF block size")
            blocks += 1
            if blocks > self.header.block_count:
                raise InvalidInputFormat("CROMFS block count exceeded")
            data_start = self.start_offset + offset + header.size
            data_end = min(data_start + header.length, self.start_offset + self.size)
            data = self.file[data_start:data_end]
            if len(data) != header.length:
                raise EOFError("Truncated CROMFS block")
            yield decompress_lzf(data, size) if header.kind == 1 else data
            offset += header.size + header.length
            remaining -= size

    def extract(self, fs: FileSystem):
        written: dict[int, Path] = {}
        links: list[CromFSNode] = []
        for node in self.entries():
            if stat.S_ISDIR(node.mode):
                fs.mkdir(node.path, parents=True, exist_ok=True)
            elif stat.S_ISREG(node.mode):
                self.extract_file(node, node.path, fs, written)
            elif stat.S_ISLNK(node.mode):
                links.append(node)
            else:
                fs.record_problem(
                    ExtractionProblem(
                        problem=f"Unsupported CROMFS node mode {oct(node.mode)}.",
                        resolution="Skipped.",
                        path=str(node.path),
                    )
                )
        for node in links:
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
            self.extract_file(target, node.path, fs, written)
        elif stat.S_ISDIR(target.mode):
            if not self.tree.contains(str(target.offset)):
                raise InvalidInputFormat("CROMFS directory link target is unreachable")
            fs.create_symlink(
                Path(os.path.relpath(target.path, node.path.parent)), node.path
            )
        else:
            fs.record_problem(
                ExtractionProblem(
                    problem=f"Unsupported CROMFS link target mode {oct(target.mode)}.",
                    resolution="Skipped.",
                    path=str(node.path),
                )
            )


class CromFSExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            CromFS(file).extract(fs)
        return ExtractResult(reports=fs.problems)


class CROMFSHandler(Handler):
    NAME = "cromfs"
    PATTERNS = [
        Regex(r"\x43\x52\x4f\x4d[\x00-\xff]{12}\x00\x02\x00\x00"),
        Regex(r"\x4d\x4f\x52\x43[\x00-\xff]{12}\x00\x00\x02\x00"),
    ]
    EXTRACTOR = CromFSExtractor()
    DOC = HandlerDoc(
        name="NuttX CROMFS",
        description="NuttX CROMFS is a read-only embedded file system with independently LZF-compressed blocks. Both little-endian and big-endian images are supported.",
        handler_type=HandlerType.FILESYSTEM,
        vendor="Apache",
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
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        image = CromFS(file, start_offset)
        image.root_node()
        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + image.size
        )
