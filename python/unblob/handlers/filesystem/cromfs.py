"""NuttX CROMFS, as written by tools/gencromfs.c."""

from __future__ import annotations

import os
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ...file_utils import File, FileSystem, InvalidInputFormat
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


@dataclass(frozen=True)
class CromFSNode:
    mode: int
    name: str
    size: int
    peer: int
    data: int


class CromFS:
    def __init__(self, file: File, start_offset: int = 0):
        self.file = file
        self.start_offset = start_offset
        self.size = file.size() - start_offset
        magic = self.read(0, 4)
        if magic not in (b"CROM", b"MORC"):
            raise InvalidInputFormat("Invalid CROMFS magic")
        self.endian = "<" if magic == b"CROM" else ">"
        _, self.nnodes, self.nblocks, self.root, size, self.bsize = struct.unpack(
            self.endian + "IHHIII", self.read(0, HEADER_SIZE)
        )
        if (
            not self.nnodes
            or size < HEADER_SIZE + NODE_SIZE + 2
            or size > self.size
            or not 0 < self.bsize <= 0xFFFF
            or self.nnodes > (size - HEADER_SIZE) // (NODE_SIZE + 2)
        ):
            raise InvalidInputFormat("Invalid CROMFS volume header")
        self.size = size
        self.nodes: dict[int, CromFSNode] = {}
        root = self.node(self.root)
        if root.name != "." or not stat.S_ISLNK(root.mode) or root.data != self.root:
            raise InvalidInputFormat("Invalid CROMFS root node")

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise InvalidInputFormat("CROMFS offset outside image")
        self.file.seek(self.start_offset + offset)
        return self.file.read(size)

    def node(self, offset: int) -> CromFSNode:
        if offset in self.nodes:
            return self.nodes[offset]
        if offset < HEADER_SIZE or len(self.nodes) >= self.nnodes:
            raise InvalidInputFormat("Invalid CROMFS node offset or count")
        mode, pad, name_offset, size, peer, data = struct.unpack(
            self.endian + "HHIIII", self.read(offset, NODE_SIZE)
        )
        if pad or stat.S_IFMT(mode) not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK):
            raise InvalidInputFormat("Invalid CROMFS node type")
        if name_offset < HEADER_SIZE:
            raise InvalidInputFormat("Invalid CROMFS name offset")
        name_data = self.read(name_offset, min(MAX_NAME_SIZE, self.size - name_offset))
        name, separator, _ = name_data.partition(b"\0")
        if not separator or not name or b"/" in name or b"\\" in name:
            raise InvalidInputFormat("Invalid CROMFS filename")
        if name in (b".", b"..") and not stat.S_ISLNK(mode):
            raise InvalidInputFormat("Invalid CROMFS directory link")
        node = CromFSNode(mode, os.fsdecode(name), size, peer, data)
        self.nodes[offset] = node
        return node

    def entries(self) -> Iterator[tuple[int, CromFSNode, Path]]:
        """Walk physical directory entries without following hard links."""
        pending = [(self.root, Path())]
        visited: set[int] = set()
        paths: set[Path] = set()
        while pending:
            offset, parent = pending.pop()
            if not offset:
                continue
            if offset in visited:
                raise InvalidInputFormat("CROMFS directory cycle or shared node")
            visited.add(offset)
            node = self.node(offset)
            pending.append((node.peer, parent))
            if node.name in (".", ".."):
                self.node(node.data)
                continue
            path = parent / node.name
            if path in paths:
                raise InvalidInputFormat("Duplicate CROMFS path")
            paths.add(path)
            yield offset, node, path
            if stat.S_ISDIR(node.mode):
                pending.append((node.data, path))

    def resolve(self, offset: int) -> tuple[int, CromFSNode]:
        visited: set[int] = set()
        while True:
            if offset in visited:
                raise InvalidInputFormat("CROMFS hard link cycle")
            visited.add(offset)
            node = self.node(offset)
            if not stat.S_ISLNK(node.mode):
                return offset, node
            if node.name in (".", ".."):
                raise InvalidInputFormat("CROMFS hard link targets a directory opener")
            offset = node.data

    def chunks(self, node: CromFSNode) -> Iterator[bytes]:
        remaining = node.size
        offset = node.data
        blocks = 0
        if remaining > self.nblocks * self.bsize:
            raise InvalidInputFormat("CROMFS file exceeds volume block count")
        while remaining:
            magic, kind, length = struct.unpack(">2sBH", self.read(offset, 5))
            if magic != b"ZV" or kind not in (0, 1):
                raise InvalidInputFormat("Invalid CROMFS LZF block header")
            offset += 5
            size = length
            if kind == 1:
                size = struct.unpack(">H", self.read(offset, 2))[0]
                offset += 2
            if not 0 < size <= min(self.bsize, remaining) or not length:
                raise InvalidInputFormat("Invalid CROMFS LZF block size")
            blocks += 1
            if blocks > self.nblocks:
                raise InvalidInputFormat("CROMFS block count exceeded")
            data = self.read(offset, length)
            yield decompress_lzf(data, size) if kind == 1 else data
            offset += length
            remaining -= size


class CromFSExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            image = CromFS(file)
            paths: dict[int, Path] = {}
            links: list[tuple[CromFSNode, Path]] = []
            for offset, node, path in image.entries():
                paths[offset] = path
                if stat.S_ISDIR(node.mode):
                    fs.mkdir(path, parents=True, exist_ok=True)
                elif stat.S_ISREG(node.mode):
                    fs.write_chunks(path, image.chunks(node))
                else:
                    links.append((node, path))
            for link, path in links:
                offset, target = image.resolve(link.data)
                if stat.S_ISREG(target.mode):
                    if offset in paths:
                        fs.create_hardlink(paths[offset], path)
                    else:
                        fs.write_chunks(path, image.chunks(target))
                elif offset in paths:
                    fs.create_symlink(
                        Path(os.path.relpath(paths[offset], path.parent)), path
                    )
                else:
                    raise InvalidInputFormat(
                        "CROMFS directory link target is unreachable"
                    )
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
        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + image.size
        )
