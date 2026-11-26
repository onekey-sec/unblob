import contextlib
import dataclasses
import io
import zlib
from enum import IntFlag
from pathlib import Path

import zstandard
from structlog import get_logger

from unblob.file_utils import (
    DEFAULT_BUFSIZE,
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    convert_int32,
    convert_int64,
    iterate_file,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)
from unblob.report import ExtractionProblem

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct rcc_header {
        char magic[4];         /* "qres" */
        uint32 version;
        uint32 tree_offset;
        uint32 data_offset;
        uint32 names_offset;
    } rcc_header_t;

    typedef struct rcc_tree_node_header {
        uint32 name_offset;    /* into the names section */
        uint16 flags;
    } rcc_tree_node_header_t;

    typedef struct rcc_dir_node {
        uint32 child_count;
        uint32 first_child;    /* index of the first child node */
    } rcc_dir_node_t;

    typedef struct rcc_file_node {
        uint16 country;        /* QLocale::Country */
        uint16 language;       /* QLocale::Language */
        uint32 data_offset;    /* into the data section */
    } rcc_file_node_t;

    typedef struct rcc_name_entry {
        uint16 length;
        uint32 hash;
        char name[length * 2];
    } rcc_name_entry_t;
"""


class NodeFlag(IntFlag):
    # qtbase/src/corelib/io/qresource.cpp: QResourceRoot flags
    RAW = 0
    COMPRESSED_ZLIB = 0x01
    DIRECTORY = 0x02
    COMPRESSED_ZSTD = 0x04


KNOWN_NODE_FLAGS = (
    NodeFlag.COMPRESSED_ZLIB | NodeFlag.DIRECTORY | NodeFlag.COMPRESSED_ZSTD
)
KNOWN_FILE_FLAGS = NodeFlag.COMPRESSED_ZLIB | NodeFlag.COMPRESSED_ZSTD

HEADER_LEN_V1_V2 = 20
HEADER_LEN_V3 = 24
NODE_BASE_LEN = 14
NODE_TIMESTAMP_LEN = 8  # version >= 2 nodes append a last-modified field


@dataclasses.dataclass(frozen=True)
class RccNode:
    index: int
    name: str
    flags: NodeFlag
    parent_index: int | None
    children: tuple[int, ...] = ()
    # file nodes only
    data_offset: int = 0  # absolute offset of the uint32 payload length
    data_len: int = 0  # size of the stored payload (compressed, if flagged)
    mtime_ms: int = 0

    @property
    def is_dir(self) -> bool:
        return bool(self.flags & NodeFlag.DIRECTORY)


@dataclasses.dataclass(frozen=True)
class RccFile:
    version: int
    nodes: tuple[RccNode, ...]
    # offset right after the furthest section extent, relative to the
    # resource start: also the end of the resource
    extent: int


class RccParser:
    """Parses and validates an RCC resource tree."""

    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def parse(self, file: File, offset: int) -> RccFile:
        header, header_len, node_len = self._parse_header(file, offset)

        # every node index must live inside the file: bound what a
        # directory can reference before walking it
        max_nodes = (file.size() - (offset + header.tree_offset)) // node_len
        if max_nodes < 1:
            raise InvalidInputFormat("RCC resource without a root node.")

        nodes: list[RccNode] = []
        seen: set[int] = set()
        extent = header_len
        stack: list[tuple[int, int | None]] = [(0, None)]
        while stack:
            index, parent_index = stack.pop()
            if index in seen:
                raise InvalidInputFormat("RCC tree node referenced twice.")
            if index >= max_nodes:
                raise InvalidInputFormat(f"RCC node index out of bounds: {index}.")
            node, node_extent = self._parse_node(
                file, offset, header, index, parent_index, node_len, max_nodes
            )
            seen.add(index)
            nodes.append(node)
            extent = max(extent, node_extent)
            stack.extend((child, index) for child in reversed(node.children))

        if not nodes[0].is_dir:
            raise InvalidInputFormat("RCC root node is not a directory.")

        return RccFile(header.version, tuple(nodes), extent)

    def _parse_header(self, file: File, offset: int) -> tuple:
        file.seek(offset, io.SEEK_SET)
        header = self._struct_parser.parse("rcc_header_t", file, Endian.BIG)

        if header.version >= 3:
            header_len = HEADER_LEN_V3
            file_flags = convert_int32(file.read(4), Endian.BIG)
            if file_flags & ~int(KNOWN_FILE_FLAGS):
                raise InvalidInputFormat(f"Unknown RCC feature flags: {file_flags:#x}.")
        else:
            header_len = HEADER_LEN_V1_V2

        for section_offset in (
            header.tree_offset,
            header.data_offset,
            header.names_offset,
        ):
            if section_offset < header_len:
                raise InvalidInputFormat(
                    f"RCC section offset overlaps the header: {section_offset:#x}."
                )

        node_len = NODE_BASE_LEN
        if header.version >= 2:
            node_len += NODE_TIMESTAMP_LEN

        return header, header_len, node_len

    def _parse_node(
        self,
        file: File,
        offset: int,
        header,
        index: int,
        parent_index: int | None,
        node_len: int,
        max_nodes: int,
    ) -> tuple[RccNode, int]:
        node_pos = offset + header.tree_offset + index * node_len
        file.seek(node_pos, io.SEEK_SET)
        node_header = self._struct_parser.parse(
            "rcc_tree_node_header_t", file, Endian.BIG
        )
        self._check_node_flags(node_header.flags)
        flags = NodeFlag(node_header.flags)
        extent = header.tree_offset + (index + 1) * node_len

        # the node body keeps the file position right after the header
        if flags & NodeFlag.DIRECTORY:
            body = self._struct_parser.parse("rcc_dir_node_t", file, Endian.BIG)
        else:
            body = self._struct_parser.parse("rcc_file_node_t", file, Endian.BIG)

        mtime_ms = 0
        if header.version >= 2:
            mtime_ms = convert_int64(file.read(NODE_TIMESTAMP_LEN), Endian.BIG)

        # the root node's name is ignored by Qt
        name = ""
        if index != 0:
            name, name_extent = self._read_name(
                file, offset, header, node_header.name_offset
            )
            extent = max(extent, name_extent)

        if flags & NodeFlag.DIRECTORY:
            if body.child_count > max_nodes - body.first_child:
                raise InvalidInputFormat(
                    f"RCC children out of bounds: {body.child_count} at {body.first_child}."
                )
            children = tuple(
                range(body.first_child, body.first_child + body.child_count)
            )
            node = RccNode(
                index, name, flags, parent_index, children=children, mtime_ms=mtime_ms
            )
        else:
            data_offset = offset + header.data_offset + body.data_offset
            data_len = self._read_data_len(file, data_offset)
            # zlib payloads must hold at least the 4-byte uncompressed
            # size prefix before the compressed stream
            if flags & NodeFlag.COMPRESSED_ZLIB and data_len < 4:
                raise InvalidInputFormat(
                    "RCC zlib payload smaller than its size prefix."
                )
            extent = max(extent, data_offset + 4 + data_len - offset)
            node = RccNode(
                index,
                name,
                flags=flags,
                parent_index=parent_index,
                data_offset=data_offset,
                data_len=data_len,
                mtime_ms=mtime_ms,
            )

        return node, extent

    @staticmethod
    def _check_node_flags(flags: int):
        if flags & ~int(KNOWN_NODE_FLAGS):
            raise InvalidInputFormat(f"Unknown RCC node flags: {flags:#x}.")
        if flags & NodeFlag.COMPRESSED_ZLIB and flags & NodeFlag.COMPRESSED_ZSTD:
            raise InvalidInputFormat("RCC node with two compression algorithms.")
        if flags & NodeFlag.DIRECTORY and flags & (
            NodeFlag.COMPRESSED_ZLIB | NodeFlag.COMPRESSED_ZSTD
        ):
            raise InvalidInputFormat("RCC directory node with compression flag.")

    def _read_name(
        self, file: File, offset: int, header, name_offset: int
    ) -> tuple[str, int]:
        name_pos = offset + header.names_offset + name_offset
        file.seek(name_pos, io.SEEK_SET)
        entry = self._struct_parser.parse("rcc_name_entry_t", file, Endian.BIG)
        try:
            name = entry.name.decode("utf-16-be")
        except UnicodeDecodeError as e:
            raise InvalidInputFormat("Invalid UTF-16 in RCC name.") from e
        if "\x00" in name or not name.strip("/") or name.strip("/") == ".":
            raise InvalidInputFormat(f"Invalid RCC node name: {name!r}.")
        return name, file.tell() - offset

    def _read_data_len(self, file: File, data_offset: int) -> int:
        file.seek(data_offset, io.SEEK_SET)
        # The computed chunk end is checked against the file size by core.
        return convert_int32(file.read(4), Endian.BIG)


class QtRccExtractor(Extractor):
    def __init__(self):
        self._parser = RccParser()

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            resource = self._parser.parse(file, 0)
            directories: dict[int | None, Path] = {None: Path()}
            used_names: dict[Path, set[str]] = {}
            for node in resource.nodes:
                if node.parent_index not in directories:
                    # A failed directory is skipped together with its descendants.
                    continue
                parent = directories[node.parent_index]
                if node.is_dir:
                    dir_path = parent
                    if node.name:
                        dir_path = parent / self._unique_name(
                            used_names.setdefault(parent, set()), fs, parent, node.name
                        )
                        try:
                            fs.mkdir(dir_path, exist_ok=True)
                        except OSError as exc:
                            fs.record_problem(
                                ExtractionProblem(
                                    problem=f"Cannot create RCC directory {dir_path}: {exc}",
                                    resolution="Skipped with contents.",
                                    path=str(dir_path),
                                )
                            )
                            continue
                    directories[node.index] = dir_path
                else:
                    out_path = parent / self._unique_name(
                        used_names.setdefault(parent, set()), fs, parent, node.name
                    )
                    self._extract_file(fs, file, node, out_path)
        return ExtractResult(reports=fs.problems)

    def _unique_name(
        self, used: set[str], fs: FileSystem, parent: Path, name: str
    ) -> str:
        candidate = name
        suffix = 2
        while candidate in used:
            candidate = f"{name}-{suffix}"
            suffix += 1
        if candidate != name:
            fs.record_problem(
                ExtractionProblem(
                    problem=f"Duplicate RCC entry name: {parent / name}",
                    resolution=f"Extracted as {candidate}.",
                    path=str(parent / name),
                )
            )
        used.add(candidate)
        return candidate

    def _extract_file(self, fs: FileSystem, file: File, node: RccNode, out_path: Path):
        payload_offset = node.data_offset + 4
        try:
            if node.flags == NodeFlag.COMPRESSED_ZLIB:
                self._extract_zlib(fs, file, node, out_path, payload_offset)
            elif node.flags == NodeFlag.COMPRESSED_ZSTD:
                self._extract_zstd(fs, file, node, out_path, payload_offset)
            elif node.flags == NodeFlag.RAW:
                # Qt stores uncompressed resources as length-prefixed raw bytes.
                fs.carve(out_path, file, payload_offset, node.data_len)

            if node.mtime_ms:
                fs.utime(out_path, (node.mtime_ms / 1000, node.mtime_ms / 1000))
        except OSError as e:
            # e.g. names containing characters illegal on this filesystem,
            # or hitting filesystem limits (name length, depth)
            with contextlib.suppress(OSError):
                fs.unlink(out_path)
            fs.record_problem(
                ExtractionProblem(
                    problem=f"Cannot write RCC entry {out_path}: {e}",
                    resolution="Skipped.",
                    path=str(out_path),
                )
            )

    def _extract_zlib(
        self,
        fs: FileSystem,
        file: File,
        node: RccNode,
        out_path: Path,
        payload_offset: int,
    ):
        # zlib payloads carry a 4-byte big-endian uncompressed size prefix
        file.seek(payload_offset, io.SEEK_SET)
        declared_size = convert_int32(file.read(4), Endian.BIG)
        decompressor = zlib.decompressobj()
        try:
            with fs.open(out_path, "wb+") as outfile:
                produced, trailing_data = self._write_zlib(
                    file, payload_offset + 4, node.data_len - 4, decompressor, outfile
                )
        except zlib.error as e:
            fs.unlink(out_path)
            fs.record_problem(
                ExtractionProblem(
                    problem=f"Invalid zlib payload in RCC entry: {e}",
                    resolution="Skipped.",
                    path=str(out_path),
                )
            )
            return
        if produced != declared_size:
            fs.record_problem(
                ExtractionProblem(
                    problem=(
                        f"RCC entry size mismatch: declared "
                        f"{declared_size}, got {produced}"
                    ),
                    resolution="Extracted anyway.",
                    path=str(out_path),
                )
            )
        if not decompressor.eof:
            fs.record_problem(
                ExtractionProblem(
                    problem="Truncated zlib stream in RCC entry",
                    resolution="Extracted anyway.",
                    path=str(out_path),
                )
            )
        elif trailing_data:
            fs.record_problem(
                ExtractionProblem(
                    problem="Trailing data after zlib stream in RCC entry",
                    resolution="Extracted anyway.",
                    path=str(out_path),
                )
            )

    @staticmethod
    def _write_zlib(file, offset, size, decompressor, outfile) -> tuple[int, bool]:
        produced = 0
        remaining = size
        for chunk in iterate_file(file, offset, size):
            remaining -= len(chunk)
            pending = chunk
            while True:
                out = decompressor.decompress(pending, max_length=DEFAULT_BUFSIZE)
                produced += len(out)
                outfile.write(out)
                if decompressor.eof:
                    return produced, bool(decompressor.unused_data or remaining)
                pending = decompressor.unconsumed_tail
                if not pending and len(out) < DEFAULT_BUFSIZE:
                    break
        return produced, False

    def _extract_zstd(
        self,
        fs: FileSystem,
        file: File,
        node: RccNode,
        out_path: Path,
        payload_offset: int,
    ):
        try:
            decompressor = zstandard.ZstdDecompressor().decompressobj()
            with fs.open(out_path, "wb+") as outfile:
                for chunk in iterate_file(file, payload_offset, node.data_len):
                    outfile.write(decompressor.decompress(chunk))
        except zstandard.ZstdError as e:
            fs.unlink(out_path)
            fs.record_problem(
                ExtractionProblem(
                    problem=f"Invalid zstd payload in RCC entry: {e}",
                    resolution="Skipped.",
                    path=str(out_path),
                )
            )
            return
        if not decompressor.eof:
            fs.record_problem(
                ExtractionProblem(
                    problem="Truncated zstd stream in RCC entry",
                    resolution="Extracted anyway.",
                    path=str(out_path),
                )
            )
        elif decompressor.unused_data:
            fs.record_problem(
                ExtractionProblem(
                    problem="Trailing data after zstd stream in RCC entry",
                    resolution="Extracted anyway.",
                    path=str(out_path),
                )
            )


class QtRccHandler(StructHandler):
    NAME = "qt_rcc"

    PATTERNS = [
        HexString(
            """
            71 72 65 73 00 00 00 ( 01 | 02 | 03 )
        """
        ),
    ]
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "rcc_header_t"
    EXTRACTOR = QtRccExtractor()

    DOC = HandlerDoc(
        name="Qt RCC",
        description=(
            "Qt binary resource files produced by the Resource Compiler "
            "(rcc -binary) bundle a directory tree of files, optionally "
            "zlib or zstd compressed, into a single blob. The handler "
            "walks the resource tree and extracts every file with its "
            "resource path, decompressing payloads where flagged."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="Qt",
        references=[
            Reference(
                title="Qt Resource System",
                url="https://doc.qt.io/qt-6/resources.html",
            ),
            Reference(
                title="QResource format implementation in qtbase",
                url="https://codebrowser.dev/qt5/qtbase/src/corelib/io/qresource.cpp.html",
            ),
        ],
        limitations=[],
    )

    _parser = RccParser()

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        resource = self._parser.parse(file, start_offset)
        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + resource.extent,
        )
