from __future__ import annotations

import io
import math
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from unblob.file_utils import (
    Endian,
    FileSystem,
    InvalidInputFormat,
    StructParser,
)
from unblob.models import (
    Extractor,
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass
class MinixInode:
    i_mode: int
    i_nlinks: int
    i_uid: int
    i_gid: int
    i_size: int
    i_time: int | None
    i_atime: int | None
    i_mtime: int | None
    i_ctime: int | None
    i_zone: list[int]


@dataclass
class MinixDirEntry:
    inode: int
    name: bytes


# see linux/minix_fs.h
SUPERBLOCK_OFFSET = 0x400
ROOT_INODE_INDEX = 1
STATIC_BLOCK_SIZE = 1_024
HEADER_STRUCT = "minix_super_block"
INODE_V1_CDEF = """
    typedef struct minix_inode {
        uint16 i_mode;
        uint16 i_uid;
        uint32 i_size;
        uint32 i_time;
        uint8  i_gid;
        uint8  i_nlinks;
        uint16 i_zone[9];
    } minix_inode;
"""

INODE_V2_CDEF = """
    typedef struct minix_inode {
        uint16 i_mode;
        uint16 i_nlinks;
        uint16 i_uid;
        uint16 i_gid;
        uint32 i_size;
        uint32 i_atime;
        uint32 i_mtime;
        uint32 i_ctime;
        uint32 i_zone[10];
    } minix_inode;
"""

SUPERBLOCK_V1_CDEF = """
    typedef struct minix_super_block {
        uint16 s_ninodes;           /* number of inodes */
        uint16 s_nzones;            /* number of zones (v1 only) */
        uint16 s_imap_blocks;       /* inode map size (in blocks) */
        uint16 s_zmap_blocks;       /* zone map size (in blocks) */
        uint16 s_firstdatazone;     /* first zone containing file data */
        uint16 s_log_zone_size;     /* log_2(zone_size / blocks_size); 0 => zone_size == block_size */
        uint32 s_max_size;          /* max file size */
        uint16 s_magic;             /* minix magic */
        uint16 s_state;             /* mount state */
        uint32 s_zones;             /* number of zones (v2 only) */
    } minix_super_block;
"""

SUPERBLOCK_V3_CDEF = """
    typedef struct minix_super_block {
        uint32 s_ninodes;
        uint16 s_pad0;
        uint16 s_imap_blocks;
        uint16 s_zmap_blocks;
        uint16 s_firstdatazone;
        uint16 s_log_zone_size;
        uint16 s_pad1;
        uint32 s_max_size;
        uint32 s_zones;
        uint16 s_magic;
        uint16 s_pad2;
        uint16 s_blocksize;
        uint8  s_disk_version;
    } minix_super_block;
"""

DIR_V1_CDEF = """
    typedef struct minix_dir_entry {
        uint16 inode;
        char   name[];
    } minix_dir_entry;
"""

DIR_V3_CDEF = """
    typedef struct minix_dir_entry {
        uint32 inode;
        char   name[];
    } minix3_dir_entry;
"""

VERSION_TO_BIG_ENDIAN_MAGIC = {
    1: {0x13_7F, 0x13_8F},
    2: {0x24_68, 0x24_78},
    3: {0x4D_5A},
}
VERSION_TO_MAGIC_OFFSET = {
    1: 0x10,
    2: 0x10,
    3: 0x18,
}

VERSION_TO_C_DEFINITIONS = {
    1: INODE_V1_CDEF + SUPERBLOCK_V1_CDEF + DIR_V1_CDEF,
    2: INODE_V2_CDEF + SUPERBLOCK_V1_CDEF + DIR_V1_CDEF,
    3: INODE_V2_CDEF + SUPERBLOCK_V3_CDEF + DIR_V3_CDEF,
}


class MinixFS:
    def __init__(self, file: File, version: int, c_definitions: str):
        self.file = file
        self.version = version
        self.struct_parser = StructParser(c_definitions)
        self.file.seek(SUPERBLOCK_OFFSET, io.SEEK_SET)
        self.endianness = get_endianness(file, version)
        self.superblock = self.struct_parser.parse(HEADER_STRUCT, file, self.endianness)
        block_size = get_block_size(self.superblock)
        imap_offset = 2 * block_size
        zmap_offset = imap_offset + self.superblock.s_imap_blocks * block_size
        self.inode_offset = zmap_offset + self.superblock.s_zmap_blocks * block_size
        self.zone_size = (block_size << self.superblock.s_log_zone_size) & 0xFF_FF_FF_FF
        self.inode_size = self.struct_parser.cparser_le.minix_inode.size
        self.zone_ptr_size = self.struct_parser.cparser_le.minix_inode.fields[
            "i_zone"
        ].type.type.size
        dirent_inode_size = self.struct_parser.cparser_le.minix_dir_entry.fields[
            "inode"
        ].type.size
        self.dir_entry_size = self._get_name_len() + dirent_inode_size

    def _get_name_len(self) -> int:
        lower_magic: int = self.superblock.s_magic & 0x00FF
        if lower_magic in {0x7F, 0x68}:
            return 14  # v1/v2
        if lower_magic in {0x8F, 0x78}:
            return 30  # v1/v2
        if lower_magic == 0x5A:
            return 60  # v3
        raise InvalidInputFormat(f"Invalid magic: {self.superblock.s_magic:x}")

    def _read_zone_data(self, zone_index: int) -> bytes:
        self.file.seek(zone_index * self.zone_size, io.SEEK_SET)
        return self.file.read(self.zone_size)

    def _get_zone_pointers(self, zone_index: int) -> list[int]:
        data = self._read_zone_data(zone_index)
        ptr_fmt = "H" if self.zone_ptr_size == 2 else "I"
        count = self.zone_size // self.zone_ptr_size
        endianness_fmt = "<" if self.endianness == Endian.LITTLE else ">"
        return list(struct.unpack(f"{endianness_fmt}{count}{ptr_fmt}", data))

    def _stream_file_data(self, inode: MinixInode) -> Iterator[bytes]:
        remaining = inode.i_size
        for zone_data in self._iter_zones(inode.i_zone):
            chunk = zone_data[:remaining]
            remaining -= len(chunk)
            yield chunk
            if remaining <= 0:
                break

    def _iter_zones(self, zones: list[int]) -> Iterator[bytes]:
        # Data zones are a bit complicated. See e.g. https://osblog.stephenmarz.com/ch10.html
        # for a more detailed explanation.
        yield from self._read_zones(zones[:7])  # direct zones 0-6:
        if zones[7] != 0:  # indirect zone 7:
            yield from self._read_zones([zones[7]], 1)
        if zones[8] != 0:  # doubly indirect zone 8:
            yield from self._read_zones([zones[8]], 2)
        if len(zones) == 10 and zones[9] != 0:  # triply indirect zone 9 (V2/V3 only)
            yield from self._read_zones([zones[9]], 3)

    def _read_zones(
        self, zone_index_list: list[int], indirectness: int = 0
    ) -> Iterator[bytes]:
        for index in zone_index_list:
            if index == 0:
                break
            if indirectness > 0:
                zone_pointers = self._get_zone_pointers(index)
                yield from self._read_zones(zone_pointers, indirectness - 1)
            else:
                yield self._read_zone_data(index)

    def _read_directory(self, inode: MinixInode) -> Iterator[MinixDirEntry]:
        for zone_data in self._stream_file_data(inode):
            for i in range(0, len(zone_data), self.dir_entry_size):
                raw_entry = self.struct_parser.parse(
                    "minix_dir_entry",
                    zone_data[i : i + self.dir_entry_size],
                    self.endianness,
                )
                yield MinixDirEntry(inode=raw_entry.inode, name=raw_entry.name)

    def _read_inode(self, index: int) -> MinixInode:
        if not 1 <= index <= self.superblock.s_ninodes:
            raise InvalidInputFormat(f"Invalid inode number: {index}")
        offset = self.inode_offset + (index - 1) * self.inode_size
        self.file.seek(offset, io.SEEK_SET)
        raw_inode = self.struct_parser.parse("minix_inode", self.file, self.endianness)
        if self.version == 1:
            return MinixInode(
                i_mode=raw_inode.i_mode,
                i_nlinks=raw_inode.i_nlinks,
                i_uid=raw_inode.i_uid,
                i_gid=raw_inode.i_gid,
                i_size=raw_inode.i_size,
                i_time=raw_inode.i_time,
                i_atime=None,
                i_mtime=None,
                i_ctime=None,
                i_zone=list(raw_inode.i_zone),
            )
        return MinixInode(
            i_mode=raw_inode.i_mode,
            i_nlinks=raw_inode.i_nlinks,
            i_uid=raw_inode.i_uid,
            i_gid=raw_inode.i_gid,
            i_size=raw_inode.i_size,
            i_time=None,
            i_atime=raw_inode.i_atime,
            i_mtime=raw_inode.i_mtime,
            i_ctime=raw_inode.i_ctime,
            i_zone=list(raw_inode.i_zone),
        )

    def extract(self, fs: FileSystem, inode=None, path: Path = Path()):  # noqa: C901
        if not inode:
            try:
                inode = self._read_inode(ROOT_INODE_INDEX)
                if inode is None:
                    raise InvalidInputFormat("Root inode is empty")
                if not stat.S_ISDIR(inode.i_mode):
                    raise InvalidInputFormat("Root entries should be directories")
            except EOFError as error:
                raise InvalidInputFormat("File system is empty") from error

        for entry in self._read_directory(inode):
            if entry.name in (b".", b"..") or entry.inode < 1:
                continue
            entry_path = path / entry.name.decode("utf-8", errors="replace")
            entry_inode = self._read_inode(entry.inode)

            if stat.S_ISREG(entry_inode.i_mode):
                fs.write_chunks(entry_path, self._stream_file_data(entry_inode))

            elif stat.S_ISLNK(entry_inode.i_mode):
                contents = b"".join(self._stream_file_data(entry_inode))
                link_target = contents.decode("utf-8", errors="replace")
                fs.create_symlink(Path(link_target), entry_path)

            elif stat.S_ISFIFO(entry_inode.i_mode):
                fs.mkfifo(entry_path, mode=entry_inode.i_mode)

            elif stat.S_ISCHR(entry_inode.i_mode) or stat.S_ISBLK(entry_inode.i_mode):
                fs.mknod(entry_path, mode=entry_inode.i_mode)

            elif stat.S_ISDIR(entry_inode.i_mode):
                fs.mkdir(entry_path, parents=True, exist_ok=True)
                self.extract(fs, entry_inode, entry_path)


class MinixFSExtractor(Extractor):
    def __init__(self, version: int):
        self.version = version
        self.c_definitions = self._get_c_definitions()

    def _get_c_definitions(self) -> str:
        cdefs = VERSION_TO_C_DEFINITIONS.get(self.version)
        if not cdefs:
            raise ValueError(f"Unsupported MINIX FS version: {self.version}")
        return cdefs

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            minix = MinixFS(file, self.version, self.c_definitions)
            minix.extract(fs)


def get_endianness(file: File, version: int) -> Endian:
    offset = VERSION_TO_MAGIC_OFFSET[version]
    start = file.tell()
    file.seek(start + offset, io.SEEK_SET)
    magic_bytes = file.read(2)
    file.seek(start, io.SEEK_SET)
    if len(magic_bytes) < 2:
        raise InvalidInputFormat("Not enough bytes to read MINIX magic.")
    magic_be = int.from_bytes(magic_bytes, byteorder="big", signed=False)
    magic_le = int.from_bytes(magic_bytes, byteorder="little", signed=False)
    magics = VERSION_TO_BIG_ENDIAN_MAGIC[version]
    if magic_be in magics:
        return Endian.BIG
    if magic_le in magics:
        return Endian.LITTLE
    raise InvalidInputFormat(f"Invalid MINIX magic: 0x{magic_be:04x}")


def get_block_size(superblock) -> int:
    return getattr(superblock, "s_blocksize", STATIC_BLOCK_SIZE)


class _MinixFSHandlerBase(StructHandler):
    VERSION = 1
    HEADER_STRUCT = "minix_super_block"
    PATTERN_MATCH_OFFSET = -SUPERBLOCK_OFFSET

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        version = getattr(cls, "VERSION", None)
        if version:
            cls.EXTRACTOR = MinixFSExtractor(version=version)
            cls.C_DEFINITIONS = VERSION_TO_C_DEFINITIONS[version]

    def _get_zone_count(self, header) -> int:
        return header.s_nzones

    def validate_header(self, header, file: File, block_size: int) -> None:  # noqa: C901
        if header.s_ninodes < 1:
            raise InvalidInputFormat("Invalid inode count")
        if header.s_imap_blocks < 1:
            raise InvalidInputFormat("Invalid inode map block count")
        if header.s_zmap_blocks < 1:
            raise InvalidInputFormat("Invalid zone map block count")
        if header.s_max_size == 0:
            raise InvalidInputFormat("Invalid max file size")
        # according to https://www.minix3.org/doc/A-312.html valid blocksizes for v3 are 1, 2, 4 and 8 KiB
        if self.VERSION == 3 and header.s_blocksize not in {
            2**x for x in range(10, 14)
        }:
            raise InvalidInputFormat("Invalid block size")
        if header.s_log_zone_size > 10:
            # The default log_zone_size is 0 (meaning zone_size == block_size). Though there does not seem to
            # be a hard cap on this value, values larger than 10 (2**10 = 1024 blocks per zone) are not realistic
            raise InvalidInputFormat("Invalid log zone size")
        zone_count = header.s_zones or header.s_nzones
        if zone_count < 1:
            raise InvalidInputFormat("Invalid zone count")

        blocks_per_zone = 2**header.s_log_zone_size
        total_size = zone_count * blocks_per_zone * block_size
        if total_size > file.size():
            raise InvalidInputFormat("larger than the file size")
        inode_size = 32 if self.VERSION == 1 else 64
        inodes_per_block = block_size // inode_size
        first_data_block = (
            2  # boot block + superblock
            + header.s_imap_blocks
            + header.s_zmap_blocks
            + math.ceil(header.s_ninodes / inodes_per_block)
        )
        first_data_zone = math.ceil(first_data_block / blocks_per_zone)
        if header.s_firstdatazone != first_data_zone:
            raise InvalidInputFormat("Invalid first data zone")

        if self._get_zone_count(header) == 0:
            raise InvalidInputFormat("Invalid zone count")

    def is_valid_header(self, header, file: File, block_size: int) -> bool:
        try:
            self.validate_header(header, file, block_size)
        except InvalidInputFormat:
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(start_offset + SUPERBLOCK_OFFSET, io.SEEK_SET)
        endianness = get_endianness(file, self.VERSION)
        superblock = self.parse_header(file, endianness)

        # TODO: should probably be moved to MinixFS and rename MinixFS to MinixFSParser,
        # with a get_end_offset() function.

        block_size = get_block_size(superblock)
        self.validate_header(superblock, file, block_size)

        zone_size = 2**superblock.s_log_zone_size
        zone_count = self._get_zone_count(superblock)
        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + zone_count * zone_size * block_size,
        )


class MinixFSv1Handler(_MinixFSHandlerBase):
    NAME = "minix_fs_v1"
    PATTERNS = [
        # the magic comes at offset 0x10 in the header
        # the field that comes after this (s_state) indicates the FS state (1 -> valid; 2 -> error).
        # A value of 0 has been seen in the wild, but is not documented.
        # There are two variants with the only difference being the maximum name length (0x7f -> 14; 0x8f -> 30)
        HexString("[16] (7f | 8f) 13 (00 | 01 | 02) 00 [2] 00 00 00 00"),  # LE
        HexString("[16] 13 (7f | 8f) 00 (00 | 01 | 02) [2] 00 00 00 00"),  # BE
    ]
    VERSION = 1

    DOC = HandlerDoc(
        name="MINIX FS (v1)",
        description="MINIX FS is a simple file system format designed as the filesystem of MINIX. MINIX is a UNIX-like operating system, originally developed by Andrew S. Tanenbaum for educational purposes.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="Official website",
                url="https://www.minix3.org/",
            ),
            Reference(
                title="Linux headers (minix_fs.h)",
                url="https://github.com/torvalds/linux/blob/master/include/uapi/linux/minix_fs.h",
            ),
            Reference(
                title="Official tool for creating MINIX filesystems",
                url="https://github.com/Stichting-MINIX-Research-Foundation/minix/tree/master/minix/usr.sbin/mkfs.mfs",
            ),
        ],
        limitations=[],
    )


class MinixFSv2Handler(MinixFSv1Handler):
    NAME = "minix_fs_v2"
    PATTERNS = [
        # v2 also has two variants regarding the maximum name length (0x68 -> 14; 0x78 -> 30)
        HexString("[16] (68 | 78) 24 (00 | 01 | 02) 00 [4] 00 00 00 00"),  # LE
        HexString("[16] 24 (68 | 78) 00 (00 | 01 | 02) [4] 00 00 00 00"),  # BE
    ]
    VERSION = 2

    def _get_zone_count(self, header) -> int:
        return header.s_zones

    DOC = HandlerDoc(
        name="MINIX FS (v2)",
        description="MINIX FS is a simple file system format designed as the filesystem of MINIX. MINIX is a UNIX-like operating system, originally developed by Andrew S. Tanenbaum for educational purposes.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="Official website",
                url="https://www.minix3.org/",
            ),
            Reference(
                title="Linux headers (minix_fs.h)",
                url="https://github.com/torvalds/linux/blob/master/include/uapi/linux/minix_fs.h",
            ),
            Reference(
                title="Official tool for creating MINIX filesystems",
                url="https://github.com/Stichting-MINIX-Research-Foundation/minix/tree/master/minix/usr.sbin/mkfs.mfs",
            ),
        ],
        limitations=[],
    )


class MinixFSv3Handler(MinixFSv2Handler):
    NAME = "minix_fs_v3"
    PATTERNS = [
        HexString("[4] 00 00 [18] 5a 4d 00 00"),  # LE
        HexString("[4] 00 00 [18] 4d 5a 00 00"),  # BE
    ]
    VERSION = 3

    DOC = HandlerDoc(
        name="MINIX FS (v3)",
        description="MINIX FS is a simple file system format designed as the filesystem of MINIX. MINIX is a UNIX-like operating system, originally developed by Andrew S. Tanenbaum for educational purposes.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="Official website",
                url="https://www.minix3.org/",
            ),
            Reference(
                title="Linux headers (minix_fs.h)",
                url="https://github.com/torvalds/linux/blob/master/include/uapi/linux/minix_fs.h",
            ),
            Reference(
                title="Official tool for creating MINIX filesystems",
                url="https://github.com/Stichting-MINIX-Research-Foundation/minix/tree/master/minix/usr.sbin/mkfs.mfs",
            ),
        ],
        limitations=[],
    )
