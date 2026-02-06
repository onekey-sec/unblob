from __future__ import annotations

import io
import math
import stat
import struct
from pathlib import Path
from typing import TYPE_CHECKING, cast

from more_itertools import chunked

from unblob.file_utils import (
    Endian,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    get_endian_multi,
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

    from dissect.cstruct import Structure

    class Inode(Structure):
        i_mode: int
        i_size: int
        i_zone: list[int]

    class DirEntry(Structure):
        inode: int
        name: bytes

    class Superblock(Structure):
        s_ninodes: int
        s_nzones: int
        s_imap_blocks: int
        s_zmap_blocks: int
        s_firstdatazone: int
        s_log_zone_size: int
        s_max_size: int
        s_magic: int
        s_state: int
        s_zones: int
        s_blocksize: int


# see linux/minix_fs.h
SUPERBLOCK_OFFSET = 0x400
ROOT_INODE_INDEX = 1
STATIC_BLOCK_SIZE = 1_024
HEADER_STRUCT = "minix_super_block"
INODE_V1_CDEF = r"""
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


class _MinixFSExtractor(Extractor):
    C_DEFINITIONS = None
    VERSION = None

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            minix = MinixFS(file, self.VERSION, self.C_DEFINITIONS)
            minix.extract(fs)


class MinixFSv1Extractor(_MinixFSExtractor):
    C_DEFINITIONS = INODE_V1_CDEF + SUPERBLOCK_V1_CDEF + DIR_V1_CDEF
    VERSION = 1


class MinixFSv2Extractor(_MinixFSExtractor):
    C_DEFINITIONS = INODE_V2_CDEF + SUPERBLOCK_V1_CDEF + DIR_V1_CDEF
    VERSION = 2


class MinixFSv3Extractor(_MinixFSExtractor):
    C_DEFINITIONS = INODE_V2_CDEF + SUPERBLOCK_V3_CDEF + DIR_V3_CDEF
    VERSION = 3


def get_endianness(file: File, version: int) -> Endian:
    offset = VERSION_TO_MAGIC_OFFSET[version]
    file.seek(offset, io.SEEK_CUR)
    endianness = get_endian_multi(file, VERSION_TO_BIG_ENDIAN_MAGIC[version], 2)
    file.seek(-offset, io.SEEK_CUR)
    return endianness


def get_block_size(superblock: Superblock) -> int:
    return getattr(superblock, "s_blocksize", STATIC_BLOCK_SIZE)


class MinixFSv1Handler(StructHandler):
    NAME = "minix_fs_v1"
    PATTERNS = [
        # the magic comes at offset 0x10 in the header
        # the field that comes after this (s_state) indicates the FS state (1 -> valid; 2 -> error).
        # A value of 0 has been seen in the wild, but is not documented.
        # There are two variants with the only difference being the maximum name length (0x7f -> 14; 0x8f -> 30)
        HexString("[16] (7f | 8f) 13 (00 | 01 | 02) 00 [2] 00 00 00 00"),  # LE
        HexString("[16] 13 (7f | 8f) 00 (00 | 01 | 02) [2] 00 00 00 00"),  # BE
    ]
    EXTRACTOR = MinixFSv1Extractor()
    C_DEFINITIONS = EXTRACTOR.C_DEFINITIONS
    # the superblock is preceded by a 1 KiB boot sector (also part of the FS; can be empty)
    PATTERN_MATCH_OFFSET = -SUPERBLOCK_OFFSET
    HEADER_STRUCT = HEADER_STRUCT
    VERSION = 1

    DOC = HandlerDoc(
        name="MINIX FS",
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

    def _get_zone_count(self, header: Superblock) -> int:
        return header.s_nzones

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(start_offset + SUPERBLOCK_OFFSET, io.SEEK_SET)
        endianness = get_endianness(file, self.VERSION)
        superblock = cast("Superblock", self.parse_header(file, endianness))

        block_size = get_block_size(superblock)
        self._do_sanity_checks(superblock, file, block_size)

        zone_count = self._get_zone_count(superblock)
        if zone_count != 0:
            end_offset = (
                start_offset + zone_count * 2**superblock.s_log_zone_size * block_size
            )
            return ValidChunk(start_offset=start_offset, end_offset=end_offset)
        return None

    def _do_sanity_checks(self, header: Superblock, file: File, block_size: int):  # noqa: C901
        if header.s_ninodes < 1:
            raise InvalidInputFormat("Invalid inode count")
        if header.s_imap_blocks < 1:
            raise InvalidInputFormat("Invalid inode map block count")
        if header.s_zmap_blocks < 1:
            raise InvalidInputFormat("Invalid zone map block count")
        if header.s_max_size == 0:
            raise InvalidInputFormat("Invalid max file size: 0")
        # according to https://www.minix3.org/doc/A-312.html valid blocksizes for v3 are 1, 2, 4 and 8 KiB
        if self.VERSION == 3 and header.s_blocksize not in {
            2**x for x in range(10, 14)
        }:
            raise InvalidInputFormat(f"Invalid block size: {header.s_blocksize}")
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
            raise InvalidInputFormat("Zones are larger than the file size")
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


class MinixFSv2Handler(MinixFSv1Handler):
    NAME = "minix_fs_v2"
    PATTERNS = [
        # v2 also has two variants regarding the maximum name length (0x68 -> 14; 0x78 -> 30)
        HexString("[16] (68 | 78) 24 (00 | 01 | 02) 00 [4] 00 00 00 00"),  # LE
        HexString("[16] 24 (68 | 78) 00 (00 | 01 | 02) [4] 00 00 00 00"),  # BE
    ]
    VERSION = 2
    EXTRACTOR = MinixFSv2Extractor()
    C_DEFINITIONS = EXTRACTOR.C_DEFINITIONS

    def _get_zone_count(self, header) -> int:
        # s_nzones (16 bits) is replaced with s_zones (32 bits) in v2.
        # s_nzones should be 0 for v2 and s_zones should be 0 for v1.
        return header.s_zones


class MinixFSv3Handler(MinixFSv2Handler):
    NAME = "minix_fs_v3"
    PATTERNS = [
        HexString("[4] 00 00 [18] 5a 4d 00 00"),  # LE
        HexString("[4] 00 00 [18] 4d 5a 00 00"),  # BE
    ]
    VERSION = 3
    EXTRACTOR = MinixFSv3Extractor()
    C_DEFINITIONS = EXTRACTOR.C_DEFINITIONS


class MinixFS:
    def __init__(self, file: File, version: int, c_definitions: str):
        self.file = file
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
        ].type.size
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

    def _stream_file_data(self, inode: Inode) -> Iterator[bytes]:
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

    def _read_directory(self, inode: Inode) -> Iterator[DirEntry]:
        for zone_data in self._stream_file_data(inode):
            for dir_data in chunked(zone_data, self.dir_entry_size):
                if len(dir_data) < self.dir_entry_size:
                    # this should never happen, because zone_size should always be a multiple of dir_entry_size
                    break
                yield self.struct_parser.parse(
                    "minix_dir_entry", bytes(dir_data), self.endianness
                )

    def _read_inode(self, index: int) -> Inode:
        if not 1 <= index <= self.superblock.s_ninodes:
            raise InvalidInputFormat(f"Invalid inode number: {index}")
        offset = self.inode_offset + (index - 1) * self.inode_size
        self.file.seek(offset, io.SEEK_SET)
        return self.struct_parser.parse("minix_inode", self.file, self.endianness)

    def extract(self, fs: FileSystem, inode: Inode | None = None, path: Path = Path()):  # noqa: C901
        if not inode:
            try:
                inode = self._read_inode(ROOT_INODE_INDEX)
            except EOFError as error:
                raise InvalidInputFormat("File system is empty") from error
            if not self._is_dir(inode):
                raise InvalidInputFormat("Root entries should be directories")

        for entry in self._read_directory(inode):
            if entry.name in (b".", b"..") or entry.inode < 1:
                continue
            entry_path = path / entry.name.decode("utf-8", errors="replace")
            entry_inode = self._read_inode(entry.inode)

            if self._is_file(entry_inode):
                fs.write_chunks(entry_path, self._stream_file_data(entry_inode))

            elif self._is_symlink(entry_inode):
                contents = b"".join(self._stream_file_data(entry_inode))
                link_target = contents.decode("utf-8", errors="replace")
                fs.create_symlink(Path(link_target), entry_path)

            elif self._is_fifo(entry_inode):
                fs.mkfifo(entry_path, mode=entry_inode.i_mode)

            elif self._is_char_device(entry_inode) or self._is_block_device(
                entry_inode
            ):
                fs.mknod(entry_path, mode=entry_inode.i_mode)

            elif self._is_dir(entry_inode):
                fs.mkdir(entry_path, parents=True, exist_ok=True)
                self.extract(fs, entry_inode, entry_path)

    @staticmethod
    def _is_dir(inode: Inode) -> bool:
        return stat.S_ISDIR(inode.i_mode)

    @staticmethod
    def _is_file(inode: Inode) -> bool:
        return stat.S_ISREG(inode.i_mode)

    @staticmethod
    def _is_symlink(inode: Inode) -> bool:
        return stat.S_ISLNK(inode.i_mode)

    @staticmethod
    def _is_fifo(inode: Inode) -> bool:
        return stat.S_ISFIFO(inode.i_mode)

    @staticmethod
    def _is_block_device(inode: Inode) -> bool:
        return stat.S_ISBLK(inode.i_mode)

    @staticmethod
    def _is_char_device(inode: Inode) -> bool:
        return stat.S_ISCHR(inode.i_mode)
