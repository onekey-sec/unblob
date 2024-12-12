import io
import os
import stat
import struct
from enum import IntEnum, unique
from pathlib import Path
from typing import Optional

from structlog import get_logger

from ...file_utils import (
    Endian,
    FileSystem,
    InvalidInputFormat,
    read_until_past,
    round_up,
)
from ...models import (
    Extractor,
    ExtractResult,
    File,
    HexString,
    StructHandler,
    ValidChunk,
)

logger = get_logger()


STRING_ALIGNMENT = 16
MAX_LINUX_PATH_LENGTH = 0xFF
MAX_UINT32 = 0x100000000


WORLD_RW = 0o666
WORLD_RWX = 0o777
ROMFS_HEADER_SIZE = 512
ROMFS_SIGNATURE = b"-rom1fs-"


@unique
class FSType(IntEnum):
    HARD_LINK = 0
    DIRECTORY = 1
    FILE = 2
    SYMLINK = 3
    BLOCK_DEV = 4
    CHAR_DEV = 5
    SOCKET = 6
    FIFO = 7


def valid_checksum(content: bytes) -> bool:
    """Apply a RomFS checksum and returns whether it's valid or not."""
    total = 0

    # unalign content will lead to unpacking errors down the line
    if len(content) % 4 != 0:
        return False

    for i in range(0, len(content), 4):
        total = (total + struct.unpack(">L", content[i : i + 4])[0]) % MAX_UINT32
    return total == 0


def get_string(file: File) -> bytes:
    """Read a 16 bytes aligned, null terminated string."""
    filename = b""
    counter = 0
    while b"\x00" not in filename and counter < MAX_LINUX_PATH_LENGTH:
        filename += file.read(STRING_ALIGNMENT)
        counter += STRING_ALIGNMENT
    return filename.rstrip(b"\x00")


class FileHeader:
    addr: int
    next_filehdr: int
    spec_info: int
    fs_type: FSType
    executable: bool
    size: int
    checksum: int
    filename: bytes
    depth: int = -1
    parent: Optional["FileHeader"] = None
    start_offset: int
    end_offset: int
    file: File

    def __init__(self, addr: int, file: File):
        self.addr = addr
        fs_typeexec_next = struct.unpack(">L", file.read(4))[0]
        self.next_filehdr = fs_typeexec_next & ~0b1111
        self.fs_type = FSType(fs_typeexec_next & 0b0111)
        self.executable = fs_typeexec_next & 0b1000
        self.spec_info = struct.unpack(">I", file.read(4))[0]
        self.size = struct.unpack(">I", file.read(4))[0]
        self.checksum = struct.unpack(">I", file.read(4))[0]
        self.filename = get_string(file)
        self.start_offset = file.tell()
        self.file = file

    def valid_checksum(self) -> bool:
        current_position = self.file.tell()
        try:
            self.file.seek(self.addr, io.SEEK_SET)
            filename_len = len(self.filename)
            header_size = 16 + round_up(filename_len, 16)
            return valid_checksum(self.file.read(header_size))
        finally:
            self.file.seek(current_position, io.SEEK_SET)

    @property
    def content(self) -> bytes:
        """Returns the file content. Applicable to files and symlinks."""
        try:
            self.file.seek(self.start_offset, io.SEEK_SET)
            return self.file.read(self.size)
        finally:
            self.file.seek(-self.size, io.SEEK_CUR)

    @property
    def mode(self) -> int:
        """Permission mode.

        It is assumed to be world readable if executable bit is set,
        and world executable otherwise.  Handle mode for both block
        device and character devices too.
        """
        mode = WORLD_RWX if self.executable else WORLD_RW
        mode |= stat.S_IFBLK if self.fs_type == FSType.BLOCK_DEV else 0x0
        mode |= stat.S_IFCHR if self.fs_type == FSType.CHAR_DEV else 0x0
        return mode

    @property
    def dev(self) -> int:
        """Raw device number if block device or character device, zero otherwise."""
        if self.fs_type in [FSType.BLOCK_DEV, FSType.CHAR_DEV]:
            major = self.spec_info >> 16
            minor = self.spec_info & 0xFFFF
            return os.makedev(major, minor)
        return 0

    @property
    def path(self) -> Path:
        """Returns the full path of this file, up to the RomFS root."""
        current_node = self
        current_path = Path()
        while current_node is not None:
            current_path = Path(current_node.filename.decode("utf-8")).joinpath(
                current_path
            )
            current_node = current_node.parent
        return current_path

    def __repr__(self):
        return (
            f"FileHeader<next_filehdr:{self.next_filehdr}, type:{self.fs_type},"
            f" executable:{self.executable}, spec_info:{self.spec_info},"
            f" size:{self.size}, checksum:{self.checksum}, filename:{self.filename}>"
        )


class RomFSError(Exception):
    pass


class RomFSHeader:
    signature: bytes
    full_size: int
    checksum: int
    volume_name: bytes
    eof: int
    file: File
    end_offset: int
    inodes: dict[int, "FileHeader"]
    fs: FileSystem

    def __init__(
        self,
        file: File,
        fs: FileSystem,
    ):
        self.file = file
        self.file.seek(0, io.SEEK_END)
        self.eof = self.file.tell()
        self.file.seek(0, io.SEEK_SET)

        if self.eof < ROMFS_HEADER_SIZE:
            raise RomFSError("File too small to hold ROMFS")

        self.signature = self.file.read(8)
        self.full_size = struct.unpack(">I", self.file.read(4))[0]
        self.checksum = struct.unpack(">I", self.file.read(4))[0]
        self.volume_name = get_string(self.file)
        self.header_end_offset = self.file.tell()
        self.inodes = {}

        self.fs = fs

    def valid_checksum(self) -> bool:
        current_position = self.file.tell()
        try:
            self.file.seek(0, io.SEEK_SET)
            return valid_checksum(self.file.read(ROMFS_HEADER_SIZE))
        finally:
            self.file.seek(current_position, io.SEEK_SET)

    def validate(self):
        if self.signature != ROMFS_SIGNATURE:
            raise RomFSError("Invalid RomFS signature")
        if self.full_size > self.eof:
            raise RomFSError("ROMFS size is greater than file size")
        if not self.valid_checksum():
            raise RomFSError("Invalid checksum")

    def is_valid_addr(self, addr):
        """Validate that an inode address is valid.

        Inodes addresses must be 16 bytes aligned and placed within
        the RomFS on file.
        """
        return (self.header_end_offset <= addr <= self.eof) and (addr % 16 == 0)

    def is_recursive(self, addr) -> bool:
        return addr in self.inodes

    def recursive_walk(self, addr: int, parent: Optional[FileHeader] = None):
        while self.is_valid_addr(addr) is True:
            addr = self.walk_dir(addr, parent)

    def walk_dir(self, addr: int, parent: Optional[FileHeader] = None):
        self.file.seek(addr, io.SEEK_SET)
        file_header = FileHeader(addr, self.file)
        file_header.parent = parent

        if not file_header.valid_checksum():
            raise RomFSError(f"Invalid file CRC at addr {addr:0x}.")

        logger.debug("walking dir", addr=addr, file=file_header)

        if file_header.filename not in [b".", b".."]:
            if (
                file_header.fs_type == FSType.DIRECTORY
                and file_header.spec_info != 0x0
                and not self.is_recursive(addr)
            ):
                self.inodes[addr] = file_header
                self.recursive_walk(file_header.spec_info, file_header)
            self.inodes[addr] = file_header
        return file_header.next_filehdr

    def create_symlink(self, output_path: Path, inode: FileHeader):
        target_path = Path(inode.content.decode("utf-8"))
        self.fs.create_symlink(src=target_path, dst=output_path)

    def create_hardlink(self, output_path: Path, inode: FileHeader):
        if inode.spec_info in self.inodes:
            target_path = self.inodes[inode.spec_info].path
            self.fs.create_hardlink(dst=output_path, src=target_path)
        else:
            logger.warning("Invalid hard link target", inode_key=inode.spec_info)

    def create_inode(self, inode: FileHeader):
        output_path = inode.path
        logger.info("dumping inode", inode=inode, output_path=str(output_path))

        if inode.fs_type == FSType.HARD_LINK:
            self.create_hardlink(output_path, inode)
        elif inode.fs_type == FSType.SYMLINK:
            self.create_symlink(output_path, inode)
        elif inode.fs_type == FSType.DIRECTORY:
            self.fs.mkdir(output_path, mode=inode.mode, exist_ok=True)
        elif inode.fs_type == FSType.FILE:
            self.fs.write_bytes(output_path, inode.content)
        elif inode.fs_type in [FSType.BLOCK_DEV, FSType.CHAR_DEV]:
            self.fs.mknod(output_path, mode=inode.mode, device=inode.dev)
        elif inode.fs_type == FSType.FIFO:
            self.fs.mkfifo(output_path, mode=inode.mode)

    def dump_fs(self):
        def inodes(*inode_types):
            return sorted(
                (v for v in self.inodes.values() if v.fs_type in inode_types),
                key=lambda inode: inode.path,
            )

        # order of file object creation is important
        sorted_inodes = (
            inodes(FSType.FILE, FSType.DIRECTORY, FSType.FIFO, FSType.SOCKET)
            + inodes(FSType.BLOCK_DEV, FSType.CHAR_DEV)
            + inodes(FSType.SYMLINK, FSType.HARD_LINK)
        )

        for inode in sorted_inodes:
            self.create_inode(inode)

    def __str__(self):
        return f"signature: {self.signature}\nfull_size: {self.full_size}\nchecksum: {self.checksum}\nvolume_name: {self.volume_name}"


class RomfsExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as f:
            header = RomFSHeader(f, fs)
            header.validate()
            header.recursive_walk(header.header_end_offset, None)
            header.dump_fs()
            return ExtractResult(reports=fs.problems)


class RomFSFSHandler(StructHandler):
    NAME = "romfs"

    PATTERNS = [
        # '-rom1fs-'
        HexString("2D 72 6F 6D 31 66 73 2d")
    ]

    C_DEFINITIONS = r"""
        struct romfs_header {
            char magic[8];
            uint32 full_size;
            uint32 checksum;
        }
    """
    HEADER_STRUCT = "romfs_header"
    EXTRACTOR = RomfsExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        if not valid_checksum(file.read(512)):
            raise InvalidInputFormat("Invalid RomFS checksum.")

        file.seek(-512, io.SEEK_CUR)

        # Every multi byte value must be in big endian order.
        header = self.parse_header(file, Endian.BIG)

        # The zero terminated name of the volume, padded to 16 byte boundary.
        get_string(file)

        # seek filesystem size (number of accessible bytes in this fs)
        # from the actual end of the header
        file.seek(header.full_size, io.SEEK_CUR)

        # Another thing to note is that romfs works on file headers and data
        # aligned to 16 byte boundaries, but most hardware devices and the block
        # device drivers are unable to cope with smaller than block-sized data.
        # To overcome this limitation, the whole size of the file system must be
        # padded to an 1024 byte boundary.
        read_until_past(file, b"\x00")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.tell(),
        )
