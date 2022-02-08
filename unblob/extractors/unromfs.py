import io
import os
import shutil
import stat
import struct
from enum import IntEnum, unique
from pathlib import Path
from typing import Dict, Optional

import click
from structlog import get_logger

from ..cli_options import verbosity_option
from ..file_utils import round_up
from ..logging import configure_logger

logger = get_logger()

WORLD_RW = 0o666
WORLD_RWX = 0o777
ROMFS_HEADER_SIZE = 512
STRING_ALIGNMENT = 16
MAX_LINUX_PATH_LENGTH = 0xFF
MAX_UINT32 = 2 ** 32
ROMFS_SIGNATURE = b"-rom1fs-"


@unique
class FS_TYPE(IntEnum):
    HARD_LINK = 0
    DIRECTORY = 1
    FILE = 2
    SYMLINK = 3
    BLOCK_DEV = 4
    CHAR_DEV = 5
    SOCKET = 6
    FIFO = 7


def is_safe_path(basedir: Path, path: Path) -> bool:
    try:
        basedir.joinpath(path).resolve().relative_to(basedir.resolve())
    except ValueError:
        return False
    return True


def romfs_checksum(content: bytes) -> int:
    """Apply a RomFS checksum and returns whether it's valid or not."""
    total = 0

    # unalign content will lead to unpacking errors down the line
    if len(content) % 4 != 0:
        return -1

    for i in range(0, len(content), 4):
        total = (
            total + struct.unpack(">L", content[i : i + 4])[0]  # noqa: E203
        ) % MAX_UINT32
    return total


def get_string(file: io.BufferedIOBase) -> bytes:
    """Read a 16 bytes aligned, null terminated string."""
    filename = b""
    counter = 0
    while b"\x00" not in filename and counter < MAX_LINUX_PATH_LENGTH:
        filename += file.read(STRING_ALIGNMENT)
        counter += STRING_ALIGNMENT
    return filename.rstrip(b"\x00")


class FileHeader(object):
    addr: int
    next_filehdr: int
    spec_info: int
    type: FS_TYPE
    executable: bool
    size: int
    checksum: int
    filename: bytes
    depth: int = -1
    parent: Optional["FileHeader"] = None
    start_offset: int
    end_offset: int
    file: io.BufferedReader

    def __init__(self, addr: int, file: io.BufferedReader):
        self.addr = addr
        type_exec_next = struct.unpack(">L", file.read(4))[0]
        self.next_filehdr = type_exec_next & ~0b1111
        self.type = FS_TYPE(type_exec_next & 0b0111)
        self.executable = type_exec_next & 0b1000
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
            return romfs_checksum(self.file.read(header_size)) == 0
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
        """Permission mode is assumed to be world readable if executable bit is set, and world executable otherwise.
        Handle mode for both block device and character devices too.
        """
        mode = WORLD_RWX if self.executable else WORLD_RW
        mode |= stat.S_IFBLK if self.type == FS_TYPE.BLOCK_DEV else 0x0
        mode |= stat.S_IFCHR if self.type == FS_TYPE.CHAR_DEV else 0x0
        return mode

    @property
    def dev(self) -> int:
        """Returns raw device number if block device or character device, zero otherwise."""
        if self.type in [FS_TYPE.BLOCK_DEV, FS_TYPE.CHAR_DEV]:
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
            f"FileHeader<next_filehdr:{self.next_filehdr}, type:{self.type},"
            f" executable:{self.executable}, spec_info:{self.spec_info},"
            f" size:{self.size}, checksum:{self.checksum}, filename:{self.filename}>"
        )


class RomFSHeader(object):
    signature: bytes
    full_size: int
    checksum: int
    volume_name: bytes
    eof: int
    file: io.BufferedReader
    end_offset: int
    inodes: Dict[int, "FileHeader"]
    extract_root: Path
    force_overwrite: bool = False

    def __init__(
        self,
        file: io.BufferedReader,
        extract_root: Path,
        force_overwrite: bool = False,
    ):

        self.file = file
        self.file.seek(0, io.SEEK_END)
        self.eof = self.file.tell()
        self.file.seek(0, io.SEEK_SET)

        if self.eof < ROMFS_HEADER_SIZE:
            raise Exception("File too small to hold ROMFS")

        self.signature = self.file.read(8)
        self.full_size = struct.unpack(">I", self.file.read(4))[0]
        self.checksum = struct.unpack(">I", self.file.read(4))[0]
        self.volume_name = get_string(self.file)
        self.header_end_offset = self.file.tell()
        self.inodes = {}

        extract_root.mkdir()

        self.extract_root = extract_root
        self.force_overwrite = force_overwrite

    def valid_checksum(self) -> bool:
        current_position = self.file.tell()
        try:
            self.file.seek(0, io.SEEK_SET)
            return romfs_checksum(self.file.read(ROMFS_HEADER_SIZE)) == 0
        finally:
            self.file.seek(current_position, io.SEEK_SET)

    def validate(self):
        if self.signature != ROMFS_SIGNATURE:
            raise Exception("Invalid RomFS signature")
        if self.full_size > self.eof:
            raise Exception("ROMFS size is greater than file size")
        if not self.valid_checksum():
            raise Exception("Invalid checksum")

    def is_valid_addr(self, addr):
        """Validates that an inode address is valid. inodes addresses must be 16 bytes aligned and placed within the RomFS on file."""
        if (self.header_end_offset <= addr <= self.eof) and (addr % 16 == 0):
            return True
        return False

    def is_recursive(self, addr) -> bool:
        return True if addr in self.inodes else False

    def recursive_walk(self, addr: int, parent: FileHeader = None):
        while self.is_valid_addr(addr) is True:
            addr = self.walk_dir(addr, parent)

    def walk_dir(self, addr: int, parent: FileHeader = None):
        self.file.seek(addr, io.SEEK_SET)
        file_header = FileHeader(addr, self.file)
        file_header.parent = parent

        if not file_header.valid_checksum():
            raise Exception(f"Invalid file CRC at addr {addr:0x}.")

        logger.debug("walking dir", addr=addr, file=file_header)

        if file_header.filename not in [b".", b".."]:
            if file_header.type == FS_TYPE.DIRECTORY and file_header.spec_info != 0x0:
                if not self.is_recursive(addr):
                    self.inodes[addr] = file_header
                    self.recursive_walk(file_header.spec_info, file_header)
            self.inodes[addr] = file_header
        return file_header.next_filehdr

    def create_symlink(self, extract_root: Path, output_path: Path, inode: FileHeader):
        target = inode.content.decode("utf-8").lstrip("/")

        if target.startswith(".."):
            target_path = extract_root.joinpath(output_path.parent, target).resolve()
        else:
            target_path = extract_root.joinpath(target).resolve()

        if not is_safe_path(extract_root, target_path):
            logger.warn(
                "Path traversal attempt through symlink.", target_path=target_path
            )
            return
        # we create relative paths to make the output directory portable
        output_path.symlink_to(os.path.relpath(target_path, start=output_path.parent))

    def create_hardlink(self, extract_root: Path, link_path: Path, inode: FileHeader):

        if inode.spec_info in self.inodes:
            target = str(self.inodes[inode.spec_info].path).lstrip("/")
            target_path = extract_root.joinpath(target).resolve()

            # we don't need to check for potential traversal given that, if the inode
            # is in self.inodes, it already got verified in create_inode.
            try:
                os.link(target_path, link_path)
            except FileNotFoundError:
                logger.warn(
                    "Hard link target does not exist, discarding.",
                    target_path=target_path,
                    link_path=link_path,
                )
            except PermissionError:
                logger.warn(
                    "Not enough privileges to create hardlink to block/char device, discarding.",
                    target_path=target_path,
                    link_path=link_path,
                )
        else:
            logger.warn("Invalid hard link target", inode_key=inode.spec_info)

    def create_inode(self, extract_root: Path, inode: FileHeader):

        output_path = extract_root.joinpath(inode.path).resolve()
        if not is_safe_path(extract_root, inode.path):
            logger.warn("Path traversal attempt, discarding.", output_path=output_path)
            return
        logger.info("dumping inode", inode=inode, output_path=str(output_path))

        if inode.type == FS_TYPE.HARD_LINK:
            self.create_hardlink(extract_root, output_path, inode)
        elif inode.type == FS_TYPE.SYMLINK:
            self.create_symlink(extract_root, output_path, inode)
        elif inode.type == FS_TYPE.DIRECTORY:
            output_path.mkdir(mode=inode.mode, exist_ok=True)
        elif inode.type == FS_TYPE.FILE:
            with output_path.open("wb") as f:
                f.write(inode.content)
        elif inode.type in [FS_TYPE.BLOCK_DEV, FS_TYPE.CHAR_DEV]:
            os.mknod(inode.path, inode.mode, inode.dev)
        elif inode.type == FS_TYPE.FIFO:
            os.mkfifo(output_path, inode.mode)

    def dump_fs(self):
        # first we create files and directories
        fd_inodes = {
            k: v
            for k, v in self.inodes.items()
            if v.type in [FS_TYPE.FILE, FS_TYPE.DIRECTORY, FS_TYPE.FIFO, FS_TYPE.SOCKET]
        }
        for inode in sorted(fd_inodes.values(), key=lambda inode: inode.path):
            self.create_inode(self.extract_root, inode)

        if os.geteuid() != 0:
            logger.warn(
                "root privileges are required to create block and char devices, skipping."
            )
        else:
            # then we create devices if we have enough privileges
            dev_inodes = {
                k: v
                for k, v in self.inodes.items()
                if v.type in [FS_TYPE.BLOCK_DEV, FS_TYPE.CHAR_DEV]
            }
            for inode in sorted(dev_inodes.values(), key=lambda inode: inode.path):
                self.create_inode(self.extract_root, inode)

        # then we create links
        links_inodes = {
            k: v
            for k, v in self.inodes.items()
            if v.type in [FS_TYPE.SYMLINK, FS_TYPE.HARD_LINK]
        }
        for inode in sorted(links_inodes.values(), key=lambda inode: inode.path):
            self.create_inode(self.extract_root, inode)

    def __str__(self):
        return f"signature: {self.signature}\nfull_size: {self.full_size}\nchecksum: {self.checksum}\nvolume_name: {self.volume_name}"


@click.command(help="A tool to unpack RomFS filesystems.")
@click.argument(
    "romfs_file",
    type=click.Path(path_type=Path, dir_okay=False, file_okay=True, exists=True),
)
@click.option(
    "-e",
    "--extract-dir",
    "extract_root",
    type=click.Path(path_type=Path, dir_okay=True, file_okay=False, resolve_path=True),
    default=Path.cwd(),
    help="Extract the files to this directory. Will be created if it doesn't exist.",
)
@click.option("-f", "--force", is_flag=True, help="Force overwrite.")
@verbosity_option
def cli(romfs_file: Path, extract_root: Path, force: bool, verbose: int):
    configure_logger(verbose, extract_root)
    if not romfs_file:
        logger.error("No file provided")
        return
    logger.info("Start processing file", path=romfs_file)

    if os.path.isdir(extract_root):
        if force:
            shutil.rmtree(extract_root)
        else:
            logger.warning(
                f"extraction root {extract_root} already exists. Use -f operator to force overwrite."
            )
            return

    with romfs_file.open("rb") as f:
        header = RomFSHeader(f, extract_root, force)
        header.validate()
        header.recursive_walk(header.header_end_offset, None)
        header.dump_fs()


if __name__ == "__main__":
    cli()
