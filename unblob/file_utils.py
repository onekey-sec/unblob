import enum
import functools
import hashlib
import io
import math
import mmap
import os
import re
import shutil
import struct
import unicodedata
from pathlib import Path
from typing import Iterable, Iterator, List, Literal, Optional, Tuple, Union

from dissect.cstruct import Instance, cstruct
from structlog import get_logger

from .logging import format_hex
from .report import (
    ExtractionProblem,
    LinkExtractionProblem,
    PathTraversalProblem,
    Report,
    SpecialFileExtractionProblem,
)

DEFAULT_BUFSIZE = shutil.COPY_BUFSIZE  # type: ignore
logger = get_logger()


def is_safe_path(basedir: Path, path: Path) -> bool:
    try:
        basedir.joinpath(path).resolve().relative_to(basedir.resolve())
    except ValueError:
        return False
    return True


class SeekError(ValueError):
    """Specific ValueError for File.seek."""


class File(mmap.mmap):
    access: int

    @classmethod
    def from_bytes(cls, content: bytes):
        if not content:
            raise ValueError("Can't create File from empty bytes.")
        m = cls(-1, len(content))
        m.write(content)
        m.seek(0)
        m.access = mmap.ACCESS_WRITE
        return m

    @classmethod
    def from_path(cls, path: Path, access=mmap.ACCESS_READ):
        """Create File.

        Needs a valid non-empty file,
        raises ValueError on empty files.
        """
        mode = "r+b" if access == mmap.ACCESS_WRITE else "rb"
        with path.open(mode) as base_file:
            m = cls(base_file.fileno(), 0, access=access)
            m.access = access
            return m

    def seek(self, pos: int, whence: int = os.SEEK_SET) -> int:
        try:
            super().seek(pos, whence)
        except ValueError as e:
            raise SeekError from e
        return self.tell()

    def size(self) -> int:
        size = 0
        try:
            size = super().size()
        except OSError:
            # the file was built with from_bytes() so it's not on disk,
            # triggering an OSError on fstat() call
            current_offset = self.tell()
            self.seek(0, io.SEEK_END)
            size = self.tell()
            self.seek(current_offset, io.SEEK_SET)

        return size

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        self.close()

    def readable(self) -> bool:
        return self.access in (mmap.ACCESS_READ, mmap.ACCESS_COPY)

    def writable(self) -> bool:
        return self.access in (mmap.ACCESS_WRITE, mmap.ACCESS_COPY)

    def seekable(self) -> bool:
        return True  # Memory-mapped files are always seekable


class OffsetFile:
    def __init__(self, file: File, offset: int):
        self._file = file
        self._offset = offset
        self._file.seek(offset)

    def seek(self, pos: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            pos += self._offset
        self._file.seek(pos, whence)
        return self._file.tell() - self._offset

    def read(self, n=None):
        return self._file.read(n)

    def tell(self):
        return self._file.tell() - self._offset


class InvalidInputFormat(Exception):
    pass


class Endian(enum.Enum):
    LITTLE = "<"
    BIG = ">"


def iterbits(file: File) -> Iterator[int]:
    """bit-wise reading of file in little-endian mode."""
    while cur_bytes := file.read(DEFAULT_BUFSIZE):
        for b in cur_bytes:
            for i in range(7, -1, -1):
                yield (b >> i) & 1


def snull(content: bytes):
    """Strip null bytes from the end of the string."""
    return content.rstrip(b"\x00")


def round_down(size: int, alignment: int):
    """Round down size to the alignment boundary."""
    return alignment * math.floor(size / alignment)


def round_up(size: int, alignment: int):
    """Round up size to the alignment boundary."""
    return alignment * math.ceil(size / alignment)


def convert_int8(value: bytes, endian: Endian) -> int:
    """Convert 1 byte integer to a Python int."""
    try:
        return struct.unpack(f"{endian.value}B", value)[0]
    except struct.error as exc:
        raise InvalidInputFormat from exc


def convert_int16(value: bytes, endian: Endian) -> int:
    """Convert 2 byte integer to a Python int."""
    try:
        return struct.unpack(f"{endian.value}H", value)[0]
    except struct.error as exc:
        raise InvalidInputFormat from exc


def convert_int32(value: bytes, endian: Endian) -> int:
    """Convert 4 byte integer to a Python int."""
    try:
        return struct.unpack(f"{endian.value}I", value)[0]
    except struct.error as exc:
        raise InvalidInputFormat from exc


def convert_int64(value: bytes, endian: Endian) -> int:
    """Convert 8 byte integer to a Python int."""
    try:
        return struct.unpack(f"{endian.value}Q", value)[0]
    except struct.error as exc:
        raise InvalidInputFormat from exc


def decode_int(value, base: int) -> int:
    try:
        return int(value, base)
    except ValueError as exc:
        raise InvalidInputFormat from exc


def decode_multibyte_integer(data: bytes) -> Tuple[int, int]:
    """Decode multi-bytes integer into integer size and integer value.

    Multibyte integers of static length are stored in little endian byte order.

    When smaller values are more likely than bigger values (for example file sizes),
    multibyte integers are encoded in a variable-length representation:
        - Numbers in the range [0, 127] are copied as is, and take one byte of space.
        - Bigger numbers will occupy two or more bytes. All but the last byte of the multibyte
         representation have the highest (eighth) bit set.
    """
    value = 0
    for size, byte in enumerate(data):
        value |= (byte & 0x7F) << (size * 7)
        if not byte & 0x80:
            return (size + 1, value)
    raise InvalidInputFormat("Multibyte integer decoding failed.")


def iterate_patterns(
    file: File, pattern: bytes, chunk_size: int = 0x1000
) -> Iterator[int]:
    """Iterate on the file searching for pattern until all occurences has been found.

    Seek the file pointer to the next byte of where we found the pattern or
    seek back to the initial position when the iterator is exhausted.
    """
    if chunk_size < len(pattern):
        chunk_hex = format_hex(chunk_size)
        raise ValueError(
            f"Chunk size ({chunk_hex}) shouldn't be shorter than pattern's ({pattern}) length ({len(pattern)})!"
        )

    initial_position = file.tell()

    compensation = len(pattern) - 1
    try:
        while True:
            current_position = file.tell()

            # Prepend the padding from the last chunk, to make sure that we find the pattern,
            # even if it straddles the chunk boundary.
            data = file.read(chunk_size)
            if data == b"":
                # We've reached the end of the stream.
                return

            if len(data) < len(pattern):
                # The length that we read from the file is the same
                # length or less than as the pattern we're looking
                # for, and we didn't find the pattern in there.
                return

            marker = data.find(pattern)
            while marker != -1:
                found_pos = current_position + marker
                # Reset the file pointer so that calling code cannot
                # depend on the side-effect of this iterator advancing
                # it.
                file.seek(initial_position)
                yield found_pos
                # We want to seek past the found position to the next byte,
                # so we can call find_first again without extra seek
                # This might seek past the actual end of the file
                file.seek(found_pos + len(pattern))
                marker = data.find(pattern, marker + len(pattern))

            file.seek(-compensation, os.SEEK_CUR)
    finally:
        file.seek(initial_position)


def iterate_file(
    file: File,
    start_offset: int,
    size: int,
    # default buffer size in shutil for unix based systems
    buffer_size: int = DEFAULT_BUFSIZE,
) -> Iterator[bytes]:
    if buffer_size <= 0:
        raise ValueError(
            "The file needs to be read until a specific size, so buffer_size must be greater than 0"
        )

    read_bytes = 0
    file.seek(start_offset)
    file_read = file.read
    while read_bytes < size:
        remaining = size - read_bytes
        if remaining < buffer_size:
            buffer_size = remaining
        read_bytes += buffer_size
        data = file_read(buffer_size)

        if data == b"":
            # We've reached the end of the stream.
            break

        yield data


def carve(carve_path: Path, file: File, start_offset: int, size: int):
    """Extract part of a file."""
    carve_path.parent.mkdir(parents=True, exist_ok=True)

    with carve_path.open("xb") as f:
        for data in iterate_file(file, start_offset, size):
            f.write(data)


def stream_scan(scanner, file: File):
    """Scan the whole file by increment of DEFAULT_BUFSIZE using Hyperscan's streaming mode."""
    scanner.scan(file, DEFAULT_BUFSIZE)


class StructParser:
    """Wrapper for dissect.cstruct to handle different endianness parsing dynamically."""

    def __init__(self, definitions: str):
        self._definitions = definitions
        self.__cparser_le = None
        self.__cparser_be = None

    @property
    def cparser_le(self):
        if self.__cparser_le is None:
            # Default endianness is little
            self.__cparser_le = cstruct()
            self.__cparser_le.load(self._definitions)
        return self.__cparser_le

    @property
    def cparser_be(self):
        if self.__cparser_be is None:
            self.__cparser_be = cstruct(endian=">")
            self.__cparser_be.load(self._definitions)
        return self.__cparser_be

    def parse(
        self,
        struct_name: str,
        file: Union[File, bytes],
        endian: Endian,
    ) -> Instance:
        cparser = self.cparser_le if endian is Endian.LITTLE else self.cparser_be
        struct_parser = getattr(cparser, struct_name)
        return struct_parser(file)


def get_endian(file: File, big_endian_magic: int) -> Endian:
    """Read a four bytes magic and derive endianness from it.

    It compares the read data with the big endian magic.  It reads
    four bytes and seeks back after that.
    """
    if big_endian_magic > 0xFF_FF_FF_FF:
        raise ValueError("big_endian_magic is larger than a 32 bit integer.")
    magic_bytes = file.read(4)
    file.seek(-len(magic_bytes), io.SEEK_CUR)
    magic = convert_int32(magic_bytes, Endian.BIG)
    return Endian.BIG if magic == big_endian_magic else Endian.LITTLE


def get_endian_multi(file: File, big_endian_magics: List[int]) -> Endian:
    """Read a four bytes magic and derive endianness from it.

    It compares the read data with the big endian magic.  It reads
    four bytes and seeks back after that.
    """
    if any(big_endian_magic > 0xFF_FF_FF_FF for big_endian_magic in big_endian_magics):
        raise ValueError("big_endian_magic is larger than a 32 bit integer.")
    magic_bytes = file.read(4)
    file.seek(-len(magic_bytes), io.SEEK_CUR)
    magic = convert_int32(magic_bytes, Endian.BIG)
    return (
        Endian.BIG
        if any((magic == big_endian_magic) for big_endian_magic in big_endian_magics)
        else Endian.LITTLE
    )


def read_until_past(file: File, pattern: bytes):
    """Read until the bytes are not 0x00 or 0xff."""
    while True:
        next_byte = file.read(1)
        if next_byte == b"":
            # We've hit the EoF
            return file.tell()
        if next_byte not in pattern:
            return file.tell() - 1


def chop_root(path: Path):
    """Make absolute paths relative by chopping off the root."""
    if not path.is_absolute():
        return path

    relative_parts = list(path.parts[1:])
    return Path("/".join(relative_parts))


def make_lost_and_found_path(path: Path) -> Path:
    """Make a human readable, safe path."""
    dir_path = path.parent

    # . and .. would not be a valid filename, but they would lead to confusion
    filename = {".": "dot", "..": "dot-dot"}.get(path.name, path.name)
    dir_hash = hashlib.sha224(str(dir_path).encode(errors="ignore")).hexdigest()

    # adapted from https://stackoverflow.com/questions/5574042/string-slugification-in-python
    dir_slug = str(dir_path)
    dir_slug = unicodedata.normalize("NFKD", dir_slug)
    dir_slug = dir_slug.encode("ascii", "ignore").lower()
    dir_slug = re.sub(rb"[^a-z0-9]+", b"-", dir_slug).strip(b"-")
    dir_slug = re.sub(rb"[-]+", b"-", dir_slug).decode()

    return Path(f".unblob-lost+found/{dir_slug}_{dir_hash}/{filename}")


class _FSPath:
    def __init__(self, *, root: Path, path: Path) -> None:
        self.root = root
        self.relative_path = chop_root(path)
        absolute_path = root / self.relative_path
        self.is_safe = is_safe_path(root, absolute_path)

        if self.is_safe:
            self.safe_relative_path = self.relative_path
            self.absolute_path = absolute_path
        else:
            self.safe_relative_path = make_lost_and_found_path(path)
            self.absolute_path = root / self.safe_relative_path
            assert is_safe_path(root, self.absolute_path)


class _FSLink:
    def __init__(self, *, root: Path, src: Path, dst: Path) -> None:
        self.dst = _FSPath(root=root, path=dst)
        self.src = _FSPath(root=root, path=src)
        self.is_safe = self.dst.is_safe and self.src.is_safe

    def format_report(
        self, description, resolution="Skipped."
    ) -> LinkExtractionProblem:
        return LinkExtractionProblem(
            problem=description,
            resolution=resolution,
            path=str(self.dst.relative_path),
            link_path=str(self.src.relative_path),
        )


class FileSystem:
    """Restricts file system operations to a directory.

    Path traversal violations are collected as a list of :ExtractionProblem:-s
    and not reported immediately - violating operations looks like successful for the caller.

    All input paths are interpreted as relative to the root directory.
    Absolute paths are converted to relative paths by dropping the root /.
    There is one exception to this universal base: symlink targets,
    which are relative to the directory containing the symbolic link, because
    this is how symlinks work.
    """

    problems: List[Report]

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.problems = []

    def record_problem(self, problem: ExtractionProblem):
        self.problems.append(problem)
        problem.log_with(logger)

    @functools.cached_property
    def has_root_permissions(self):
        return os.geteuid() == 0

    def _fs_path(self, path: Path) -> _FSPath:
        return _FSPath(root=self.root, path=path)

    def _ensure_parent_dir(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)

    def _get_extraction_path(self, path: Path, path_use_description: str) -> Path:
        fs_path = self._fs_path(path)

        if not fs_path.is_safe:
            report = PathTraversalProblem(
                path=str(fs_path.relative_path),
                extraction_path=str(fs_path.safe_relative_path),
                problem=f"Potential path traversal through {path_use_description}",
                resolution="Redirected.",
            )
            self.record_problem(report)

        return fs_path.absolute_path

    def write_bytes(self, path: Path, content: bytes):
        logger.debug("creating file", file_path=path, _verbosity=3)
        safe_path = self._get_extraction_path(path, "write_bytes")

        self._ensure_parent_dir(safe_path)
        safe_path.write_bytes(content)

    def write_chunks(self, path: Path, chunks: Iterable[bytes]):
        logger.debug("creating file", file_path=path, _verbosity=3)
        safe_path = self._get_extraction_path(path, "write_chunks")

        self._ensure_parent_dir(safe_path)
        with safe_path.open("wb") as f:
            for chunk in chunks:
                f.write(chunk)

    def carve(self, path: Path, file: File, start_offset: int, size: int):
        logger.debug("carving file", path=path, _verbosity=3)
        safe_path = self._get_extraction_path(path, "carve")

        self._ensure_parent_dir(safe_path)
        carve(safe_path, file, start_offset, size)

    def mkdir(self, path: Path, *, mode=0o777, parents=False, exist_ok=False):
        logger.debug("creating directory", dir_path=path, _verbosity=3)
        safe_path = self._get_extraction_path(path, "mkdir")

        safe_path.mkdir(mode=mode, parents=parents, exist_ok=exist_ok)

    def mkfifo(self, path: Path, mode=0o666):
        logger.debug("creating fifo", path=path, _verbosity=3)
        safe_path = self._get_extraction_path(path, "mkfifo")

        self._ensure_parent_dir(safe_path)
        os.mkfifo(safe_path, mode=mode)

    def mknod(self, path: Path, mode=0o600, device=0):
        logger.debug("creating special file", special_path=path, _verbosity=3)
        safe_path = self._get_extraction_path(path, "mknod")

        if self.has_root_permissions:
            self._ensure_parent_dir(safe_path)
            os.mknod(safe_path, mode=mode, device=device)
        else:
            problem = SpecialFileExtractionProblem(
                problem="Root privileges are required to create block and char devices.",
                resolution="Skipped.",
                path=str(path),
                mode=mode,
                device=device,
            )
            self.record_problem(problem)

    def _get_checked_link(self, src: Path, dst: Path) -> Optional[_FSLink]:
        link = _FSLink(root=self.root, src=src, dst=dst)
        if link.is_safe:
            return link

        self.record_problem(link.format_report("Potential path traversal through link"))
        return None

    def _path_to_root(self, from_dir: Path) -> Path:
        # This version does not look at the existing symlinks, so while it looks cleaner it is also
        # somewhat less precise:
        #
        # os.path.relpath(self.root, start=self.root / chop_root(from_dir))
        #
        # In contrast, the below version looks like a kludge, but using .resolve() actually
        # calculates the correct path in more cases, even if it can still give a bad result due
        # to ordering of symlink creation and resolve defaulting to non-strict checking.
        # Calculation unfortunately might fall back to the potentially wrong string interpretation,
        # which is the same as os.path.relpath, sharing the same failure case.
        # Ultimately we can not easily catch all symlink based path traversals here, so there
        # still remains work for `unblob.extractor.fix_symlink()`
        #
        absolute_from_dir = (self.root / chop_root(from_dir)).resolve()
        ups = len(absolute_from_dir.parts) - len(self.root.parts)
        return Path("/".join(["."] + [".."] * ups))

    def create_symlink(self, src: Path, dst: Path):
        """Create a symlink dst with the link/content/target src."""
        logger.debug("creating symlink", file_path=dst, link_target=src, _verbosity=3)

        if src.is_absolute():
            # convert absolute paths to dst relative paths
            # these would point to the same path if self.root would be the real root "/"
            # but they are relocatable
            src = self._path_to_root(dst.parent) / chop_root(src)

        safe_link = self._get_checked_link(src=dst.parent / src, dst=dst)

        if safe_link:
            dst = safe_link.dst.absolute_path
            self._ensure_parent_dir(dst)
            dst.symlink_to(src)

    def create_hardlink(self, src: Path, dst: Path):
        """Create a new hardlink dst to the existing file src."""
        logger.debug("creating hardlink", file_path=dst, link_target=src, _verbosity=3)
        safe_link = self._get_checked_link(src=src, dst=dst)

        if safe_link:
            try:
                src = safe_link.src.absolute_path
                dst = safe_link.dst.absolute_path
                self._ensure_parent_dir(dst)
                os.link(src, dst)
                # FIXME: from python 3.10 change the above to
                #        dst.hardlink_to(src)
                #        so as to make it consistent with create_symlink
                #        (see Path.link_to vs Path.hardlink_to parameter order mess up)
            except FileNotFoundError:
                self.record_problem(
                    safe_link.format_report("Hard link target does not exist.")
                )
            except PermissionError:
                not_enough_privileges = (
                    "Not enough privileges to create hardlink to block/char device."
                )
                self.record_problem(safe_link.format_report(not_enough_privileges))

    def open(  # noqa: A003
        self, path, mode: Literal["wb+", "rb+", "xb+"] = "wb+"
    ) -> io.BufferedRandom:
        """Create/open binary file for random access read-writing.

        There is no intention in supporting anything other than binary files opened for random access.
        """
        logger.debug("create/open binary file for writing", file_path=path)
        safe_path = self._get_extraction_path(path, "open")

        self._ensure_parent_dir(safe_path)
        return safe_path.open(mode)

    def unlink(self, path):
        """Delete file within extraction path."""
        logger.debug("unlink file", file_path=path, _verbosity=3)
        safe_path = self._get_extraction_path(path, "unlink")

        safe_path.unlink(missing_ok=True)
