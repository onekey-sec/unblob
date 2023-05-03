import enum
import io
import math
import mmap
import os
import shutil
import struct
from pathlib import Path
from typing import Iterator, List, Tuple, Union

from dissect.cstruct import cstruct

from .logging import format_hex

DEFAULT_BUFSIZE = shutil.COPY_BUFSIZE  # type: ignore


class SeekError(ValueError):
    """Specific ValueError for File.seek."""


class File(mmap.mmap):
    @classmethod
    def from_bytes(cls, content: bytes):
        m = cls(-1, len(content))
        m.write(content)
        m.seek(0)
        return m

    @classmethod
    def from_path(cls, path: Path, access=mmap.ACCESS_READ):
        mode = "r+b" if access == mmap.ACCESS_WRITE else "rb"
        with path.open(mode) as base_file:
            return cls(base_file.fileno(), 0, access=access)

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

    def parse(self, struct_name: str, file: Union[File, bytes], endian: Endian):
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
