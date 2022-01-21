import enum
import io
import math
import os
import shutil
import struct
from pathlib import Path
from typing import Iterator, Tuple

from dissect.cstruct import cstruct

from .logging import format_hex

DEFAULT_BUFSIZE = shutil.COPY_BUFSIZE  # type: ignore


class InvalidInputFormat(Exception):
    pass


class Endian(enum.Enum):
    LITTLE = "<"
    BIG = ">"


def iterbits(file: io.BufferedIOBase) -> Iterator[int]:
    """bit-wise reading of file in little-endian mode"""
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


def decode_int(value: bytes, base: int) -> int:
    try:
        return int(value, base)
    except ValueError as exc:
        raise InvalidInputFormat from exc


def decode_multibyte_integer(data: bytes) -> Tuple[int, int]:
    """Decodes multi-bytes integer into integer size and integer value.

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


def find_first(
    file: io.BufferedIOBase, pattern: bytes, chunk_size: int = 0x1000
) -> int:
    """Search for the pattern and return the absolute position of the start of the pattern in the file.
    Returns -1 if not found.
    Seek the file pointer to the next byte of where we found the pattern or
    seek back to the initial position when we did not find it.
    """
    try:
        return next(iterate_patterns(file, pattern, chunk_size))
    except StopIteration:
        return -1


def iterate_patterns(
    file: io.BufferedIOBase, pattern: bytes, chunk_size: int = 0x1000
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
    file: io.BufferedIOBase,
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


class LimitedStartReader(io.BufferedIOBase):
    """Wrapper for open files, which
    enforces that seekeng earlier than the start offset is not possible.
    """

    def __init__(self, file: io.BufferedIOBase, start: int):
        self._file = file
        self._start = start
        self._file.seek(start)

    def seek(self, offset: int, whence=io.SEEK_SET):
        new_pos = self._file.seek(offset, whence)
        if new_pos < self._start:
            new_pos = self._file.seek(self._start, io.SEEK_SET)
        return new_pos

    def write(self, *args, **kwargs):
        raise TypeError("MUST NOT call write method")

    def detach(self, *args, **kwargs):
        return self._file.detach(*args, **kwargs)

    def read(self, *args, **kwargs):
        return self._file.read(*args, **kwargs)

    def read1(self, *args, **kwargs):
        return self._file.read1(*args, **kwargs)

    def readinto(self, *args, **kwargs):
        return self._file.readinto(*args, **kwargs)

    def readinto1(self, *args, **kwargs):
        return self._file.readinto1(*args, **kwargs)


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

    def parse(self, struct_name: str, file: io.BufferedIOBase, endian: Endian):
        cparser = self.cparser_le if endian is Endian.LITTLE else self.cparser_be
        struct_parser = getattr(cparser, struct_name)
        return struct_parser(file)


def get_endian(file: io.BufferedIOBase, big_endian_magic: int) -> Endian:
    """Reads a four bytes magic and derive endianness from it by
    comparing it with the big endian magic. It reads four bytes and
    seeks back after that.
    """
    if big_endian_magic > 0xFF_FF_FF_FF:
        raise ValueError("big_endian_magic is larger than a 32 bit integer.")
    magic_bytes = file.read(4)
    file.seek(-len(magic_bytes), io.SEEK_CUR)
    magic = convert_int32(magic_bytes, Endian.BIG)
    endian = Endian.BIG if magic == big_endian_magic else Endian.LITTLE
    return endian


def read_until_past(file: io.BufferedIOBase, pattern: bytes):
    """Read until the bytes are not 0x00 or 0xff."""
    while True:
        next_byte = file.read(1)
        if next_byte == b"":
            # We've hit the EoF
            return file.tell()
        if next_byte not in pattern:
            return file.tell() - 1


def valid_path(path: Path) -> bool:
    try:
        path.as_posix().encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True
