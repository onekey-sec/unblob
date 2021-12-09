import enum
import io
import math
import os
import shutil
import struct
from typing import Iterator

from dissect.cstruct import cstruct

from .logging import format_hex

DEFAULT_BUFSIZE = shutil.COPY_BUFSIZE  # type: ignore


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


def round_up(size: int, alignment: int):
    """Round up size to the alignment boundary."""
    return alignment * math.ceil(size / alignment)


def convert_int32(value: bytes, endian: Endian) -> int:
    """Convert 4 byte integer to a Python int."""
    try:
        return struct.unpack(f"{endian.value}I", value)[0]
    except struct.error:
        raise ValueError("Not an int32")


def find_first(
    file: io.BufferedIOBase, pattern: bytes, chunk_size: int = 0x1000
) -> int:
    """Search for the pattern and return the position where it starts.
    Returns -1 if not found.
    """
    if chunk_size < len(pattern):
        chunk_hex = format_hex(chunk_size)
        raise ValueError(
            f"Chunk size ({chunk_hex}) shouldn't be shorter than pattern's ({pattern}) length ({len(pattern)})!"
        )

    compensation = len(pattern) - 1
    bytes_searched = 0
    while True:
        # Prepend the padding from the last chunk, to make sure that we find the pattern,
        # even if it straddles the chunk boundary.
        data = file.read(chunk_size)
        if data == b"":
            # We've reached the end of the stream.
            return -1
        marker = data.find(pattern)
        if marker != -1:
            return marker + bytes_searched
        if len(data) <= len(pattern):
            # The length that we read from the file is the same length or less than as the pattern
            # we're looking for, and we didn't find the pattern in there. If we don't return -1
            # here, we'll end up in an infinite loop.
            return -1
        file.seek(-compensation, os.SEEK_CUR)
        bytes_searched += chunk_size - compensation


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


def get_endian(
    file: io.BufferedIOBase, big_endian_magic: int, read_bytes: int = 4
) -> Endian:
    """Read the magic and derive endianness from it by comparing the big endian magic.
    It reads read_bytes number of bytes and seeks back after that.
    """
    magic_bytes = file.read(read_bytes)
    file.seek(-1 * read_bytes, io.SEEK_CUR)
    magic = convert_int32(magic_bytes, Endian.BIG)
    endian = Endian.BIG if magic == big_endian_magic else Endian.LITTLE
    return endian
