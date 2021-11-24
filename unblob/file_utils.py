import enum
import io
import math
import struct

from dissect.cstruct import cstruct


class Endian(enum.Enum):
    LITTLE = "<"
    BIG = ">"


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
        file.seek(-compensation, os.SEEK_CUR)
        bytes_searched += chunk_size - compensation


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
