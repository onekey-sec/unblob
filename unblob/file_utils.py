import enum
import io
import math

from dissect.cstruct import cstruct


def snull(content: bytes):
    """Strip null bytes from the end of the string."""
    return content.rstrip(b"\x00")


def round_up(size: int, alignment: int):
    """Round up size to the alignment boundary."""
    return alignment * math.ceil(size / alignment)


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


class Endian(enum.Enum):
    LITTLE = "<"
    BIG = ">"


class StructParser:
    """Wrapper for dissect.cstruct to handle different endianness parsing dynamically."""

    def __init__(self, definitions: str):
        self._definitions = definitions
        self.__cparser_le = None
        self.__cparser_be = None

    @property
    def _cparser_le(self):
        if self.__cparser_le is None:
            # Default endianness is little
            self.__cparser_le = cstruct()
            self.__cparser_le.load(self._definitions)
        return self.__cparser_le

    @property
    def _cparser_be(self):
        if self.__cparser_be is None:
            self.__cparser_be = cstruct(endian=">")
            self.__cparser_be.load(self._definitions)
        return self.__cparser_be

    def parse(self, struct_name: str, file: io.BufferedIOBase, endian: Endian):
        cparser = self._cparser_le if endian is Endian.LITTLE else self._cparser_be
        struct_parser = getattr(cparser, struct_name)
        return struct_parser(file)
