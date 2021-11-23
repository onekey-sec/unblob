import io
import math


def snull(content: bytes):
    """Strip null bytes from the end of the string."""
    return content.rstrip(b"\x00")


def round_up(size: int, alignment: int):
    """Round up size to the alignment boundary."""
    return alignment * math.ceil(size / alignment)


class LimitedStartReader:
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

    def __getattr__(self, attr):
        return getattr(self._file, attr)
