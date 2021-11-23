import io
import math
import os


def snull(content: bytes):
    """Strip null bytes from the end of the string."""
    return content.rstrip(b"\x00")


def round_up(size: int, alignment: int):
    """Round up size to the alignment boundary."""
    return alignment * math.ceil(size / alignment)


def find_first(file: io.BufferedReader, pattern: bytes) -> int:
    chunk_size = 0x1000
    compensation = len(pattern) - 1
    bytes_searched = 0
    while True:
        # Prepend the padding from the last chunk, to make sure that we find the pattern, even if
        # it straddles the chunk boundary.
        data = file.read(chunk_size)
        marker = data.find(pattern)
        if marker != -1:
            return marker + bytes_searched
        file.seek(-compensation, os.SEEK_CUR)
        bytes_searched += chunk_size - compensation
