import math


def snull(content: bytes):
    """Strip null bytes from the end of the string."""
    return content.rstrip(b"\x00")


def round_up(size: int, alignment: int):
    """Round up size to the alignment boundary."""
    return alignment * math.ceil(size / alignment)
