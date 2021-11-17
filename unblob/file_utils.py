def snull(content: bytes):
    """Strip null bytes from the end of the string."""
    return content.rstrip(b"\x00")
