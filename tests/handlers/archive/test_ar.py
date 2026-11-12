import pytest

from unblob.file_utils import File
from unblob.handlers.archive.ar import ARHandler

handler = ARHandler()

GLOBAL_HEADER = b"!<arch>\n"


def member(name: str, content: bytes) -> bytes:
    header = (
        f"{name:<16}{0:<12}{0:<6}{0:<6}{'644':<8}{len(content):<10}".encode() + b"`\n"
    )
    assert len(header) == 60
    # members are padded to an even offset
    return header + content + (b"\n" if len(content) % 2 else b"")


ARCHIVE = GLOBAL_HEADER + member("a.txt/", b"apple\n") + member("b.txt/", b"banana\n")


@pytest.mark.parametrize("start_offset", [0, 16])
@pytest.mark.parametrize(
    "trailing",
    [
        pytest.param(b"", id="eof"),
        pytest.param(b"\x00", id="one-byte"),
        pytest.param(b"\x00" * 59, id="shorter-than-member-header"),
        pytest.param(b"\x00" * 60, id="member-header-length"),
        pytest.param(b"\xff" * 100, id="longer-than-member-header"),
    ],
)
def test_chunk_ends_at_last_member(start_offset: int, trailing: bytes):
    file = File.from_bytes(b"\x00" * start_offset + ARCHIVE + trailing)
    file.seek(start_offset)

    chunk = handler.calculate_chunk(file, start_offset)

    assert chunk is not None
    assert chunk.start_offset == start_offset
    assert chunk.end_offset == start_offset + len(ARCHIVE)


def test_corrupt_first_member_header_is_not_an_archive():
    file = File.from_bytes(GLOBAL_HEADER + b"\x00" * 60)

    assert handler.calculate_chunk(file, 0) is None
