import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.cpio import PortableASCIIParser, PortableOldASCIIParser


def old_ascii_entry(namesize: bytes) -> bytes:
    # old_ascii_header_t: magic6 dev6 ino6 mode6 uid6 gid6 nlink6 rdev6
    #                     mtime11 namesize6 filesize11
    return b"070707" + b"000000" * 7 + b"00000000000" + namesize + b"00000000000"


def new_ascii_entry(namesize: bytes) -> bytes:
    # new_ascii_header_t: magic6 then 13 char[8] fields, namesize is the 13th
    return b"070701" + b"00000000" * 11 + namesize + b"00000000"


@pytest.mark.parametrize(
    "parser, entry",
    [
        (PortableOldASCIIParser, old_ascii_entry(b"-00001")),
        (PortableASCIIParser, new_ascii_entry(b"-0000001")),
    ],
)
def test_parse_rejects_negative_namesize(parser, entry):
    # decode_int accepts a leading minus, so a negative c_namesize slips past the
    # size checks and File.read(c_namesize) returns the whole rest of the mapping.
    file = File.from_bytes(entry + b"A" * 4096 + b"\x00")

    reads = []
    original_read = file.read
    file.read = lambda n=None, *a: reads.append(n) or original_read(n, *a)

    with pytest.raises(InvalidInputFormat):
        parser(file, 0).parse()

    assert all(n is None or n >= 0 for n in reads)
