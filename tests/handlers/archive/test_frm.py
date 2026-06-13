import struct
from pathlib import Path

from unblob.file_utils import File
from unblob.handlers.archive.moxa.frm import MoxaFRMExtractor, MoxaFRMHandler
from unblob.testing import unhex

FILE_CONTENTS = unhex(
    """\
00000000: 2a46 524d 0000 0001 cc92 0e00 6000 0200  *FRM........`...
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0200 0000 6000 0000 d08c 0300 0000 0000  ....`...........
00000050: 0100 0000 308d 0300 9c05 0b00 0000 0000  ....0...........
00000060: 5265 6461 6374 6564 0000 0000 0000 0000  Redacted........
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0103 5d74 4668 101d 0200 2e79 1f01  ....]tFh.....y..
00000090: 0001 0000 000f 0000 4000 3c00 d07c 0300  ........@.<..|..
"""
)
handler = MoxaFRMHandler()


def test_chunk_calculation():
    file = File.from_bytes(FILE_CONTENTS)
    chunk = handler.calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == 0xE92CC


CONTENT = b"GOOD"
TRAILING = b"SECRETFW"


def build_frm(file_length: int) -> bytes:
    """Build an FRM with one file at the very end of its FILESYSTEM section, then trailing bytes."""
    fs_header = (
        b"device".ljust(32, b"\x00")
        + struct.pack("<I", 0)  # unknown1
        + struct.pack("<I", 0)  # timestamp
        + struct.pack("<I", 0)  # unknown2
        + struct.pack("<I", 0)  # unknown3
        + struct.pack("<I", 76)  # file_table_offset
        + struct.pack("<I", 64)  # file_table_length
        + struct.pack("<H", 64)  # file_header_length
        + struct.pack("<H", 1)  # file_count
        + struct.pack("<I", len(CONTENT))  # data_length
        + struct.pack("<H", 0)  # unknown4
        + struct.pack("<H", 0)  # file_count2
        + struct.pack("<I", 0)  # file_table_length2
        + struct.pack("<I", 0)  # unknown5
    )
    assert len(fs_header) == 76

    data_offset = len(fs_header) + 64  # content sits right after the file table
    file_entry = (
        b"data.bin".ljust(48, b"\x00")
        + b"\x00" * 8  # unknown
        + struct.pack("<I", file_length)
        + struct.pack("<I", data_offset)
    )
    section = fs_header + file_entry + CONTENT

    section_offset = 64 + 16  # container header + one section entry
    container = (
        b"*FRM"
        + struct.pack("<I", 1)  # unknown1
        + struct.pack("<I", section_offset + len(section))  # total_length
        + struct.pack("<H", 0x60)  # header_length
        + struct.pack("<H", 1)  # section_count
        + b"\x00" * 48  # unknown2
    )
    section_entry = struct.pack(
        "<IIII", 2, section_offset, len(section), 0
    )  # type=FILESYSTEM
    return container + section_entry + section + TRAILING


def test_extract_bounds_file_to_section(tmp_path: Path):
    # file_length is taken straight from the entry; an oversized value reads past
    # the section (and to EOF), so the trailing bytes outside the section must not
    # leak into the extracted file.
    inpath = tmp_path / "in.frm"
    inpath.write_bytes(build_frm(file_length=0x10000))

    MoxaFRMExtractor().extract(inpath, tmp_path)

    extracted = (tmp_path / "data.bin").read_bytes()
    assert extracted == CONTENT
    assert TRAILING not in extracted
