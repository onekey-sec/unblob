import struct
from pathlib import Path

from unblob.handlers.archive.tesla.sbfh import SBFHExtractor

HEADER_SIZE = 0x11C  # fixed sbfh_header_t size


def build_image(seg_size: int) -> bytes:
    # sbfh_header_t: magic[4], header_size, unk[7], firmware_size, padding[265]
    # firmware region = [HEADER_SIZE, HEADER_SIZE + firmware_size); here the MRVL
    # header (20) + one segment header (20) + 4 bytes of segment data == 44 bytes
    firmware_size = 44
    sbfh = (
        b"SBFH"
        + struct.pack("<I", HEADER_SIZE)
        + b"\x00" * 7
        + struct.pack("<I", firmware_size)
        + b"\x00" * 265
    )
    # mrvl_header_t: magic[4], unk_const, creation_time, num_segments, elf_version
    mrvl = b"MRVL" + struct.pack("<IIII", 0x2E9CF17B, 0, 1, 0x1F000000)
    # mrvl_segment_header_t: type, offset (rel. to MRVL start), seg_size, vaddr, crc
    # data starts at MRVL-relative offset 40 (right after the segment header)
    seg = struct.pack("<IIIII", 2, 40, seg_size, 0, 0xDEADBEEF)
    return sbfh + mrvl + seg + b"AAAA" + b"LEAK"


def test_extract_bounds_segment_to_firmware_region(tmp_path: Path):
    # seg_size 8 declares 4 bytes more than the segment actually holds; without a
    # bound the read crosses the firmware region into the trailing "LEAK" bytes and
    # writes them into the reassembled image.
    inpath = tmp_path / "in.sbfh"
    inpath.write_bytes(build_image(seg_size=8))

    SBFHExtractor().extract(inpath, tmp_path)

    (image,) = tmp_path.glob("firmware_*.bin")
    data = image.read_bytes()
    assert b"LEAK" not in data
    assert data == b"AAAA"
