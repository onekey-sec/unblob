import struct
from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.filesystem.lvm import (
    SECTOR_SIZE,
    LVM2Extractor,
    LVM2Handler,
    _lvm_crc32,
    parse_lvm_metadata,
)

PV_UUID = b"0123456789abcdef0123456789abcdef"
PV_SIZE = 12 * 1024
MDA_OFFSET = 4 * 1024
MDA_SIZE = 4 * 1024
DATA_OFFSET = MDA_OFFSET + MDA_SIZE
LV_DATA = b"A" * SECTOR_SIZE

METADATA = f"""
vg {{
    extent_size = 1
    physical_volumes {{
        pv0 {{
            id = "{PV_UUID.decode()}"
        }}
    }}
    logical_volumes {{
        test {{
            segment1 {{
                start_extent = 0
                extent_count = 1
                type = "striped"
                stripe_count = 1
                stripes = [ "pv0", 0 ]
            }}
        }}
    }}
}}
""".encode()


def _descriptor(offset: int, size: int) -> bytes:
    return struct.pack("<QQ", offset, size)


def _build_pv(
    *,
    label_sector: int = 1,
    locations: list[tuple[int, bytes, int]],
    device_size: int = PV_SIZE,
) -> bytes:
    pv = bytearray(PV_SIZE)
    label_offset = label_sector * SECTOR_SIZE
    pv[label_offset : label_offset + 32] = struct.pack(
        "<8sQII8s", b"LABELONE", label_sector, 0, 32, b"LVM2 001"
    )

    pv_header_offset = label_offset + 32
    pv[pv_header_offset : pv_header_offset + 40] = struct.pack(
        "<32sQ", PV_UUID, device_size
    )
    descriptors = b"".join(
        (
            _descriptor(DATA_OFFSET, PV_SIZE - DATA_OFFSET),
            _descriptor(0, 0),
            _descriptor(MDA_OFFSET, MDA_SIZE),
            _descriptor(0, 0),
        )
    )
    pv[pv_header_offset + 40 : pv_header_offset + 40 + len(descriptors)] = descriptors

    raw_locations = b"".join(
        struct.pack("<QQII", offset, len(data), _lvm_crc32(data), flags)
        for offset, data, flags in locations
    ).ljust(4 * 24, b"\0")
    mda_header = struct.pack(
        "<I16sIQQ", 0, b" LVM2 x[5A%r0N*>", 1, MDA_OFFSET, MDA_SIZE
    )
    pv[MDA_OFFSET : MDA_OFFSET + SECTOR_SIZE] = mda_header + raw_locations + bytes(376)
    struct.pack_into(
        "<I",
        pv,
        MDA_OFFSET,
        _lvm_crc32(pv[MDA_OFFSET + 4 : MDA_OFFSET + SECTOR_SIZE]),
    )

    for offset, data, _flags in locations:
        first_size = min(len(data), MDA_SIZE - offset)
        pv[MDA_OFFSET + offset : MDA_OFFSET + offset + first_size] = data[:first_size]
        if first_size < len(data):
            remainder = data[first_size:]
            pv[MDA_OFFSET + SECTOR_SIZE : MDA_OFFSET + SECTOR_SIZE + len(remainder)] = (
                remainder
            )

    pv[DATA_OFFSET : DATA_OFFSET + len(LV_DATA)] = LV_DATA
    struct.pack_into(
        "<I",
        pv,
        label_offset + 16,
        _lvm_crc32(pv[label_offset + 20 : label_offset + SECTOR_SIZE]),
    )
    return bytes(pv)


def _extract(tmp_path: Path, pv: bytes) -> bytes:
    inpath = tmp_path / "pv.img"
    outdir = tmp_path / "out"
    inpath.write_bytes(pv)
    outdir.mkdir()

    LVM2Extractor().extract(inpath, outdir)

    return (outdir / "test.img").read_bytes()


@pytest.mark.parametrize("label_sector", range(4))
def test_extract_reads_label_from_any_valid_label_sector(
    tmp_path: Path, label_sector: int
):
    pv = _build_pv(
        label_sector=label_sector,
        locations=[(SECTOR_SIZE, METADATA, 0)],
    )

    assert _extract(tmp_path, pv) == LV_DATA


def test_extract_skips_ignored_metadata_locations(tmp_path: Path):
    pv = _build_pv(
        locations=[
            (SECTOR_SIZE, b"\xff", 1),
            (2 * SECTOR_SIZE, METADATA, 0),
        ]
    )

    assert _extract(tmp_path, pv) == LV_DATA


def test_extract_reads_wrapped_metadata_location(tmp_path: Path):
    pv = _build_pv(
        locations=[(MDA_SIZE - 20, METADATA, 0)],
    )

    assert _extract(tmp_path, pv) == LV_DATA


def test_calculate_chunk_accounts_for_prefix():
    prefix = b"prefix"
    pv = _build_pv(locations=[(SECTOR_SIZE, METADATA, 0)])

    with File.from_bytes(prefix + pv) as file:
        label_offset = len(prefix) + SECTOR_SIZE
        file.seek(label_offset)
        chunk = LVM2Handler().calculate_chunk(file, label_offset)

    assert chunk is not None
    assert chunk.start_offset == len(prefix)
    assert chunk.end_offset == len(prefix) + PV_SIZE


def test_calculate_chunk_rejects_device_size_past_eof():
    pv = _build_pv(locations=[(SECTOR_SIZE, METADATA, 0)], device_size=PV_SIZE + 1)

    with File.from_bytes(pv) as file:
        file.seek(SECTOR_SIZE)
        with pytest.raises(InvalidInputFormat, match="device size"):
            LVM2Handler().calculate_chunk(file, SECTOR_SIZE)


def test_calculate_chunk_rejects_invalid_label_checksum():
    pv = bytearray(_build_pv(locations=[(SECTOR_SIZE, METADATA, 0)]))
    pv[SECTOR_SIZE + 20] ^= 1

    with File.from_bytes(pv) as file:
        file.seek(SECTOR_SIZE)
        with pytest.raises(InvalidInputFormat, match="label checksum"):
            LVM2Handler().calculate_chunk(file, SECTOR_SIZE)


def test_calculate_chunk_rejects_label_after_first_four_sectors():
    label_sector = 4
    pv = _build_pv(
        label_sector=label_sector,
        locations=[(SECTOR_SIZE, METADATA, 0)],
    )

    with File.from_bytes(pv) as file:
        label_offset = label_sector * SECTOR_SIZE
        file.seek(label_offset)
        with pytest.raises(InvalidInputFormat, match="label header"):
            LVM2Handler().calculate_chunk(file, label_offset)


def test_extract_rejects_invalid_metadata_area_header(tmp_path: Path):
    pv = bytearray(_build_pv(locations=[(SECTOR_SIZE, METADATA, 0)]))
    pv[MDA_OFFSET + 4] = 0

    with pytest.raises(InvalidInputFormat, match="metadata area header"):
        _extract(tmp_path, bytes(pv))


def test_extract_rejects_invalid_metadata_checksum(tmp_path: Path):
    pv = bytearray(_build_pv(locations=[(SECTOR_SIZE, METADATA, 0)]))
    pv[MDA_OFFSET + SECTOR_SIZE] ^= 1

    with pytest.raises(InvalidInputFormat, match="metadata checksum"):
        _extract(tmp_path, bytes(pv))


@pytest.mark.parametrize(
    "metadata,error",
    [
        ("}", "Unexpected closing brace"),
        ("vg {", "Unclosed section"),
        ("status = [\n", "Unclosed list"),
    ],
)
def test_parse_metadata_rejects_unbalanced_syntax(metadata: str, error: str):
    with pytest.raises(InvalidInputFormat, match=error):
        parse_lvm_metadata(metadata)
