import pytest

from unblob.handlers.executable.pe import _upx
from unblob.handlers.executable.pe._headers import DataDirectory
from unblob.handlers.executable.pe._nsis import NSISPayload
from unblob.handlers.executable.pe._upx import UPXFormat, UPXPayload
from unblob.handlers.executable.pe.pe import PEChunk, PEHandler
from unblob.testing import (
    PE_CERTIFICATE_SIZE,
    PE_PREFIX,
    PE_SIZE_OF_HEADERS,
    PE_SUFFIX,
    UPX_PACKHEADER_OFFSET,
    UPX_PE_END,
    UPX_SECTION_TABLE_END,
    UPX_SIZE_OF_IMAGE,
    build_upx_packheader,
    build_upx_pe,
    calculate_chunk,
    find_chunks,
    with_nsis,
)

# UPX packed PE files

# packheaders written by upx 4.2.2 for the zip2exe.upx.exe (PE32, NRV2B) and
# pageant.upx.exe (PE32+, --lzma) integration inputs
UPX_PACKHEADER_PE32 = bytes.fromhex(
    "55505821 0d 09 02 08 414fce9e fb21a97c 6c870000 ed250000 005a0000 26 01 00 06"
)
UPX_PACKHEADER_PE32_PLUS = bytes.fromhex(
    "55505821 0d 24 0e 07 2ebf838c 2aee4354 7bd90800 281c0300 58ae0800 49 11 00 1f"
)


@pytest.mark.parametrize(
    "fields, real",
    [
        pytest.param({}, UPX_PACKHEADER_PE32, id="pe32"),
        pytest.param(
            {
                "format": UPXFormat.W64PE_AMD64,
                "method": 14,
                "level": 7,
                "u_adler": 0x8C83BF2E,
                "c_adler": 0x5443EE2A,
                "u_len": 0x8D97B,
                "c_len": 0x31C28,
                "u_file_size": 0x8AE58,
                "filter": 0x49,
                "filter_cto": 0x11,
            },
            UPX_PACKHEADER_PE32_PLUS,
            id="pe32+",
        ),
    ],
)
def test_packheader_matches_upx(fields: dict, real: bytes):
    # pins the structure and the checksum to what upx writes
    overrides = {"c_len": 0x25ED} | fields
    assert build_upx_packheader(**overrides) == real


@pytest.mark.parametrize("plus", [False, True], ids=["pe32", "pe32+"])
def test_upx_packed_pe(plus: bool):
    packed = build_upx_pe(plus=plus)
    assert len(packed) == UPX_PE_END
    # the suffix stands for an overlay: it is not part of the chunk
    content = PE_PREFIX + packed + PE_SUFFIX

    assert find_chunks(PEHandler, content) == [
        (len(PE_PREFIX), len(PE_PREFIX) + UPX_PE_END)
    ]
    chunk = calculate_chunk(PEHandler, content, len(PE_PREFIX))
    assert isinstance(chunk, PEChunk)
    assert isinstance(chunk.payload, UPXPayload)


def test_upx_packheader_running_into_section_data():
    # as in pageant.upx.exe: the packheader starts in the headers, ends in UPX1
    packed = build_upx_pe(packheader_offset=PE_SIZE_OF_HEADERS - 3)
    chunk = calculate_chunk(PEHandler, packed)
    assert isinstance(chunk, PEChunk)
    assert isinstance(chunk.payload, UPXPayload)


def test_upx_packheader_right_after_section_table():
    packed = build_upx_pe(packheader_offset=UPX_SECTION_TABLE_END)
    chunk = calculate_chunk(PEHandler, packed)
    assert isinstance(chunk, PEChunk)
    assert isinstance(chunk.payload, UPXPayload)


def test_upx_certificate_table_is_included():
    # a UPX packed file signed after packing
    packed = build_upx_pe(
        data_directories={DataDirectory.SECURITY: (UPX_PE_END, PE_CERTIFICATE_SIZE)}
    )
    signed = packed + b"\xcc" * PE_CERTIFICATE_SIZE
    assert find_chunks(PEHandler, signed + PE_SUFFIX) == [(0, len(signed))]


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param(
            {"packheader": build_upx_packheader(magic=b"UPX?")}, id="no-magic"
        ),
        pytest.param(
            {"packheader": build_upx_packheader(header_checksum=0)}, id="checksum"
        ),
        pytest.param({"packheader": build_upx_packheader(version=9)}, id="version"),
        pytest.param(
            {"packheader": build_upx_packheader(format=21)}, id="unknown-format"
        ),
        pytest.param(
            {"packheader": build_upx_packheader(format=UPXFormat.W64PE_AMD64)},
            id="format-machine-mismatch",
        ),
        pytest.param(
            {"packheader": build_upx_packheader(c_len=UPX_PE_END + 1)}, id="c-len"
        ),
        pytest.param(
            {"packheader": build_upx_packheader(u_len=UPX_SIZE_OF_IMAGE + 1)},
            id="u-len",
        ),
        pytest.param(
            # inside the section data, where the window ends
            {"packheader_offset": PE_SIZE_OF_HEADERS},
            id="after-first-section-start",
        ),
        pytest.param(
            # inside the section table, before the window starts
            {"packheader_offset": UPX_SECTION_TABLE_END - 4},
            id="in-section-table",
        ),
    ],
)
def test_invalid_upx_packheader_is_not_claimed(kwargs: dict):
    assert calculate_chunk(PEHandler, build_upx_pe(**kwargs)) is None


def test_upx_window_is_bounded(monkeypatch: pytest.MonkeyPatch):
    # a first section starting far after the section table: only the first
    # MAX_UPX_HEADER_WINDOW bytes after the table are searched
    monkeypatch.setattr(_upx, "MAX_UPX_HEADER_WINDOW", 0x10)
    packed = build_upx_pe(packheader_offset=UPX_SECTION_TABLE_END + 0x10)
    assert calculate_chunk(PEHandler, packed) is None


def test_truncated_upx_packheader_is_not_claimed():
    packed = build_upx_pe()
    # the file ends inside the packheader: probing must not raise
    assert calculate_chunk(PEHandler, packed[: UPX_PACKHEADER_OFFSET + 8]) is None


def test_upx_packed_nsis_stub_is_nsis():
    # makensis !packhdr: the installer data is what matters
    installer = with_nsis(build_upx_pe())
    chunk = calculate_chunk(PEHandler, installer)
    assert isinstance(chunk, PEChunk)
    assert isinstance(chunk.payload, NSISPayload)
    assert chunk.end_offset == len(installer)
