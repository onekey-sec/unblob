from pathlib import Path

import pytest

from unblob.file_utils import round_up
from unblob.handlers.executable.pe._headers import DataDirectory
from unblob.handlers.executable.pe._nsis import (
    NSIS_FLAG_NO_CRC,
    NSISExtractor,
    NSISPayload,
)
from unblob.handlers.executable.pe.pe import PEChunk, PEHandler
from unblob.models import ExtractError
from unblob.report import ExtractionProblem
from unblob.testing import (
    PE_CERTIFICATE_SIZE,
    PE_E_LFANEW,
    PE_END,
    PE_PREFIX,
    PE_SECTION_SIZE,
    PE_SECTION_TABLE_END,
    PE_SIZE_OF_HEADERS,
    PE_STRUCTS,
    PE_SUFFIX,
    build_nsis_data,
    build_pe,
    calculate_chunk,
    find_chunks,
    with_nsis,
)

# NSIS installers


@pytest.mark.parametrize("plus", [False, True], ids=["pe32", "pe32+"])
@pytest.mark.parametrize(
    "section_size",
    [PE_SECTION_SIZE, PE_SECTION_SIZE - 0x10],
    ids=["aligned", "unaligned"],
)
def test_nsis_installer(section_size: int, plus: bool):
    installer = with_nsis(build_pe(plus=plus, section_size=section_size))
    content = PE_PREFIX + installer + PE_SUFFIX

    assert find_chunks(PEHandler, content) == [
        (len(PE_PREFIX), len(PE_PREFIX) + len(installer))
    ]
    chunk = calculate_chunk(PEHandler, content, len(PE_PREFIX))
    assert isinstance(chunk, PEChunk)
    assert isinstance(chunk.payload, NSISPayload)


def test_truncated_nsis_installer():
    installer = with_nsis(build_pe())
    assert find_chunks(PEHandler, PE_PREFIX + installer[:-1]) == []


def test_nsis_after_debug_data():
    # e.g. a stub with CodeView data after its last section: the installer data
    # follows it, so the image end must include it
    debug_size = 0x2C
    pe = build_pe(debug_entries=[(PE_END, debug_size)]) + b"\xdd" * debug_size
    installer = with_nsis(pe)

    assert find_chunks(PEHandler, installer) == [(0, len(installer))]


def test_e_lfanew_above_64k_is_not_matched():
    e_lfanew = 0x10000
    pe = build_pe(section={"size_of_raw_data": 0})
    content = (
        PE_STRUCTS.dos_header_t(e_magic=b"MZ", e_lfanew=e_lfanew)
        .dumps()
        .ljust(e_lfanew, b"\0")
        + pe[PE_E_LFANEW:PE_SECTION_TABLE_END]
    )
    installer = with_nsis(content)

    # the handler accepts it, only the pattern skips it
    assert calculate_chunk(PEHandler, installer) is not None
    assert find_chunks(PEHandler, installer) == []


def test_nsis_firstheader_off_boundary_is_ignored():
    content = build_pe() + b"\x00" + build_nsis_data()
    assert calculate_chunk(PEHandler, content) is None


def test_nsis_magic_inside_section_is_ignored():
    pe = build_pe(section_data=build_nsis_data(payload_size=0))
    assert calculate_chunk(PEHandler, pe + PE_SUFFIX) is None


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"siginfo": 0xDEADBEEE}, id="siginfo"),
        pytest.param({"nsinst": b"NullsoftInsX"}, id="magic"),
        pytest.param({"flags": 0x10}, id="unknown-flags"),
        pytest.param({"length_of_all_following_data": 27}, id="length-too-small"),
    ],
)
def test_invalid_nsis_firstheader_is_not_claimed(overrides: dict):
    content = build_pe() + build_nsis_data(**overrides)
    assert calculate_chunk(PEHandler, content) is None


# Authenticode certificate table, after the installer data


def build_signed_installer(payload_size: int, certificate_offset: int) -> bytes:
    pe = build_pe(
        data_directories={
            DataDirectory.SECURITY: (certificate_offset, PE_CERTIFICATE_SIZE)
        }
    )
    return with_nsis(pe, payload_size)


@pytest.mark.parametrize(
    "payload_size",
    # the firstheader is 28 bytes: 28 + 0x104 is 8 byte aligned, 28 + 0x100 is not
    [0x104, 0x100],
    ids=["aligned", "unaligned"],
)
def test_authenticode_certificate_table_is_included(payload_size: int):
    installer_size = PE_END + PE_STRUCTS.nsis_firstheader_t.size + payload_size
    # the certificate table is 8 byte aligned and addressed by file offset
    certificate_offset = round_up(installer_size, 8)
    installer = build_signed_installer(payload_size, certificate_offset)
    assert len(installer) == installer_size
    signed = (
        installer.ljust(certificate_offset, b"\x00") + b"\xcc" * PE_CERTIFICATE_SIZE
    )

    assert find_chunks(PEHandler, PE_PREFIX + signed + PE_SUFFIX) == [
        (len(PE_PREFIX), len(PE_PREFIX) + len(signed))
    ]


def test_certificate_table_after_overlay_is_not_included():
    # e.g. data appended to a signed installer: it is left to other handlers
    overlay = b"\xbb" * 0x100
    payload_size = 0x104
    installer_size = PE_END + PE_STRUCTS.nsis_firstheader_t.size + payload_size
    installer = build_signed_installer(payload_size, installer_size + len(overlay))
    content = installer + overlay + b"\xcc" * PE_CERTIFICATE_SIZE

    chunk = calculate_chunk(PEHandler, content)
    assert chunk is not None
    assert chunk.end_offset == len(installer)


def test_empty_certificate_table_is_ignored():
    payload_size = 0x100
    installer_size = PE_END + PE_STRUCTS.nsis_firstheader_t.size + payload_size
    pe = build_pe(
        data_directories={DataDirectory.SECURITY: (round_up(installer_size, 8), 0)}
    )
    installer = with_nsis(pe, payload_size)

    chunk = calculate_chunk(PEHandler, installer + PE_SUFFIX)
    assert chunk is not None
    assert chunk.end_offset == len(installer)


# CRC, verified on extraction


@pytest.fixture
def seven_zip_calls(monkeypatch: pytest.MonkeyPatch) -> list:
    """Replace the 7-Zip command of the NSIS extractor, recording its calls."""
    calls = []
    monkeypatch.setattr(
        nsis_extractor().command,
        "extract",
        lambda inpath, outdir: calls.append((inpath, outdir)),
    )
    return calls


def nsis_extractor() -> NSISExtractor:
    extractor = NSISPayload.extractor
    assert isinstance(extractor, NSISExtractor)
    return extractor


def extract_nsis(tmp_path: Path, installer: bytes):
    inpath = tmp_path / "installer.exe"
    inpath.write_bytes(installer)
    outdir = tmp_path / "out"
    outdir.mkdir()
    return inpath, outdir, NSISPayload.extractor.extract(inpath, outdir)


def corrupt_crc(installer: bytes, offset: int = -1) -> bytes:
    corrupted = bytearray(installer)
    corrupted[offset] ^= 0xFF
    return bytes(corrupted)


def test_nsis_crc_matches(tmp_path: Path, seven_zip_calls: list):
    inpath, outdir, result = extract_nsis(tmp_path, with_nsis(build_pe()))

    assert result is not None
    assert result.reports == []
    assert seven_zip_calls == [(inpath, outdir)]


def test_nsis_crc_mismatch_is_reported_and_extracted(
    tmp_path: Path, seven_zip_calls: list
):
    inpath, outdir, result = extract_nsis(tmp_path, corrupt_crc(with_nsis(build_pe())))

    assert result is not None
    assert len(result.reports) == 1
    problem = result.reports[0]
    assert isinstance(problem, ExtractionProblem)
    assert "CRC mismatch" in problem.problem
    assert problem.resolution == "Extracted anyway"
    assert seven_zip_calls == [(inpath, outdir)]


@pytest.mark.usefixtures("seven_zip_calls")
def test_nsis_crc_covers_the_stub(tmp_path: Path):
    # a byte of the stub after its first 512 bytes, as modified by e.g. upx
    installer = corrupt_crc(with_nsis(build_pe()), offset=PE_SIZE_OF_HEADERS)
    _, _, result = extract_nsis(tmp_path, installer)

    assert result is not None
    assert len(result.reports) == 1


@pytest.mark.usefixtures("seven_zip_calls")
def test_nsis_crc_skips_the_first_512_bytes(tmp_path: Path):
    # e.g. the DOS stub: not covered by the CRC
    installer = corrupt_crc(with_nsis(build_pe()), offset=0x100)
    _, _, result = extract_nsis(tmp_path, installer)

    assert result is not None
    assert result.reports == []


@pytest.mark.usefixtures("seven_zip_calls")
def test_nsis_without_crc_check_is_not_verified(tmp_path: Path):
    installer = corrupt_crc(with_nsis(build_pe(), flags=NSIS_FLAG_NO_CRC))
    _, _, result = extract_nsis(tmp_path, installer)

    assert result is not None
    assert result.reports == []


@pytest.mark.usefixtures("seven_zip_calls")
def test_nsis_crc_excludes_the_certificate_table(tmp_path: Path):
    payload_size = 0x104
    installer_size = PE_END + PE_STRUCTS.nsis_firstheader_t.size + payload_size
    installer = build_signed_installer(payload_size, installer_size)
    signed = installer + b"\xcc" * PE_CERTIFICATE_SIZE
    _, _, result = extract_nsis(tmp_path, signed)

    assert result is not None
    assert result.reports == []


def test_nsis_crc_problem_is_kept_when_7z_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    failure = ExtractionProblem(problem="7-Zip failed", resolution="Skipped")

    def fail(*_):
        raise ExtractError(failure)

    monkeypatch.setattr(nsis_extractor().command, "extract", fail)
    with pytest.raises(ExtractError) as exc_info:
        extract_nsis(tmp_path, corrupt_crc(with_nsis(build_pe())))

    crc_problem, reported_failure = exc_info.value.reports
    assert isinstance(crc_problem, ExtractionProblem)
    assert "CRC mismatch" in crc_problem.problem
    assert reported_failure is failure


def test_nsis_extraction_without_installer_data_fails(
    tmp_path: Path, seven_zip_calls: list
):
    with pytest.raises(ExtractError):
        extract_nsis(tmp_path, build_pe())
    assert seven_zip_calls == []
