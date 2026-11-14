from pathlib import Path

import pytest

from unblob.handlers.executable.pe._nsis import NSISPayload
from unblob.handlers.executable.pe._upx import UPXPayload
from unblob.handlers.executable.pe.pe import PAYLOADS, PEChunk, PEHandler
from unblob.testing import (
    build_pe,
    build_upx_pe,
    calculate_chunk,
    with_nsis,
)

# Extraction


def test_nsis_chunk_is_extracted_with_its_payload_extractor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    calls = []
    monkeypatch.setattr(
        NSISPayload.extractor,
        "extract",
        lambda inpath, outdir: calls.append((inpath, outdir)),
    )
    installer = with_nsis(build_pe())
    chunk = calculate_chunk(PEHandler, installer)
    assert isinstance(chunk, PEChunk)

    inpath = tmp_path / "installer.exe"
    inpath.write_bytes(installer)
    outdir = tmp_path / "out"
    chunk.extract(inpath, outdir)

    assert calls == [(inpath, outdir)]
    assert outdir.is_dir()


def test_upx_chunk_is_extracted_with_its_payload_extractor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    calls = []
    monkeypatch.setattr(
        UPXPayload.extractor,
        "extract",
        lambda inpath, outdir: calls.append((inpath, outdir)),
    )
    packed = build_upx_pe()
    chunk = calculate_chunk(PEHandler, packed)
    assert isinstance(chunk, PEChunk)

    inpath = tmp_path / "packed.exe"
    inpath.write_bytes(packed)
    outdir = tmp_path / "out"
    chunk.extract(inpath, outdir)

    assert calls == [(inpath, outdir)]
    assert outdir.is_dir()


def test_dependencies():
    assert PEHandler.get_dependencies() == ["7z", "upx"]


def test_doc_is_assembled_from_the_payloads():
    doc = PEHandler.DOC
    assert doc is not None
    assert doc.description is not None
    assert "Only NSIS and UPX are recognised." in doc.limitations[0]
    for payload in PAYLOADS:
        assert payload.description in doc.description
        assert all(reference in doc.references for reference in payload.references)
        assert all(limitation in doc.limitations for limitation in payload.limitations)
