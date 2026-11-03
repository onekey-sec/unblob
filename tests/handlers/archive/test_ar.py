from pathlib import Path

import arpy
import pytest

from unblob.file_utils import File
from unblob.handlers.archive.ar import ArExtractor, ARHandler
from unblob.report import ExtractionProblem, PathTraversalProblem


def ar_member(name: bytes, payload: bytes, *, bsd: bool = True) -> bytes:
    body = name + payload if bsd else payload
    header_name = f"#1/{len(name)}".encode() if bsd else name
    header = (
        header_name.ljust(16)
        + f"{0:<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n".encode()
    )
    assert len(header) == 60
    return header + body + (b"\n" if len(body) % 2 else b"")


@pytest.mark.parametrize(
    "name, bsd, expected",
    [
        pytest.param(b"test.o", True, "test.o", id="bsd-unpadded"),
        pytest.param(b"test.o\0\0\0", True, "test.o", id="bsd-padded"),
        pytest.param(
            b"__.SYMDEF SORTED\0\0\0\0", True, "__.SYMDEF SORTED", id="symbol-table"
        ),
        pytest.param(
            b"long name with spaces \0\0", True, "long name with spaces ", id="spaces"
        ),
        pytest.param(b"test.o/", False, "test.o", id="ordinary"),
        pytest.param(b"\xff.o\0", True, "\ufffd.o", id="invalid-utf8"),
    ],
)
def test_extract_names(tmp_path: Path, name: bytes, bsd: bool, expected: str):
    archive = tmp_path / "input.a"
    payload = b"\0example payload\0\n\0"
    archive.write_bytes(b"!<arch>\n" + ar_member(name, payload, bsd=bsd))
    outdir = tmp_path / "output"

    result = ArExtractor().extract(archive, outdir)

    assert (outdir / expected).read_bytes() == payload
    assert result is not None
    if b"\xff" in name:
        assert len(result.reports) == 1
        assert isinstance(result.reports[0], ExtractionProblem)
        assert result.reports[0].problem == "Path is not a valid UTF/8 string"
    else:
        assert result.reports == []


@pytest.mark.parametrize(
    "name, bsd",
    [
        pytest.param(b"test\0.o\0", True, id="embedded-nul"),
        pytest.param(b"\0test.o", True, id="leading-nul"),
        pytest.param(b"\0\0\0", True, id="only-padding"),
        pytest.param(b"", True, id="empty-bsd-name"),
        pytest.param(b"test.o\0", False, id="nul-in-ordinary-name"),
        pytest.param(b"../bad\0name\0", True, id="embedded-nul-traversal"),
    ],
)
def test_extract_rejects_malformed_names(tmp_path: Path, name: bytes, bsd: bool):
    archive = tmp_path / "input.a"
    archive.write_bytes(
        b"!<arch>\n"
        + ar_member(name, b"invalid", bsd=bsd)
        + ar_member(b"valid.o", b"valid")
    )
    outdir = tmp_path / "output"

    result = ArExtractor().extract(archive, outdir)

    assert (outdir / "valid.o").read_bytes() == b"valid"
    assert list(outdir.iterdir()) == [outdir / "valid.o"]
    assert result is not None
    assert len(result.reports) == 1
    problem = result.reports[0]
    assert isinstance(problem, ExtractionProblem)
    assert problem.path == repr(name)
    assert problem.resolution == "Skipped."


@pytest.mark.parametrize("name", [b"../escape.o", b"../escape.o\0\0"])
def test_extract_keeps_traversal_checks(tmp_path: Path, name: bytes):
    archive = tmp_path / "input.a"
    archive.write_bytes(b"!<arch>\n" + ar_member(name, b"content"))
    outdir = tmp_path / "output"

    result = ArExtractor().extract(archive, outdir)

    assert not (tmp_path / "escape.o").exists()
    assert result is not None
    assert len(result.reports) == 1
    problem = result.reports[0]
    assert isinstance(problem, PathTraversalProblem)
    assert problem.path == "../escape.o"
    assert (outdir / problem.extraction_path).read_bytes() == b"content"


def test_extract_rejects_truncated_member(tmp_path: Path):
    archive = tmp_path / "input.a"
    content = b"!<arch>\n" + ar_member(b"test.o\0\0", b"payload")
    archive.write_bytes(content[:-2])  # Remove a payload byte and archive padding.

    with pytest.raises(arpy.ArchiveAccessError, match="incorrect archive file"):
        ArExtractor().extract(archive, tmp_path / "output")


def test_extract_gnu_long_name(tmp_path: Path):
    name = b"an ordinary GNU extended filename.o"
    archive = tmp_path / "input.a"
    archive.write_bytes(
        b"!<arch>\n"
        + ar_member(b"//", name + b"/\n", bsd=False)
        + ar_member(b"/0", b"content", bsd=False)
    )
    outdir = tmp_path / "output"

    result = ArExtractor().extract(archive, outdir)

    assert (outdir / name.decode()).read_bytes() == b"content"
    assert result is not None
    assert result.reports == []


@pytest.mark.parametrize("offset", [0, 17])
def test_padded_name_chunk_bounds(offset: int):
    content = b"!<arch>\n" + ar_member(b"test.o\0\0", b"payload")
    with File.from_bytes(b"X" * offset + content) as file:
        file.seek(offset)
        chunk = ARHandler().calculate_chunk(file, offset)
    assert chunk is not None
    assert (chunk.start_offset, chunk.end_offset) == (offset, offset + len(content))
