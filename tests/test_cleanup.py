"""Tests for [not] cleaning up extracted files.

The tests use zip files as inputs - for simplicity
"""

import io
import zipfile
from pathlib import Path

import pytest

from unblob.extractors import Command
from unblob.handlers.archive.zip import ZIPHandler
from unblob.models import File, Handler, Regex, ValidChunk
from unblob.processing import (
    ExtractedFileDeletionMode,
    ExtractionConfig,
    process_file,
)
from unblob.report import ExtractedFileDeletedReport
from unblob.testing import check_result

_ZIP_CONTENT = b"good file"
# replacing _ZIP_CONTENT with _DAMAGED_ZIP_CONTENT will result in CRC error at unpacking time
_DAMAGED_ZIP_CONTENT = b"*BAD*file"


def wrapzip(filename: str, content: bytes) -> bytes:
    """Create an in-memory zip archive with a single file."""
    bio = io.BytesIO()
    z = zipfile.ZipFile(bio, mode="w", compression=zipfile.ZIP_STORED)
    z.writestr(filename, content)
    z.close()
    return bio.getvalue()


ZIP_BYTES = b"prefix to force carving the zip archive " + wrapzip(
    "content.txt", _ZIP_CONTENT
)
DAMAGED_ZIP_BYTES = ZIP_BYTES.replace(_ZIP_CONTENT, _DAMAGED_ZIP_CONTENT)
assert ZIP_BYTES != DAMAGED_ZIP_BYTES


@pytest.fixture
def input_file(tmp_path: Path):
    return tmp_path / "input_file"


@pytest.fixture
def output_dir(tmp_path):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir


def test_remove_extracted_chunks(input_file: Path, output_dir: Path):
    input_file.write_bytes(ZIP_BYTES)
    config = ExtractionConfig(
        extract_root=output_dir,
        randomness_depth=0,
    )

    all_reports = process_file(config, input_file)
    assert list(output_dir.glob("**/*.zip")) == []
    check_result(all_reports)


def test_keep_all_problematic_chunks(input_file: Path, output_dir: Path):
    input_file.write_bytes(DAMAGED_ZIP_BYTES)
    config = ExtractionConfig(
        extract_root=output_dir,
        randomness_depth=0,
    )

    all_reports = process_file(config, input_file)
    # damaged zip file should not be removed
    assert all_reports.errors != [], "Unexpectedly no errors found!"
    assert list(output_dir.glob("**/*.zip"))


def test_keep_all_unknown_chunks(input_file: Path, output_dir: Path):
    input_file.write_bytes(b"unknown1" + ZIP_BYTES + b"unknown2")
    config = ExtractionConfig(
        extract_root=output_dir,
        randomness_depth=0,
    )

    all_reports = process_file(config, input_file)
    assert list(output_dir.glob("**/*.unknown"))
    check_result(all_reports)


class _HandlerWithNullExtractor(Handler):
    NAME = "null"
    EXTRACTOR = None
    PATTERNS = [Regex(".")]

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk:
        del file  # unused argument
        return ValidChunk(start_offset=start_offset, end_offset=start_offset + 1)


class _FirstChunkHandler(Handler):
    NAME = "first"
    EXTRACTOR = Command("cp", "{inpath}", "{outdir}/first")
    PATTERNS = [Regex("A")]

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk:
        del file
        return ValidChunk(start_offset=start_offset, end_offset=start_offset + 1)


class _SecondChunkHandler(Handler):
    NAME = "second"
    EXTRACTOR = Command("cp", "{inpath}", "{outdir}/second")
    PATTERNS = [Regex("B")]

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk:
        del file
        return ValidChunk(start_offset=start_offset, end_offset=start_offset + 1)


class _FailingSecondChunkHandler(_SecondChunkHandler):
    EXTRACTOR = Command("false")


def test_keep_chunks_with_null_extractor(input_file: Path, output_dir: Path):
    input_file.write_bytes(b"some text")
    config = ExtractionConfig(
        extract_root=output_dir,
        randomness_depth=0,
        handlers=(_HandlerWithNullExtractor,),
    )
    all_reports = process_file(config, input_file)
    assert list(output_dir.glob("**/*.null"))
    check_result(all_reports)


def test_delete_intermediate_files_reported(input_file: Path, output_dir: Path):
    inner_zip = wrapzip("inner.txt", _ZIP_CONTENT)
    outer_zip = wrapzip("inner.zip", inner_zip)
    input_file.write_bytes(outer_zip)

    config = ExtractionConfig(
        extract_root=output_dir,
        randomness_depth=0,
        extracted_file_deletion=ExtractedFileDeletionMode.ALL,
    )

    all_reports = process_file(config, input_file)
    inner_zip_path = output_dir / f"{input_file.name}_extract" / "inner.zip"

    assert not inner_zip_path.exists()
    deleted_reports = [
        report
        for result in all_reports.results
        for report in result.reports
        if isinstance(report, ExtractedFileDeletedReport)
    ]
    assert any(report.path == inner_zip_path for report in deleted_reports)
    check_result(all_reports)


@pytest.mark.parametrize(
    "content,handler_filter,expect_deleted",
    [
        (b"AB", ("first", "second"), True),
        (b"AB", ("first",), False),
        (b"AXB", ("first", "second"), False),
    ],
)
def test_delete_intermediate_file_only_when_fully_covered_by_selected_chunks(
    content: bytes,
    handler_filter: tuple[str, ...],
    expect_deleted: bool,
    input_file: Path,
    output_dir: Path,
):
    input_file.write_bytes(wrapzip("chunks.bin", content))
    config = ExtractionConfig(
        extract_root=output_dir,
        randomness_depth=0,
        handlers=(ZIPHandler, _FirstChunkHandler, _SecondChunkHandler),
        extracted_file_deletion=ExtractedFileDeletionMode.SELECTED,
        extracted_file_handler_filter=handler_filter,
        max_depth=2,
        process_num=1,
    )

    reports = process_file(config, input_file)

    assert reports.errors == []
    assert input_file.exists()
    intermediate_path = output_dir / f"{input_file.name}_extract" / "chunks.bin"
    assert intermediate_path.exists() is not expect_deleted
    deletion_reported = any(
        report.path == intermediate_path and report.handler_name == "first,second"
        for result in reports.results
        for report in result.reports
        if isinstance(report, ExtractedFileDeletedReport)
    )
    assert deletion_reported is expect_deleted


def test_keep_fully_covered_file_when_chunk_extraction_fails(
    input_file: Path, output_dir: Path
):
    input_file.write_bytes(wrapzip("chunks.bin", b"AB"))
    config = ExtractionConfig(
        extract_root=output_dir,
        randomness_depth=0,
        handlers=(ZIPHandler, _FirstChunkHandler, _FailingSecondChunkHandler),
        extracted_file_deletion=ExtractedFileDeletionMode.SELECTED,
        extracted_file_handler_filter=("first", "second"),
        max_depth=2,
        process_num=1,
    )

    reports = process_file(config, input_file)

    assert reports.errors
    assert (output_dir / f"{input_file.name}_extract" / "chunks.bin").exists()
