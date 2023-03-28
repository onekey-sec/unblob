"""Tests for [not] cleaning up extracted files.

The tests use zip files as inputs - for simplicity
"""
import io
import zipfile
from pathlib import Path

import pytest

from unblob.models import File, Handler, Regex, ValidChunk
from unblob.processing import ExtractionConfig, process_file
from unblob.testing import check_result

_ZIP_CONTENT = b"good file"
# replacing _ZIP_CONTENT with _DAMAGED_ZIP_CONTENT will result in CRC error at unpacking time
_DAMAGED_ZIP_CONTENT = b"*BAD*file"


def wrapzip(filename: str, content: bytes) -> bytes:
    """Create an in-memory zip archive with a single file"""
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
        entropy_depth=0,
    )

    all_reports = process_file(config, input_file)
    assert list(output_dir.glob("**/*.zip")) == []
    check_result(all_reports)


def test_keep_all_problematic_chunks(input_file: Path, output_dir: Path):
    input_file.write_bytes(DAMAGED_ZIP_BYTES)
    config = ExtractionConfig(
        extract_root=output_dir,
        entropy_depth=0,
    )

    all_reports = process_file(config, input_file)
    # damaged zip file should not be removed
    assert all_reports.errors != [], "Unexpectedly no errors found!"
    assert list(output_dir.glob("**/*.zip"))


def test_keep_all_unknown_chunks(input_file: Path, output_dir: Path):
    input_file.write_bytes(b"unknown1" + ZIP_BYTES + b"unknown2")
    config = ExtractionConfig(
        extract_root=output_dir,
        entropy_depth=0,
    )

    all_reports = process_file(config, input_file)
    assert list(output_dir.glob("**/*.unknown"))
    check_result(all_reports)


class _HandlerWithNullExtractor(Handler):
    NAME = "null"
    EXTRACTOR = None
    PATTERNS = [Regex(".")]

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk:
        return ValidChunk(start_offset=start_offset, end_offset=start_offset + 1)


def test_keep_chunks_with_null_extractor(input_file: Path, output_dir: Path):
    input_file.write_bytes(b"some text")
    config = ExtractionConfig(
        extract_root=output_dir,
        entropy_depth=0,
        handlers=(_HandlerWithNullExtractor,),
    )
    all_reports = process_file(config, input_file)
    assert list(output_dir.glob("**/*.null"))
    check_result(all_reports)
