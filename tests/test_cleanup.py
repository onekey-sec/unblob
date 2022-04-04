"""Tests for [not] cleaning up extracted files.

The tests use zip files as inputs - for simplicity
"""
import io
import os
import zipfile
from pathlib import Path

import pytest

from unblob.models import Handler, Handlers, ValidChunk
from unblob.processing import ExtractionConfig, process_file
from unblob.testing import check_reports

_ZIP_CONTENT = b"good file"
# replacing _ZIP_CONTENT with _DAMAGED_ZIP_CONTENT will result in CRC error at unpacking time
_DAMAGED_ZIP_CONTENT = b"*BAD*file"


def _zip_bytes() -> bytes:
    bio = io.BytesIO()
    z = zipfile.ZipFile(bio, mode="w", compression=zipfile.ZIP_STORED)
    z.writestr("content.txt", _ZIP_CONTENT)
    z.close()
    return bio.getvalue()


ZIP_BYTES = _zip_bytes()
DAMAGED_ZIP_BYTES = ZIP_BYTES.replace(_ZIP_CONTENT, _DAMAGED_ZIP_CONTENT)


@pytest.fixture()
def input_dir(tmp_path: Path):
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    return input_dir


@pytest.fixture()
def output_dir(tmp_path):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir


def test_remove_extracted_chunks(input_dir: Path, output_dir: Path):
    (input_dir / "blob").write_bytes(ZIP_BYTES)
    config = ExtractionConfig(
        extract_root=output_dir,
        entropy_depth=0,
    )

    all_reports = process_file(config, path=input_dir)
    assert list(output_dir.glob("**/*.zip")) == []
    check_reports(all_reports)


def test_keep_all_problematic_chunks(input_dir: Path, output_dir: Path):
    (input_dir / "blob").write_bytes(DAMAGED_ZIP_BYTES)
    config = ExtractionConfig(
        extract_root=output_dir,
        entropy_depth=0,
    )

    all_reports = process_file(config, path=input_dir)
    # damaged zip file should not be removed
    assert all_reports.errors != [], "Unexpectedly no errors found!"
    assert list(output_dir.glob("**/*.zip"))


def test_keep_all_unknown_chunks(input_dir: Path, output_dir: Path):
    (input_dir / "blob").write_bytes(b"unknown1" + ZIP_BYTES + b"unknown2")
    config = ExtractionConfig(
        extract_root=output_dir,
        entropy_depth=0,
    )

    all_reports = process_file(config, path=input_dir)
    assert list(output_dir.glob("**/*.unknown"))
    check_reports(all_reports)


class _HandlerWithNullExtractor(Handler):
    NAME = "null"
    EXTRACTOR = None
    YARA_RULE = r"""
        strings:
            $anychar = /./

        condition:
            $anychar
    """

    def calculate_chunk(self, file: io.BufferedIOBase, start_offset: int) -> ValidChunk:
        pos = file.tell()
        length = file.seek(0, os.SEEK_END)
        file.seek(pos, os.SEEK_SET)
        return ValidChunk(start_offset=0, end_offset=length)


def test_keep_chunks_with_null_extractor(input_dir: Path, output_dir: Path):
    (input_dir / "blob").write_text("some text")
    config = ExtractionConfig(
        extract_root=output_dir,
        entropy_depth=0,
        handlers=Handlers([tuple([_HandlerWithNullExtractor])]),
    )
    all_reports = process_file(config, path=input_dir)
    assert list(output_dir.glob("**/*.null"))
    check_reports(all_reports)
