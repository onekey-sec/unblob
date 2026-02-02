import tarfile
import zlib
from pathlib import Path

import pytest

from unblob.processing import (
    ExtractedFileDeletionMode,
    ExtractionConfig,
    process_file,
)


def _build_zlib_tar(input_dir: Path) -> Path:
    input_dir.mkdir(parents=True, exist_ok=True)
    inner_file = input_dir / "hello.txt"
    inner_file.write_text("hello")

    tar_path = input_dir / "sample.tar"
    with tarfile.open(tar_path, "w") as tar:
        tar.add(inner_file, arcname=inner_file.name)

    input_path = input_dir / "sample.zlib"
    input_path.write_bytes(zlib.compress(tar_path.read_bytes()))
    tar_path.unlink()
    return input_path


@pytest.mark.parametrize(
    "deletion_mode, handler_filter, expect_intermediate",
    [
        (ExtractedFileDeletionMode.NONE, (), True),
        (ExtractedFileDeletionMode.SELECTED, ("gzip",), True),
        (ExtractedFileDeletionMode.SELECTED, ("tar",), False),
        (ExtractedFileDeletionMode.ALL, (), False),
    ],
)
def test_extracted_file_cleanup(
    deletion_mode: ExtractedFileDeletionMode,
    handler_filter: tuple[str, ...],
    expect_intermediate: bool,
    extraction_config: ExtractionConfig,
    tmp_path: Path,
):
    input_path = _build_zlib_tar(tmp_path / "inputs")

    extraction_config.extracted_file_deletion = deletion_mode
    extraction_config.extracted_file_handler_filter = handler_filter
    extraction_config.process_num = 1

    reports = process_file(extraction_config, input_path)

    assert reports.errors == []
    assert input_path.exists()

    gzip_output_dir = extraction_config.get_extract_dir_for(input_path)
    intermediate_tar = gzip_output_dir / "zlib.uncompressed"
    tar_extract_dir = extraction_config.get_extract_dir_for(intermediate_tar)

    assert intermediate_tar.exists() is expect_intermediate
    assert tar_extract_dir.is_dir()
    extracted_file = tar_extract_dir / "hello.txt"
    assert extracted_file.read_text() == "hello"
