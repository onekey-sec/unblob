from pathlib import Path

import pytest
from rust.test_sandbox import landlock_supported

from unblob.processing import ExtractionConfig
from unblob.sandbox import Sandbox

pytestmark = pytest.mark.skipif(
    not landlock_supported(), reason="Sandboxing only works on Linux"
)


@pytest.fixture
def log_path(tmp_path):
    return tmp_path / "unblob.log"


@pytest.fixture
def extraction_config(extraction_config, tmp_path):
    extraction_config.extract_root = tmp_path / "extract" / "root"
    # parent has to exist
    extraction_config.extract_root.parent.mkdir()
    return extraction_config


@pytest.fixture
def sandbox(extraction_config: ExtractionConfig, log_path: Path):
    return Sandbox(extraction_config, log_path, None)


def test_necessary_resources_can_be_created_in_sandbox(
    sandbox: Sandbox, extraction_config: ExtractionConfig, log_path: Path
):
    directory_in_extract_root = extraction_config.extract_root / "path" / "to" / "dir"
    file_in_extract_root = directory_in_extract_root / "file"
    file_in_tmp_dir = extraction_config.tmp_dir / "tmp_file"
    directory_in_tmp_dir = extraction_config.tmp_dir / "tmp_dir"

    sandbox.run(extraction_config.extract_root.mkdir, parents=True)
    sandbox.run(directory_in_extract_root.mkdir, parents=True)

    sandbox.run(file_in_extract_root.touch)
    sandbox.run(file_in_extract_root.write_text, "file content")

    # log-file is already opened
    log_path.touch()
    sandbox.run(log_path.write_text, "log line")

    sandbox.run(directory_in_tmp_dir.mkdir, parents=True)
    sandbox.run(file_in_tmp_dir.touch)
    sandbox.run(file_in_tmp_dir.write_text, "tmp file content")
    sandbox.run(file_in_tmp_dir.unlink)
    sandbox.run(directory_in_tmp_dir.rmdir)


def test_access_outside_sandbox_is_not_possible(sandbox: Sandbox, tmp_path: Path):
    unrelated_dir = tmp_path / "unrelated" / "path"
    unrelated_file = tmp_path / "unrelated-file"

    with pytest.raises(PermissionError):
        sandbox.run(unrelated_dir.mkdir, parents=True)

    with pytest.raises(PermissionError):
        sandbox.run(unrelated_file.touch)
