from pathlib import Path

import pytest

from unblob.processing import ExtractionConfig
from unblob.sandbox import Sandbox
from unblob.testing import is_sandbox_available

pytestmark = pytest.mark.skipif(
    not is_sandbox_available(), reason="Sandboxing only works on Linux"
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

    sandbox.run(extraction_config.extract_root.mkdir, parents=True)
    sandbox.run(directory_in_extract_root.mkdir, parents=True)

    sandbox.run(file_in_extract_root.touch)
    sandbox.run(file_in_extract_root.write_text, "file content")

    # log-file is already opened
    log_path.touch()
    sandbox.run(log_path.write_text, "log line")


def test_access_outside_sandbox_is_not_possible(sandbox: Sandbox, tmp_path: Path):
    unrelated_dir = tmp_path / "unrelated" / "path"
    unrelated_file = tmp_path / "unrelated-file"

    with pytest.raises(PermissionError):
        sandbox.run(unrelated_dir.mkdir, parents=True)

    with pytest.raises(PermissionError):
        sandbox.run(unrelated_file.touch)
