from pathlib import Path

import pytest

from unblob.tasks import ExtractionConfig


@pytest.mark.parametrize(
    "extract_root, path, result",
    [
        ("/extract", "firmware", "/extract/firmware_extract"),
        ("/extract", "relative/firmware", "/extract/firmware_extract"),
        ("/extract", "/extract/dir/firmware", "/extract/dir/firmware_extract"),
        (
            "/extract/dir",
            "/extract/dir/firmware",
            "/extract/dir/firmware_extract",
        ),
        ("/extract", "/some/place/else/firmware", "/extract/firmware_extract"),
        (
            "extract",
            "/some/place/else/firmware",
            str(Path(".").resolve() / "extract/firmware_extract"),
        ),
    ],
)
def test_ExtractionConfig_get_extract_dir_for(
    extract_root: str, path: str, result: str
):
    cfg = ExtractionConfig(extract_root=Path(extract_root), entropy_depth=0)
    assert cfg.get_extract_dir_for(Path(path)) == Path(result)
