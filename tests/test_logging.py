from pathlib import Path
from typing import Any

import pytest

from unblob.logging import _format_message, noformat


@pytest.mark.parametrize(
    "value, expected",
    (
        (10, "0xa"),
        (0xA, "0xa"),
        ("10", "10"),
        (noformat(10), 10),
        (noformat(Path("/absolute/path")), Path("/absolute/path")),
        (noformat(Path("relative/path")), Path("relative/path")),
        ("/string/absolute/path", "/string/absolute/path"),
        ("string/relative/path", "string/relative/path"),
    ),
)
def test_format_message_dont_care_root_path(value: Any, expected: str):
    assert expected == _format_message(value, Path("dummy/path/does/not/matter"))


@pytest.mark.parametrize(
    "value, extract_root, expected",
    (
        (Path("/a/b/c"), Path("/"), b"a/b/c"),
        (Path("/a/b/c"), Path("/a/b"), b"c"),
        (Path("/a/b/c"), Path(""), b"/a/b/c"),
        (Path("/a/b/c"), Path("qwe"), b"/a/b/c"),
        (Path("/a/b/c"), Path("/q/w/e"), b"/a/b/c"),
    ),
)
def test_format_message_root_path(value: Path, extract_root: Path, expected: str):
    assert expected == _format_message(value, extract_root)
