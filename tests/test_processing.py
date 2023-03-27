import sys
import zipfile
from pathlib import Path
from typing import Collection, List, Tuple

import attr
import pytest

from unblob.models import UnknownChunk, ValidChunk
from unblob.processing import (
    ExtractionConfig,
    calculate_buffer_size,
    calculate_entropy,
    calculate_unknown_chunks,
    draw_entropy_plot,
    process_file,
    remove_inner_chunks,
)
from unblob.report import ExtractDirectoryExistsReport


def assert_same_chunks(expected, actual, explanation=None):
    """An assert, that ignores the chunk.id-s"""

    assert len(expected) == len(actual), explanation
    for (e, a) in zip(expected, actual):
        assert attr.evolve(e, id="") == attr.evolve(a, id=""), explanation


@pytest.mark.parametrize(
    "chunks, expected, explanation",
    [
        ([], [], "Empty list as chunks (No chunk found)"),
        (
            [
                ValidChunk(1, 2),
            ],
            [ValidChunk(1, 2)],
            "Only one chunk",
        ),
        (
            [
                ValidChunk(0, 5),
                ValidChunk(1, 2),
            ],
            [ValidChunk(0, 5)],
            "One chunk within another",
        ),
        (
            [
                ValidChunk(10, 20),
                ValidChunk(11, 13),
                ValidChunk(14, 19),
            ],
            [ValidChunk(10, 20)],
            "Multiple chunks within 1 outer chunk",
        ),
        (
            [
                ValidChunk(11, 13),
                ValidChunk(10, 20),
                ValidChunk(14, 19),
            ],
            [ValidChunk(10, 20)],
            "Multiple chunks within 1 outer chunk, in different order",
        ),
        (
            [
                ValidChunk(1, 5),
                ValidChunk(6, 10),
            ],
            [ValidChunk(1, 5), ValidChunk(6, 10)],
            "Multiple outer chunks",
        ),
        (
            [
                ValidChunk(1, 5),
                ValidChunk(2, 3),
                ValidChunk(6, 10),
                ValidChunk(7, 8),
            ],
            [ValidChunk(1, 5), ValidChunk(6, 10)],
            "Multiple outer chunks, with chunks inside",
        ),
    ],
)
def test_remove_inner_chunks(
    chunks: List[ValidChunk], expected: List[ValidChunk], explanation: str
):
    assert_same_chunks(expected, remove_inner_chunks(chunks), explanation)


@pytest.mark.parametrize(
    "chunks, file_size, expected",
    [
        ([], 0, []),
        ([], 10, []),
        ([ValidChunk(0x0, 0x5)], 5, []),
        ([ValidChunk(0x0, 0x5), ValidChunk(0x5, 0xA)], 10, []),
        ([ValidChunk(0x0, 0x5), ValidChunk(0x5, 0xA)], 12, [UnknownChunk(0xA, 0xC)]),
        ([ValidChunk(0x3, 0x5)], 5, [UnknownChunk(0x0, 0x3)]),
        ([ValidChunk(0x0, 0x5), ValidChunk(0x7, 0xA)], 10, [UnknownChunk(0x5, 0x7)]),
        (
            [ValidChunk(0x8, 0xA), ValidChunk(0x0, 0x5), ValidChunk(0xF, 0x14)],
            20,
            [UnknownChunk(0x5, 0x8), UnknownChunk(0xA, 0xF)],
        ),
    ],
)
def test_calculate_unknown_chunks(
    chunks: List[ValidChunk], file_size: int, expected: List[UnknownChunk]
):
    assert_same_chunks(expected, calculate_unknown_chunks(chunks, file_size))


@pytest.mark.parametrize(
    "file_size, chunk_count, min_limit, max_limit, expected",
    [
        (1000, 1, 10, 100, 100),
        (1000, 10, 10, 100, 100),
        (1000, 100, 10, 100, 10),
    ],
)
def test_calculate_buffer_size(
    file_size: int, chunk_count: int, min_limit: int, max_limit: int, expected: int
):
    assert expected == calculate_buffer_size(
        file_size, chunk_count=chunk_count, min_limit=min_limit, max_limit=max_limit
    )


def test_draw_entropy_plot_error():
    with pytest.raises(TypeError):
        draw_entropy_plot([])


@pytest.mark.parametrize(
    "percentages",
    [
        pytest.param([0.0] * 100, id="zero-array"),
        pytest.param([99.99] * 100, id="99-array"),
        pytest.param([100.0] * 100, id="100-array"),
    ],
)
def test_draw_entropy_plot_no_exception(percentages: List[float]):
    assert draw_entropy_plot(percentages) is None


@pytest.mark.parametrize(
    "path, draw_plot",
    [
        pytest.param(Path(sys.executable), True, id="draw-plot"),
        pytest.param(Path(sys.executable), False, id="no-plot"),
    ],
)
def test_calculate_entropy_no_exception(path: Path, draw_plot: bool):
    assert calculate_entropy(path, draw_plot=draw_plot) is None


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


def mkzip(dir: Path, output: Path):
    with zipfile.ZipFile(output, "x") as zf:
        for path in dir.glob("**/*"):
            zf.write(path, path.relative_to(dir))


@pytest.fixture
def fw(tmp_path: Path):
    # _fixture_fw
    # ├── fw.zip    <------- output
    # ├── internal
    # │   └── fw
    # │       ├── hello
    # │       └── world
    # └── outer
    #     └── fw
    #         └── internal.zip
    base = tmp_path / "_fixture_fw"

    internal = base / "internal"
    (internal / "fw").mkdir(parents=True)
    (internal / "fw/hello").write_bytes(b"hello")
    (internal / "fw/world").write_bytes(b"world")
    outer = base / "outer"
    (outer / "fw").mkdir(parents=True)
    mkzip(internal, outer / "fw/internal.zip")
    mkzip(outer, base / "fw.zip")

    return base / "fw.zip"


def sort_paths(paths: Collection[Path], base: Path) -> Tuple[List[Path], List[Path]]:
    """The paths are sorted into two bins, the first one will contain subpaths of base, the second are not.

    The first bin will also be converted to relative paths.
    """
    subpaths = []
    outsiders = []
    for path in sorted(paths):
        try:
            subpaths.append(path.relative_to(base))
        except ValueError:
            outsiders.append(path)
    return subpaths, outsiders


def test_process_file_prevents_double_extracts(tmp_path: Path, fw: Path):
    # fw_extract_root
    # └── fw.zip_extract
    #     └── fw
    #         ├── internal.zip
    #         └── internal.zip_extract
    #             └── fw
    #                 ├── hello
    #                 └── world
    fw_extract_root = tmp_path / "fw_extract_root"
    config = ExtractionConfig(extract_root=fw_extract_root, entropy_depth=0)
    process_result = process_file(config, fw)
    assert process_result.errors == []
    extracted_fw_paths, outsiders = sort_paths(
        [t.task.path for t in process_result.results], base=fw_extract_root
    )
    assert outsiders == [fw]

    extracted_fw_zip = tmp_path / "extracted_fw.zip"
    mkzip(fw_extract_root, extracted_fw_zip)

    # fw_extract_of_extract_root
    # └── extracted_fw.zip_extract
    #     └── fw.zip_extract
    #         └── fw
    #             ├── internal.zip
    #             └── internal.zip_extract
    #                 └── fw
    #                     ├── hello
    #                     └── world
    fw_extract_of_extract_root = tmp_path / "fw_extract_of_extract_root"
    config = ExtractionConfig(extract_root=fw_extract_of_extract_root, entropy_depth=0)
    process_result = process_file(config, extracted_fw_zip)

    # we expect exactly 1 problem reported, related to the extraction of "internal.zip"
    [report] = process_result.errors
    assert isinstance(report, ExtractDirectoryExistsReport)
    assert report.path.name == "internal.zip_extract"

    # the rest should be the same, except that the extraction is shifted with one extra directory
    # please note, that repeated processing is also excluded with the below checks
    # "internal.zip_extract" and thus its content must not be processed twice!
    extracted_extracted_fw_paths, outsiders = sort_paths(
        [t.task.path for t in process_result.results],
        base=fw_extract_of_extract_root / "extracted_fw.zip_extract",
    )
    assert outsiders == [extracted_fw_zip]

    assert extracted_extracted_fw_paths == [Path(".")] + extracted_fw_paths
