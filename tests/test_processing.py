from pathlib import Path
from typing import List

import pytest

from unblob.models import UnknownChunk, ValidChunk
from unblob.processing import (
    ExtractionConfig,
    calculate_buffer_size,
    calculate_entropy,
    calculate_unknown_chunks,
    draw_entropy_plot,
    get_existing_extract_dirs,
    get_extract_dir_for_input,
    remove_inner_chunks,
)


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
    assert expected == remove_inner_chunks(chunks), explanation


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
    assert expected == calculate_unknown_chunks(chunks, file_size)


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
        pytest.param(Path("/proc/self/exe"), True, id="draw-plot"),
        pytest.param(Path("/proc/self/exe"), False, id="no-plot"),
    ],
)
def test_calculate_entropy_no_exception(path: Path, draw_plot: bool):
    assert calculate_entropy(path, draw_plot=draw_plot) is None


@pytest.mark.parametrize(
    "root, path, extract_dir_prefix",
    [
        (".", "firmware", "firmware"),
        ("root", "root/firmware", "firmware"),
        ("root/dir", "root/dir/firmware", "firmware"),
        ("root", "/some/place/else/firmware", "firmware"),
    ],
)
def test_get_extract_dir_for_input(
    root: str, path: str, extract_dir_prefix: str, tmp_path: Path
):
    cfg = ExtractionConfig(extract_root=tmp_path, entropy_depth=0)
    assert get_extract_dir_for_input(cfg, Path(root), Path(path)) == (
        tmp_path / Path(extract_dir_prefix + cfg.extract_suffix)
    )


def test_existing_extract_dirs_can_be_found(tmp_path: Path):
    cfg = ExtractionConfig(extract_root=tmp_path, entropy_depth=0)

    already_extracted_files = [
        Path("have_been_extracted"),
        Path("some_directory") / "also_have_been_extacted",
    ]
    existing_extract_dirs = [
        tmp_path / (e.name + cfg.extract_suffix) for e in already_extracted_files
    ]

    for e in existing_extract_dirs:
        e.mkdir()

    to_be_extracted_files = [
        Path("yet_to_extract"),
        Path("some_other_directory") / "also_yet_to_extract",
    ]
    files_to_extract = already_extracted_files + to_be_extracted_files

    assert get_existing_extract_dirs(cfg, files_to_extract) == existing_extract_dirs
