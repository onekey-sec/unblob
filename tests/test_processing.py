import platform
import sys
import zipfile
from pathlib import Path
from typing import Collection, List, Tuple, Type, TypeVar

import attr
import pytest

from unblob import handlers
from unblob.models import UnknownChunk, ValidChunk
from unblob.processing import (
    ExtractionConfig,
    calculate_block_size,
    calculate_entropy,
    calculate_unknown_chunks,
    format_entropy_plot,
    process_file,
    remove_inner_chunks,
)
from unblob.report import (
    EntropyReport,
    ExtractDirectoryExistsReport,
    StatReport,
    UnknownChunkReport,
)

T = TypeVar("T")


def assert_same_chunks(expected, actual, explanation=None):
    """Assert ignoring the chunk.id-s."""
    assert len(expected) == len(actual), explanation
    for e, a in zip(expected, actual):
        assert attr.evolve(e, chunk_id="") == attr.evolve(a, chunk_id=""), explanation


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
def test_calculate_block_size(
    file_size: int, chunk_count: int, min_limit: int, max_limit: int, expected: int
):
    assert expected == calculate_block_size(
        file_size,
        chunk_count=chunk_count,
        min_limit=min_limit,
        max_limit=max_limit,
    )


def test_format_entropy_plot_error():
    with pytest.raises(TypeError):
        format_entropy_plot(percentages=[], block_size=1024)


@pytest.mark.parametrize(
    "percentages, block_size",
    [
        pytest.param([0.0] * 100, 1024, id="zero-array"),
        pytest.param([99.99] * 100, 1024, id="99-array"),
        pytest.param([100.0] * 100, 1024, id="100-array"),
        pytest.param([100.0] * 100, -1, id="block_size-can-be-anything1"),
        pytest.param([100.0] * 100, None, id="block_size-can-be-anything2"),
        pytest.param([100.0] * 100, "None", id="block_size-can-be-anything3"),
    ],
)
def test_format_entropy_plot_no_exception(percentages: List[float], block_size: int):
    assert str(block_size) in format_entropy_plot(
        percentages=percentages,
        block_size=block_size,
    )


def test_calculate_entropy_no_exception():
    report = calculate_entropy(Path(sys.executable))
    format_entropy_plot(
        percentages=report.percentages,
        block_size=report.block_size,
    )


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
def test_ExtractionConfig_get_extract_dir_for(  # noqa: N802
    extract_root: str, path: str, result: str
):
    cfg = ExtractionConfig(extract_root=Path(extract_root), entropy_depth=0)
    assert cfg.get_extract_dir_for(Path(path)) == Path(result)


def mkzip(dir_: Path, output: Path):
    with zipfile.ZipFile(output, "x") as zf:
        for path in dir_.glob("**/*"):
            zf.write(path, path.relative_to(dir_))


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
    """Sorts paths into two bins, the first one will contain subpaths of base, the second are not.

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

    assert extracted_extracted_fw_paths == [Path("."), *extracted_fw_paths]


@pytest.mark.skipif(
    platform.system() == "Darwin", reason="non-POSIX path not supported"
)
def test_processing_with_non_posix_paths(tmp_path: Path):
    non_unicode_file = tmp_path / "file-\udce4\udc94"
    non_unicode_file.write_bytes(b"content")

    directory = tmp_path / "dir-\udce4\udc94"
    directory.mkdir(exist_ok=True)
    file_with_non_unicode_dir = directory / "test.txt"
    file_with_non_unicode_dir.write_bytes(b"content")

    extract_root = tmp_path / "extract_root"
    config = ExtractionConfig(extract_root=extract_root, entropy_depth=0)

    for path in (non_unicode_file, file_with_non_unicode_dir):
        process_result = process_file(config, path)
        assert process_result.errors == []
        assert len(process_result.results) == 1
        assert len(process_result.results[0].reports) == 3

        report = process_result.results[0].reports[0]
        assert isinstance(report, StatReport)
        assert report == StatReport(
            path=path,
            size=7,
            is_dir=False,
            is_file=True,
            is_link=False,
            link_target=None,
        )


def test_entropy_calculation(tmp_path: Path):
    """Process a file with unknown chunk and a zip file with entropy calculation enabled.

    The input file structure is
    - zip-chunk
        - empty.txt
        - 0-255.bin
    - unknown_chunk
    """
    #
    # ** input

    input_file = tmp_path / "input-file"
    with zipfile.ZipFile(input_file, "w") as zf:
        zf.writestr("empty.txt", data=b"")
        zf.writestr("0-255.bin", data=bytes(range(256)))

    # entropy is calculated in 1Kb blocks for files smaller than 80Kb
    # so let's have 1 block with 0 entropy, 1 with 6 bit entropy, the rest with 8 bit entropy
    unknown_chunk_content = (
        bytes(1024) + bytes(range(64)) * 4 * 4 + bytes(range(256)) * 4 * 62
    )
    with input_file.open("ab") as f:
        f.write(unknown_chunk_content)

    config = ExtractionConfig(
        extract_root=tmp_path / "extract_root",
        entropy_depth=100,
        entropy_plot=True,
        handlers=(handlers.archive.zip.ZIPHandler,),
    )

    # ** action

    process_result = process_file(config, input_file)

    task_result_by_name = {r.task.path.name: r for r in process_result.results}

    def get_all(file_name, report_type: Type[T]) -> List[T]:
        return [
            r
            for r in task_result_by_name[file_name].reports
            if isinstance(r, report_type)
        ]

    # ** verification

    # the unknown chunk report for the second chunk for the input file should have an entropy report
    # with a percentages (scaled up bits) of 64 items, for 0, 6, 8, 8, ... bits of entropies
    [unknown_chunk_report] = get_all("input-file", UnknownChunkReport)
    unknown_entropy = unknown_chunk_report.entropy
    assert (
        unknown_entropy is not None
    )  # removes pyright complaints for the below lines :(
    assert unknown_entropy.percentages == [0.0, 75.0] + [100.0] * 62
    assert unknown_entropy.block_size == 1024
    assert round(unknown_entropy.mean, 2) == 98.05  # noqa: PLR2004
    assert unknown_entropy.highest == 100.0  # noqa: PLR2004
    assert unknown_entropy.lowest == 0.0  # noqa: PLR2004

    # we should have entropy calculated for files without extractions, except for empty files
    assert [] == get_all("empty.txt", EntropyReport)
    assert [EntropyReport(percentages=[100.0], block_size=1024, mean=100.0)] == get_all(
        "0-255.bin", EntropyReport
    )
