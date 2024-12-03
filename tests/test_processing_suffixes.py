from pathlib import Path

import pytest

from unblob.processing import ExtractionConfig, process_file
from unblob.report import OutputDirectoryExistsReport
from unblob.testing import check_output_is_the_same

TEST_DATA_PATH = Path(__file__).parent / "files/suffixes"


def _patch(extraction_config: ExtractionConfig, carve_suffix: str, extract_suffix: str):
    extraction_config.keep_extracted_chunks = False
    extraction_config.carve_suffix = carve_suffix
    extraction_config.extract_suffix = extract_suffix


@pytest.mark.parametrize(
    "carve_suffix,extract_suffix,output_root_dir_name",
    [
        ("_extract", "_extract", "defaults"),
        ("_c", "_e", "_c_e"),
        ("_carve", "_extract", "_carve_extract"),
    ],
)
def test_top_level_carve(
    carve_suffix: str,
    extract_suffix: str,
    output_root_dir_name: str,
    extraction_config: ExtractionConfig,
):
    _patch(extraction_config, carve_suffix, extract_suffix)
    input_file = TEST_DATA_PATH / "__input__/chunks"
    carve_dir_name = input_file.name + extraction_config.carve_suffix
    extract_dir_name = input_file.name + extraction_config.extract_suffix
    expected_output_dir = TEST_DATA_PATH / "__outputs__/chunks" / output_root_dir_name

    reports = process_file(extraction_config, input_file)

    assert reports.errors == []

    assert (
        carve_dir_name == extract_dir_name
        or not (extraction_config.extract_root / extract_dir_name).exists()
    )
    check_output_is_the_same(expected_output_dir, extraction_config.extract_root)


EXPECTED_COLLISION_PATHS: "dict[tuple[str, str], set]" = {
    ("_extract", "_extract"): {
        "collisions.zip_extract/chunks_carve/0-160.gzip_extract",
    },
    ("_carve", "_extract"): {
        "collisions.zip_extract/chunks_carve",
        "collisions.zip_extract/chunks_carve/0-160.gzip_extract",
    },
}


@pytest.mark.parametrize(
    "carve_suffix,extract_suffix,output_root_dir_name",
    [
        ("_extract", "_extract", "defaults"),
        ("_c", "_e", "_c_e"),
        ("_carve", "_extract", "_carve_extract"),
    ],
)
def test_top_level_extract_and_collisions(
    carve_suffix: str,
    extract_suffix: str,
    output_root_dir_name: str,
    extraction_config: ExtractionConfig,
):
    _patch(extraction_config, carve_suffix, extract_suffix)
    input_file = TEST_DATA_PATH / "__input__/collisions.zip"
    carve_dir_name = input_file.name + extraction_config.carve_suffix
    extract_dir_name = input_file.name + extraction_config.extract_suffix
    expected_output_dir = (
        TEST_DATA_PATH / "__outputs__/collisions.zip" / output_root_dir_name
    )

    reports = process_file(extraction_config, input_file)

    # check collision problems - the input was prepared to have collisions
    # during both the carving and extracting phases
    problem_paths = {
        e.path.relative_to(extraction_config.extract_root).as_posix()
        for e in reports.errors
        if isinstance(e, OutputDirectoryExistsReport)
    }
    key = (carve_suffix, extract_suffix)
    assert problem_paths == EXPECTED_COLLISION_PATHS.get(key, set())
    # we expect only OutputDirectoryExistsReport-s
    assert len(reports.errors) == len(problem_paths)

    assert (
        carve_dir_name == extract_dir_name
        or not (extraction_config.extract_root / carve_dir_name).exists()
    )
    check_output_is_the_same(expected_output_dir, extraction_config.extract_root)
