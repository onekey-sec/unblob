from pathlib import Path
import shutil
import pytest

from unblob.processing import DEFAULT_DEPTH, process_file


TEST_DATA_PATH = Path(__file__).parent / "assets"

TEST_FILES = [p for p in TEST_DATA_PATH.glob("*/**/*") if p.is_file()]
TEST_DIRS = [p.parent for p in TEST_FILES]

TEST_IDS = [
    str(p.relative_to(TEST_DATA_PATH)).replace('/', '.') for p in TEST_FILES
]

@pytest.mark.benchmark(group="param:input_dir")
@pytest.mark.parametrize(
    "input_file, input_dir",
    zip(TEST_FILES, TEST_DIRS),
    ids=TEST_IDS,
)
def bench_compress(input_file, input_dir, tmp_path, benchmark):
    extract_dir = tmp_path.joinpath("extract")

    def setup_benchmark():
        shutil.rmtree(extract_dir, ignore_errors=True)
        extract_dir.mkdir()

    benchmark.pedantic(
        setup=setup_benchmark,
        target=process_file,
        kwargs=dict(
            root=input_dir,
            path=input_file,
            extract_root=extract_dir,
            max_depth=DEFAULT_DEPTH,
        ),
        rounds=1,
        warmup_rounds=1,
    )

