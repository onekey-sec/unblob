from pathlib import Path

from unblob.file_utils import File
from unblob.finder import search_chunks
from unblob.handlers.filesystem.extfs import EXTHandler


def test_reduced_oss_fuzz_extfs_input_is_rejected_without_exception_reports(
    task_result,
):
    testcase_path = (
        Path(__file__).parents[2]
        / "integration"
        / "filesystem"
        / "extfs"
        / "__input__"
        / "clusterfuzz-testcase-minimized-search_chunks_fuzzer-5641994765664256"
    )
    data = testcase_path.read_bytes()

    with File.from_bytes(data) as file:
        chunks = search_chunks(file, len(data), (EXTHandler,), task_result)

    assert chunks == []
    assert task_result.reports == []
