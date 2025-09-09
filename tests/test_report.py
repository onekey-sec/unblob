import io
import json
from pathlib import Path
from unittest.mock import ANY
from zipfile import ZipFile, ZipInfo

import pytest

from unblob.models import ProcessResult, Task, TaskResult
from unblob.processing import ExtractionConfig, process_file
from unblob.report import (
    CarveDirectoryReport,
    ChunkReport,
    FileMagicReport,
    HashReport,
    StatReport,
    UnknownChunkReport,
)


@pytest.fixture
def input_file(tmp_path: Path) -> Path:
    input_file = tmp_path / "input_file"
    input_file.write_bytes(bytes(range(256)))
    return input_file


@pytest.fixture
def extract_root(tmp_path: Path) -> Path:
    return tmp_path / "extract_root"


@pytest.fixture
def report_file(tmp_path: Path) -> Path:
    return tmp_path / "report.json"


def test_process_file_report_output_is_valid_json(
    input_file: Path, extract_root: Path, report_file: Path
):
    assert not report_file.exists()

    config = ExtractionConfig(extract_root=extract_root, randomness_depth=0)
    process_file(config, input_file, report_file)

    # output must be a valid json file, that is not empty
    report = json.loads(report_file.read_text())
    assert len(report)


@pytest.fixture
def hello_kitty(tmp_path: Path) -> Path:
    """Generate an input file with 3 unknown chunks and 2 zip files."""
    hello_zip = io.BytesIO()
    with ZipFile(hello_zip, "w") as zf:
        zf.writestr(ZipInfo("hello.kitty"), "Hello")

    kitty_zip = io.BytesIO()
    with ZipFile(kitty_zip, "w") as zf:
        zf.writestr(ZipInfo("hello.kitty"), "Kitty")

    content = (
        b"Hello " + hello_zip.getvalue() + b" Kitty " + kitty_zip.getvalue() + b"!"
    )

    hello_kitty = tmp_path / "hello_kitty"
    hello_kitty.write_bytes(content)
    return hello_kitty


def hello_kitty_task_results(
    hello_kitty: Path,
    extract_root: Path,
    hello_id: str,
    kitty_id: str,
    padding_id: str,
    container_id="",
    start_depth=0,
):
    """Return expected task reports processing `hello_kitty` fixture.

    Note, that it has parameters for ids, which would change between runs.

    Note, that for some values the `unittest.mock.ANY` is substituted.
    This is done so as to ignore platform related differences.

    Platform differences due to libmagic:

    - on ubuntu latest/20.04 "Zip archive data, at least v2.0 to extract"
    - on nix(github)         "Zip archive data, at least v2.0 to extract, compression method=store"

    Resolution:

    - `FileMagicReport(magic=ANY)`

    Platform stat differences for directories:

    - on ext4 directory sizes are reported as 4096
    - on tmpfs directory sizes are reported as 60

    Resolution:

    - `StatReport(size=ANY)`
    """
    return [
        TaskResult(
            task=Task(path=hello_kitty, depth=start_depth, blob_id=container_id),
            reports=[
                StatReport(
                    path=hello_kitty,
                    size=264,
                    is_dir=False,
                    is_file=True,
                    is_link=False,
                    link_target=None,
                ),
                FileMagicReport(magic="data", mime_type="application/octet-stream"),
                HashReport(
                    md5="9db962e810e645c4d230c6bdf59c31b1",
                    sha1="febca6ed75dc02e0def065e7b08f1cca87b57c74",
                    sha256="144d8b2c949cb4943128aa0081153bcba4f38eb0ba26119cc06ca1563c4999e1",
                ),
                CarveDirectoryReport(carve_dir=extract_root / "hello_kitty_extract"),
                UnknownChunkReport.model_construct(
                    id=ANY,
                    start_offset=0,
                    end_offset=6,
                    size=6,
                    randomness=None,
                ),
                UnknownChunkReport.model_construct(
                    id=ANY,
                    start_offset=131,
                    end_offset=138,
                    size=7,
                    randomness=None,
                ),
                ChunkReport(
                    id=padding_id,
                    start_offset=263,
                    end_offset=264,
                    size=1,
                    handler_name="padding",
                    is_encrypted=False,
                    extraction_reports=[],
                ),
                ChunkReport(
                    id=hello_id,
                    handler_name="zip",
                    start_offset=6,
                    end_offset=131,
                    size=125,
                    is_encrypted=False,
                    extraction_reports=[],
                ),
                ChunkReport(
                    id=kitty_id,
                    handler_name="zip",
                    start_offset=138,
                    end_offset=263,
                    size=125,
                    is_encrypted=False,
                    extraction_reports=[],
                ),
            ],
            subtasks=[
                Task(
                    path=extract_root / "hello_kitty_extract/6-131.zip_extract",
                    depth=start_depth + 1,
                    blob_id=hello_id,
                ),
                Task(
                    path=extract_root / "hello_kitty_extract/138-263.zip_extract",
                    depth=start_depth + 1,
                    blob_id=kitty_id,
                ),
            ],
        ),
        TaskResult(
            task=Task(
                path=extract_root / "hello_kitty_extract/138-263.zip_extract",
                depth=start_depth + 1,
                blob_id=kitty_id,
            ),
            reports=[
                StatReport.model_construct(
                    path=extract_root / "hello_kitty_extract/138-263.zip_extract",
                    size=ANY,
                    is_dir=True,
                    is_file=False,
                    is_link=False,
                    link_target=None,
                )
            ],
            subtasks=[
                Task(
                    path=extract_root
                    / "hello_kitty_extract/138-263.zip_extract/hello.kitty",
                    depth=start_depth + 1,
                    blob_id=kitty_id,
                )
            ],
        ),
        TaskResult(
            task=Task(
                path=extract_root
                / "hello_kitty_extract/138-263.zip_extract/hello.kitty",
                depth=start_depth + 1,
                blob_id=kitty_id,
            ),
            reports=[
                StatReport(
                    path=extract_root
                    / "hello_kitty_extract/138-263.zip_extract/hello.kitty",
                    size=5,
                    is_dir=False,
                    is_file=True,
                    is_link=False,
                    link_target=None,
                ),
                FileMagicReport(
                    magic="ASCII text, with no line terminators", mime_type="text/plain"
                ),
                HashReport(
                    md5="798903d076fdd1a8245ada3adfef6483",
                    sha1="a33027811ed9a95dc65084c59ae0560b81734d54",
                    sha256="4f0063d4dca40aa3cbcf69841070df91b2ea198ba97c150137f60350651c202d",
                ),
            ],
            subtasks=[],
        ),
        TaskResult(
            task=Task(
                path=extract_root / "hello_kitty_extract/6-131.zip_extract",
                depth=start_depth + 1,
                blob_id=hello_id,
            ),
            reports=[
                StatReport.model_construct(
                    path=extract_root / "hello_kitty_extract/6-131.zip_extract",
                    size=ANY,
                    is_dir=True,
                    is_file=False,
                    is_link=False,
                    link_target=None,
                )
            ],
            subtasks=[
                Task(
                    path=extract_root
                    / "hello_kitty_extract/6-131.zip_extract/hello.kitty",
                    depth=start_depth + 1,
                    blob_id=hello_id,
                )
            ],
        ),
        TaskResult(
            task=Task(
                path=extract_root / "hello_kitty_extract/6-131.zip_extract/hello.kitty",
                depth=start_depth + 1,
                blob_id=hello_id,
            ),
            reports=[
                StatReport(
                    path=extract_root
                    / "hello_kitty_extract/6-131.zip_extract/hello.kitty",
                    size=5,
                    is_dir=False,
                    is_file=True,
                    is_link=False,
                    link_target=None,
                ),
                FileMagicReport(
                    magic="ASCII text, with no line terminators", mime_type="text/plain"
                ),
                HashReport(
                    md5="8b1a9953c4611296a827abf8c47804d7",
                    sha1="f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0",
                    sha256="185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
                ),
            ],
            subtasks=[],
        ),
    ]


def test_flat_report_structure(hello_kitty: Path, extract_root):
    config = ExtractionConfig(extract_root=extract_root, randomness_depth=0)
    process_result = process_file(config, hello_kitty)
    task_results = get_normalized_task_results(process_result)

    # extract the ids from the chunks
    padding_id, hello_id, kitty_id = get_chunk_ids(task_results[0])

    assert task_results == hello_kitty_task_results(
        hello_kitty=hello_kitty,
        extract_root=extract_root,
        hello_id=hello_id,
        kitty_id=kitty_id,
        padding_id=padding_id,
    )


def container_task_results(
    container: Path, extract_root: Path, chunk_id: str
) -> list[TaskResult]:
    """Return expected partial task results for processing the `hello_kitty_container` fixture.

    Note, that for some values the `unittest.mock.ANY` is substituted.
    This is done so as to ignore platform related differences.

    Platform differences due to libmagic:

    - on ubuntu latest/20.04 "Zip archive data, at least v2.0 to extract"
    - on nix(github)         "Zip archive data, at least v2.0 to extract, compression method=store"

    Resolution:

    - `FileMagicReport(magic=ANY)`

    Platform stat differences for directories:

    - on ext4 directory sizes are reported as 4096
    - on tmpfs directory sizes are reported as 60

    Resolution:

    - `StatReport(size=ANY)`
    """
    return [
        TaskResult(
            task=Task(
                path=container,
                depth=0,
                blob_id="",
            ),
            reports=[
                StatReport(
                    path=container,
                    size=384,
                    is_dir=False,
                    is_file=True,
                    is_link=False,
                    link_target=None,
                ),
                FileMagicReport.model_construct(
                    magic=ANY,
                    mime_type="application/zip",
                ),
                HashReport(
                    md5="2392a3f8acf4fa53df566ece92980e1a",
                    sha1="93b9b836567468f6a9a306256685c146ec6a06d6",
                    sha256="6bce74badefcddf3020d156f80c99bac7f3d46cd145029d9034a86bfbb5e31aa",
                ),
                ChunkReport(
                    id=chunk_id,
                    handler_name="zip",
                    start_offset=0,
                    end_offset=384,
                    size=384,
                    is_encrypted=False,
                    extraction_reports=[],
                ),
            ],
            subtasks=[
                Task(
                    path=extract_root / "container_extract",
                    depth=1,
                    blob_id=chunk_id,
                )
            ],
        ),
        TaskResult(
            task=Task(
                path=extract_root / "container_extract",
                depth=1,
                blob_id=chunk_id,
            ),
            reports=[
                StatReport.model_construct(
                    path=extract_root / "container_extract",
                    size=ANY,
                    is_dir=True,
                    is_file=False,
                    is_link=False,
                    link_target=None,
                )
            ],
            subtasks=[
                Task(
                    path=extract_root / "container_extract/hello_kitty",
                    depth=1,
                    blob_id=chunk_id,
                )
            ],
        ),
    ]


@pytest.fixture
def hello_kitty_container(tmp_path: Path, hello_kitty: Path) -> Path:
    """Further embed `hello_kitty` fixture in a zip container."""
    hello_kitty_container = tmp_path / "container"
    container_zip = io.BytesIO()
    with ZipFile(container_zip, "w") as zf:
        zf.writestr(ZipInfo("hello_kitty"), hello_kitty.read_bytes())
    hello_kitty_container.write_bytes(container_zip.getvalue())
    return hello_kitty_container


def test_chunk_in_chunk_report_structure(hello_kitty_container: Path, extract_root):
    config = ExtractionConfig(extract_root=extract_root, randomness_depth=0)

    process_result = process_file(config, hello_kitty_container)
    task_results = get_normalized_task_results(process_result)

    # the output is expected to show processing due to the outer container,
    # and then the exact same processing as without the container

    # extract the ids from the chunks: these are different for every run,
    # and they should be the only differences
    [main_id] = get_chunk_ids(task_results[0])

    padding_id, hello_id, kitty_id = get_chunk_ids(task_results[2])

    # We test, that the container is referenced from the internal file
    # through the chunk id `main_id`

    expected_results = container_task_results(
        container=hello_kitty_container, extract_root=extract_root, chunk_id=main_id
    ) + hello_kitty_task_results(
        extract_root / "container_extract/hello_kitty",
        extract_root=extract_root / "container_extract",
        hello_id=hello_id,
        kitty_id=kitty_id,
        padding_id=padding_id,
        container_id=main_id,
        start_depth=1,
    )

    assert task_results == expected_results


def get_normalized_task_results(process_result: ProcessResult) -> list[TaskResult]:
    """Normalize away per-run and platform differences."""
    # sort the results - they can potentially have different orders due to multiprocessing
    return sorted(process_result.results, key=lambda tr: (tr.task.depth, tr.task.path))


def get_chunk_ids(task_result) -> list[str]:
    return [chunk_report.id for chunk_report in task_result.filter_reports(ChunkReport)]
