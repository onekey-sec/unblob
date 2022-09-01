import io
import json
from pathlib import Path
from typing import List
from unittest.mock import ANY
from zipfile import ZipFile, ZipInfo

import pytest

from unblob.models import ProcessResult, Task, TaskResult
from unblob.processing import ExtractionConfig, process_file
from unblob.report import (
    ChunkReport,
    ExtractCommandFailedReport,
    FileMagicReport,
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

    config = ExtractionConfig(extract_root=extract_root, entropy_depth=0)
    process_file(config, input_file, report_file)

    # output must be a valid json file, that is not empty
    report = json.loads(report_file.read_text())
    assert len(report)


class Test_ProcessResult_to_json:
    def test_simple_conversion(self):
        task = Task(path=Path("/nonexistent"), depth=0, chunk_id="")
        task_result = TaskResult(task)
        chunk_id = "test_basic_conversion:id"

        task_result.add_report(
            StatReport(
                path=task.path,
                size=384,
                is_dir=False,
                is_file=True,
                is_link=False,
                link_target=None,
            )
        )
        task_result.add_report(
            FileMagicReport(
                magic="Zip archive data, at least v2.0 to extract",
                mime_type="application/zip",
            )
        )
        task_result.add_report(
            ChunkReport(
                id=chunk_id,
                handler_name="zip",
                start_offset=0,
                end_offset=384,
                size=384,
                is_encrypted=False,
                extraction_reports=[],
            )
        )
        task_result.add_subtask(
            Task(
                path=Path("/extractions/nonexistent_extract"),
                depth=314,
                chunk_id=chunk_id,
            )
        )

        json_text = ProcessResult(results=[task_result]).to_json()

        # output must be a valid json string
        assert isinstance(json_text, str)

        # that can be loaded back
        decoded_report = json.loads(json_text)
        assert decoded_report == [
            {
                "__typename__": "TaskResult",
                "reports": [
                    {
                        "__typename__": "StatReport",
                        "is_dir": False,
                        "is_file": True,
                        "is_link": False,
                        "link_target": None,
                        "path": "/nonexistent",
                        "size": 384,
                    },
                    {
                        "__typename__": "FileMagicReport",
                        "magic": "Zip archive data, at least v2.0 to extract",
                        "mime_type": "application/zip",
                    },
                    {
                        "__typename__": "ChunkReport",
                        "end_offset": 384,
                        "extraction_reports": [],
                        "handler_name": "zip",
                        "id": "test_basic_conversion:id",
                        "is_encrypted": False,
                        "size": 384,
                        "start_offset": 0,
                    },
                ],
                "subtasks": [
                    {
                        "__typename__": "Task",
                        "chunk_id": "test_basic_conversion:id",
                        "depth": 314,
                        "path": "/extractions/nonexistent_extract",
                    }
                ],
                "task": {
                    "__typename__": "Task",
                    "chunk_id": "",
                    "depth": 0,
                    "path": "/nonexistent",
                },
            },
        ]

    def test_exotic_command_output(self):
        task = Task(path=Path("/nonexistent"), depth=0, chunk_id="")
        task_result = TaskResult(task)
        report = ExtractCommandFailedReport(
            command="dump all bytes",
            stdout=bytes(range(256)),
            stderr=b"stdout is pretty strange ;)",
            exit_code=1,
        )

        task_result.add_report(
            ChunkReport(
                id="test",
                handler_name="fail",
                start_offset=0,
                end_offset=256,
                size=256,
                is_encrypted=False,
                extraction_reports=[report],
            )
        )
        json_text = ProcessResult(results=[task_result]).to_json()

        decoded_report = json.loads(json_text)

        assert decoded_report == [
            {
                "__typename__": "TaskResult",
                "reports": [
                    {
                        "__typename__": "ChunkReport",
                        "end_offset": 256,
                        "extraction_reports": [
                            {
                                "__typename__": "ExtractCommandFailedReport",
                                "command": "dump all bytes",
                                "exit_code": 1,
                                "severity": "WARNING",
                                "stderr": "stdout is pretty strange ;)",
                                "stdout": (
                                    "b'\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07"
                                    + "\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f"
                                    + "\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17"
                                    + '\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f !"#'
                                    + "$%&\\'()*+,-./0123456789:;<=>?@AB"
                                    + "CDEFGHIJKLMNOPQRSTUVWXYZ[\\\\]^_`a"
                                    + "bcdefghijklmnopqrstuvwxyz{|}~\\x7f"
                                    + "\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87"
                                    + "\\x88\\x89\\x8a\\x8b\\x8c\\x8d\\x8e\\x8f"
                                    + "\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97"
                                    + "\\x98\\x99\\x9a\\x9b\\x9c\\x9d\\x9e\\x9f"
                                    + "\\xa0\\xa1\\xa2\\xa3\\xa4\\xa5\\xa6\\xa7"
                                    + "\\xa8\\xa9\\xaa\\xab\\xac\\xad\\xae\\xaf"
                                    + "\\xb0\\xb1\\xb2\\xb3\\xb4\\xb5\\xb6\\xb7"
                                    + "\\xb8\\xb9\\xba\\xbb\\xbc\\xbd\\xbe\\xbf"
                                    + "\\xc0\\xc1\\xc2\\xc3\\xc4\\xc5\\xc6\\xc7"
                                    + "\\xc8\\xc9\\xca\\xcb\\xcc\\xcd\\xce\\xcf"
                                    + "\\xd0\\xd1\\xd2\\xd3\\xd4\\xd5\\xd6\\xd7"
                                    + "\\xd8\\xd9\\xda\\xdb\\xdc\\xdd\\xde\\xdf"
                                    + "\\xe0\\xe1\\xe2\\xe3\\xe4\\xe5\\xe6\\xe7"
                                    + "\\xe8\\xe9\\xea\\xeb\\xec\\xed\\xee\\xef"
                                    + "\\xf0\\xf1\\xf2\\xf3\\xf4\\xf5\\xf6\\xf7"
                                    + "\\xf8\\xf9\\xfa\\xfb\\xfc\\xfd\\xfe\\xff"
                                    + "'"
                                ),
                            }
                        ],
                        "handler_name": "fail",
                        "id": "test",
                        "is_encrypted": False,
                        "size": 256,
                        "start_offset": 0,
                    }
                ],
                "subtasks": [],
                "task": {
                    "__typename__": "Task",
                    "chunk_id": "",
                    "depth": 0,
                    "path": "/nonexistent",
                },
            }
        ]


@pytest.fixture
def hello_kitty(tmp_path: Path) -> Path:
    """An input file with 3 unknown chunks and 2 zip files."""
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
    container_id="",
    start_depth=0,
):
    """Expected task reports processing `hello_kitty` fixture.

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
            task=Task(path=hello_kitty, depth=start_depth, chunk_id=container_id),
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
                UnknownChunkReport(id=ANY, start_offset=0, end_offset=6, size=6),
                UnknownChunkReport(id=ANY, start_offset=131, end_offset=138, size=7),
                UnknownChunkReport(id=ANY, start_offset=263, end_offset=264, size=1),
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
                    chunk_id=hello_id,
                ),
                Task(
                    path=extract_root / "hello_kitty_extract/138-263.zip_extract",
                    depth=start_depth + 1,
                    chunk_id=kitty_id,
                ),
            ],
        ),
        TaskResult(
            task=Task(
                path=extract_root / "hello_kitty_extract/138-263.zip_extract",
                depth=start_depth + 1,
                chunk_id=kitty_id,
            ),
            reports=[
                StatReport(
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
                    chunk_id=kitty_id,
                )
            ],
        ),
        TaskResult(
            task=Task(
                path=extract_root
                / "hello_kitty_extract/138-263.zip_extract/hello.kitty",
                depth=start_depth + 1,
                chunk_id=kitty_id,
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
            ],
            subtasks=[],
        ),
        TaskResult(
            task=Task(
                path=extract_root / "hello_kitty_extract/6-131.zip_extract",
                depth=start_depth + 1,
                chunk_id=hello_id,
            ),
            reports=[
                StatReport(
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
                    chunk_id=hello_id,
                )
            ],
        ),
        TaskResult(
            task=Task(
                path=extract_root / "hello_kitty_extract/6-131.zip_extract/hello.kitty",
                depth=start_depth + 1,
                chunk_id=hello_id,
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
            ],
            subtasks=[],
        ),
    ]


def test_flat_report_structure(hello_kitty: Path, extract_root):
    config = ExtractionConfig(extract_root=extract_root, entropy_depth=0)
    process_result = process_file(config, hello_kitty)
    task_results = get_normalized_task_results(process_result)

    # extract the ids from the chunks
    hello_id, kitty_id = get_chunk_ids(task_results[0])

    assert task_results == hello_kitty_task_results(
        hello_kitty=hello_kitty,
        extract_root=extract_root,
        hello_id=hello_id,
        kitty_id=kitty_id,
    )


def container_task_results(
    container: Path, extract_root: Path, chunk_id: str
) -> List[TaskResult]:
    """Expected partial task results for processing the `hello_kitty_container` fixture.

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
                chunk_id="",
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
                FileMagicReport(
                    magic=ANY,
                    mime_type="application/zip",
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
                    chunk_id=chunk_id,
                )
            ],
        ),
        TaskResult(
            task=Task(
                path=extract_root / "container_extract",
                depth=1,
                chunk_id=chunk_id,
            ),
            reports=[
                StatReport(
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
                    chunk_id=chunk_id,
                )
            ],
        ),
    ]


@pytest.fixture
def hello_kitty_container(tmp_path: Path, hello_kitty: Path) -> Path:
    """The `hello_kitty` fixture further embedded in a zip container."""
    hello_kitty_container = tmp_path / "container"
    container_zip = io.BytesIO()
    with ZipFile(container_zip, "w") as zf:
        zf.writestr(ZipInfo("hello_kitty"), hello_kitty.read_bytes())
    hello_kitty_container.write_bytes(container_zip.getvalue())
    return hello_kitty_container


def test_chunk_in_chunk_report_structure(hello_kitty_container: Path, extract_root):
    config = ExtractionConfig(extract_root=extract_root, entropy_depth=0)

    process_result = process_file(config, hello_kitty_container)
    task_results = get_normalized_task_results(process_result)

    # the output is expected to show processing due to the outer container,
    # and then the exact same processing as without the container

    # extract the ids from the chunks: these are different for every run,
    # and they should be the only differences
    [main_id] = get_chunk_ids(task_results[0])

    hello_id, kitty_id = get_chunk_ids(task_results[2])

    # We test, that the container is referenced from the internal file
    # through the chunk id `main_id`

    expected_results = container_task_results(
        container=hello_kitty_container, extract_root=extract_root, chunk_id=main_id
    ) + hello_kitty_task_results(
        extract_root / "container_extract/hello_kitty",
        extract_root=extract_root / "container_extract",
        hello_id=hello_id,
        kitty_id=kitty_id,
        container_id=main_id,
        start_depth=1,
    )

    assert task_results == expected_results


def get_normalized_task_results(process_result: ProcessResult) -> List[TaskResult]:
    """Normalize away per-run and platform differences."""
    # sort the results - they can potentially have different orders due to multiprocessing
    task_results = sorted(
        process_result.results, key=lambda tr: (tr.task.depth, tr.task.path)
    )
    return task_results


def get_chunk_ids(task_result) -> List[str]:
    return [
        chunk_report.id
        for chunk_report in task_result.reports
        if isinstance(chunk_report, ChunkReport)
    ]
