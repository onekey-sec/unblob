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
    ExtractCommandFailedReport,
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


class Test_ProcessResult_to_json:  # noqa: N801
    def test_simple_conversion(self):
        task = Task(path=Path("/nonexistent"), depth=0, blob_id="")
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
            HashReport(
                md5="9019fcece2433ad7f12c077e84537a74",
                sha1="36998218d8f43b69ef3adcadf2e8979e81eed166",
                sha256="7d7ca7e1410b702b0f85d18257aebb964ac34f7fad0a0328d72e765bfcb21118",
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
                metadata={},
                extraction_reports=[],
            )
        )
        task_result.add_subtask(
            Task(
                path=Path("/extractions/nonexistent_extract"),
                depth=314,
                blob_id=chunk_id,
            )
        )

        json_text = ProcessResult(results=[task_result]).to_json()

        # output must be a valid json string
        assert isinstance(json_text, str)

        # that can be loaded back
        decoded_report = json.loads(json_text)
        assert decoded_report == [
            {
                "task": {
                    "path": "/nonexistent",
                    "depth": 0,
                    "blob_id": "",
                    "is_multi_file": False,
                    "__typename__": "Task",
                },
                "reports": [
                    {
                        "path": "/nonexistent",
                        "size": 384,
                        "is_dir": False,
                        "is_file": True,
                        "is_link": False,
                        "link_target": None,
                        "__typename__": "StatReport",
                    },
                    {
                        "magic": "Zip archive data, at least v2.0 to extract",
                        "mime_type": "application/zip",
                        "__typename__": "FileMagicReport",
                    },
                    {
                        "md5": "9019fcece2433ad7f12c077e84537a74",
                        "sha1": "36998218d8f43b69ef3adcadf2e8979e81eed166",
                        "sha256": "7d7ca7e1410b702b0f85d18257aebb964ac34f7fad0a0328d72e765bfcb21118",
                        "__typename__": "HashReport",
                    },
                    {
                        "id": "test_basic_conversion:id",
                        "handler_name": "zip",
                        "start_offset": 0,
                        "end_offset": 384,
                        "size": 384,
                        "is_encrypted": False,
                        "metadata": {},
                        "extraction_reports": [],
                        "__typename__": "ChunkReport",
                    },
                ],
                "subtasks": [
                    {
                        "path": "/extractions/nonexistent_extract",
                        "depth": 314,
                        "blob_id": "test_basic_conversion:id",
                        "is_multi_file": False,
                        "__typename__": "Task",
                    }
                ],
                "__typename__": "TaskResult",
            }
        ]

    def test_exotic_command_output(self):
        task = Task(path=Path("/nonexistent"), depth=0, blob_id="")
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
                "task": {
                    "path": "/nonexistent",
                    "depth": 0,
                    "blob_id": "",
                    "is_multi_file": False,
                    "__typename__": "Task",
                },
                "reports": [
                    {
                        "id": "test",
                        "handler_name": "fail",
                        "start_offset": 0,
                        "end_offset": 256,
                        "size": 256,
                        "is_encrypted": False,
                        "metadata": {},
                        "extraction_reports": [
                            {
                                "severity": "WARNING",
                                "command": "dump all bytes",
                                "stdout": "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\udc80\udc81\udc82\udc83\udc84\udc85\udc86\udc87\udc88\udc89\udc8a\udc8b\udc8c\udc8d\udc8e\udc8f\udc90\udc91\udc92\udc93\udc94\udc95\udc96\udc97\udc98\udc99\udc9a\udc9b\udc9c\udc9d\udc9e\udc9f\udca0\udca1\udca2\udca3\udca4\udca5\udca6\udca7\udca8\udca9\udcaa\udcab\udcac\udcad\udcae\udcaf\udcb0\udcb1\udcb2\udcb3\udcb4\udcb5\udcb6\udcb7\udcb8\udcb9\udcba\udcbb\udcbc\udcbd\udcbe\udcbf\udcc0\udcc1\udcc2\udcc3\udcc4\udcc5\udcc6\udcc7\udcc8\udcc9\udcca\udccb\udccc\udccd\udcce\udccf\udcd0\udcd1\udcd2\udcd3\udcd4\udcd5\udcd6\udcd7\udcd8\udcd9\udcda\udcdb\udcdc\udcdd\udcde\udcdf\udce0\udce1\udce2\udce3\udce4\udce5\udce6\udce7\udce8\udce9\udcea\udceb\udcec\udced\udcee\udcef\udcf0\udcf1\udcf2\udcf3\udcf4\udcf5\udcf6\udcf7\udcf8\udcf9\udcfa\udcfb\udcfc\udcfd\udcfe\udcff",
                                "stderr": "stdout is pretty strange ;)",
                                "exit_code": 1,
                                "__typename__": "ExtractCommandFailedReport",
                            }
                        ],
                        "__typename__": "ChunkReport",
                    }
                ],
                "subtasks": [],
                "__typename__": "TaskResult",
            }
        ]


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
                UnknownChunkReport(
                    id=ANY,
                    start_offset=0,
                    end_offset=6,
                    size=6,
                    randomness=None,
                ),
                UnknownChunkReport(
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
                FileMagicReport(
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
