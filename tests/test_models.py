import json
from pathlib import Path

import pytest

from unblob.file_utils import InvalidInputFormat
from unblob.models import Chunk, ProcessResult, Task, TaskResult, UnknownChunk, to_json
from unblob.report import (
    ChunkReport,
    ExtractCommandFailedReport,
    FileMagicReport,
    HashReport,
    StatReport,
)


class TestChunk:
    @pytest.mark.parametrize(
        "chunk1, chunk2, result",
        [
            (Chunk(0, 10), Chunk(1, 2), True),
            (Chunk(0, 10), Chunk(11, 12), False),
            (Chunk(0, 10), Chunk(15, 20), False),
            (Chunk(1, 2), Chunk(3, 5), False),
            (Chunk(0, 10), Chunk(1, 10), True),
        ],
    )
    def test_contains(self, chunk1, chunk2, result):
        assert chunk1.contains(chunk2) is result

    def test_range_hex(self):
        chunk = UnknownChunk(start_offset=3, end_offset=10)
        assert chunk.range_hex == "0x3-0xa"

    @pytest.mark.parametrize(
        "chunk, offset, expected",
        [
            pytest.param(Chunk(0x1, 0x2), 0x0, False, id="offset_before_chunk"),
            pytest.param(Chunk(0x0, 0x2), 0x0, True, id="offset_start_of_chunk"),
            pytest.param(Chunk(0x0, 0x2), 0x1, True, id="offset_inside_chunk"),
            pytest.param(Chunk(0x0, 0x2), 0x2, False, id="offset_after"),
        ],
    )
    def test_contains_offset(self, chunk, offset, expected):
        assert expected is chunk.contains_offset(offset)

    @pytest.mark.parametrize(
        "start_offset, end_offset",
        [
            pytest.param(-0x1, 0x5, id="negative_start_offset"),
            pytest.param(-0x1, -0x5, id="negative_chunk"),
            pytest.param(0x1, -0x5, id="negative_end_offset"),
            pytest.param(0x5, 0x5, id="same_offset"),
            pytest.param(0x6, 0x5, id="higher_start_offset"),
        ],
    )
    def test_validation(self, start_offset, end_offset):
        with pytest.raises(InvalidInputFormat):
            Chunk(start_offset, end_offset)


class Test_to_json:  # noqa: N801
    def test_process_result_conversion(self):
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
            HashReport(
                md5="9019fcece2433ad7f12c077e84537a74",
                sha1="36998218d8f43b69ef3adcadf2e8979e81eed166",
                sha256="7d7ca7e1410b702b0f85d18257aebb964ac34f7fad0a0328d72e765bfcb21118",
            )
        )
        task_result.add_report(
            ChunkReport(
                chunk_id=chunk_id,
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
                        "__typename__": "HashReport",
                        "md5": "9019fcece2433ad7f12c077e84537a74",
                        "sha1": "36998218d8f43b69ef3adcadf2e8979e81eed166",
                        "sha256": "7d7ca7e1410b702b0f85d18257aebb964ac34f7fad0a0328d72e765bfcb21118",
                    },
                    {
                        "__typename__": "ChunkReport",
                        "end_offset": 384,
                        "extraction_reports": [],
                        "handler_name": "zip",
                        "chunk_id": "test_basic_conversion:id",
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
        report = ExtractCommandFailedReport(
            command="dump all bytes",
            stdout=bytes(range(256)),
            stderr=b"stdout is pretty strange ;)",
            exit_code=1,
        )

        json_text = to_json(report)

        decoded_report = json.loads(json_text)

        assert decoded_report == {
            "__typename__": "ExtractCommandFailedReport",
            "command": "dump all bytes",
            "exit_code": 1,
            "severity": "WARNING",
            "stderr": "stdout is pretty strange ;)",
            "stdout": (
                "b'\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07"
                "\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f"
                "\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17"
                '\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f !"#'
                "$%&\\'()*+,-./0123456789:;<=>?@AB"
                "CDEFGHIJKLMNOPQRSTUVWXYZ[\\\\]^_`a"
                "bcdefghijklmnopqrstuvwxyz{|}~\\x7f"
                "\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87"
                "\\x88\\x89\\x8a\\x8b\\x8c\\x8d\\x8e\\x8f"
                "\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97"
                "\\x98\\x99\\x9a\\x9b\\x9c\\x9d\\x9e\\x9f"
                "\\xa0\\xa1\\xa2\\xa3\\xa4\\xa5\\xa6\\xa7"
                "\\xa8\\xa9\\xaa\\xab\\xac\\xad\\xae\\xaf"
                "\\xb0\\xb1\\xb2\\xb3\\xb4\\xb5\\xb6\\xb7"
                "\\xb8\\xb9\\xba\\xbb\\xbc\\xbd\\xbe\\xbf"
                "\\xc0\\xc1\\xc2\\xc3\\xc4\\xc5\\xc6\\xc7"
                "\\xc8\\xc9\\xca\\xcb\\xcc\\xcd\\xce\\xcf"
                "\\xd0\\xd1\\xd2\\xd3\\xd4\\xd5\\xd6\\xd7"
                "\\xd8\\xd9\\xda\\xdb\\xdc\\xdd\\xde\\xdf"
                "\\xe0\\xe1\\xe2\\xe3\\xe4\\xe5\\xe6\\xe7"
                "\\xe8\\xe9\\xea\\xeb\\xec\\xed\\xee\\xef"
                "\\xf0\\xf1\\xf2\\xf3\\xf4\\xf5\\xf6\\xf7"
                "\\xf8\\xf9\\xfa\\xfb\\xfc\\xfd\\xfe\\xff"
                "'"
            ),
        }
