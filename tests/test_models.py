import json
from pathlib import Path

import pytest

from unblob.file_utils import InvalidInputFormat
from unblob.models import (
    Chunk,
    ProcessResult,
    Task,
    TaskResult,
    UnknownChunk,
    ValidChunk,
    to_json,
)
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
            pytest.param(
                Chunk(start_offset=0, end_offset=10),
                Chunk(start_offset=1, end_offset=2),
                True,
                id="starts-after-ends-before",
            ),
            pytest.param(
                Chunk(start_offset=0, end_offset=10),
                Chunk(start_offset=11, end_offset=12),
                False,
                id="starts-after-ends-after",
            ),
            pytest.param(
                Chunk(start_offset=0, end_offset=10),
                Chunk(start_offset=15, end_offset=20),
                False,
                id="starts-after-ends-after",
            ),
            pytest.param(
                Chunk(start_offset=1, end_offset=2),
                Chunk(start_offset=3, end_offset=5),
                False,
                id="starts-after-ends-after",
            ),
            pytest.param(
                Chunk(start_offset=0, end_offset=10),
                Chunk(start_offset=1, end_offset=10),
                True,
                id="starts-after-ends-same",
            ),
            pytest.param(
                Chunk(start_offset=0, end_offset=10),
                Chunk(start_offset=0, end_offset=9),
                True,
                id="starts-same-ends-before",
            ),
            pytest.param(
                Chunk(start_offset=0, end_offset=10),
                Chunk(start_offset=0, end_offset=10),
                False,
                id="starts-same-ends-same",
            ),
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
            pytest.param(
                Chunk(start_offset=0x1, end_offset=0x2),
                0x0,
                False,
                id="offset_before_chunk",
            ),
            pytest.param(
                Chunk(start_offset=0x0, end_offset=0x2),
                0x0,
                True,
                id="offset_start_of_chunk",
            ),
            pytest.param(
                Chunk(start_offset=0x0, end_offset=0x2),
                0x1,
                True,
                id="offset_inside_chunk",
            ),
            pytest.param(
                Chunk(start_offset=0x0, end_offset=0x2), 0x2, False, id="offset_after"
            ),
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
            Chunk(start_offset=start_offset, end_offset=end_offset)


class Test_to_json:  # noqa: N801
    def test_process_result_conversion(self):
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
        report = ExtractCommandFailedReport(
            command="dump all bytes",
            stdout=bytes(range(256)),
            stderr=b"stdout is pretty strange ;)",
            exit_code=1,
        )

        json_text = to_json(report)

        decoded_report = json.loads(json_text)

        assert decoded_report == {
            "severity": "WARNING",
            "command": "dump all bytes",
            "stdout": "\x00\x01\x02\x03\x04\x05\x06\x07\x08"
            "\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16"
            "\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,"
            "-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]"
            "^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\udc80\udc81"
            "\udc82\udc83\udc84\udc85\udc86\udc87\udc88\udc89"
            "\udc8a\udc8b\udc8c\udc8d\udc8e\udc8f\udc90\udc91"
            "\udc92\udc93\udc94\udc95\udc96\udc97\udc98\udc99"
            "\udc9a\udc9b\udc9c\udc9d\udc9e\udc9f\udca0\udca1"
            "\udca2\udca3\udca4\udca5\udca6\udca7\udca8\udca9"
            "\udcaa\udcab\udcac\udcad\udcae\udcaf\udcb0\udcb1"
            "\udcb2\udcb3\udcb4\udcb5\udcb6\udcb7\udcb8\udcb9"
            "\udcba\udcbb\udcbc\udcbd\udcbe\udcbf\udcc0\udcc1"
            "\udcc2\udcc3\udcc4\udcc5\udcc6\udcc7\udcc8\udcc9"
            "\udcca\udccb\udccc\udccd\udcce\udccf\udcd0\udcd1"
            "\udcd2\udcd3\udcd4\udcd5\udcd6\udcd7\udcd8\udcd9"
            "\udcda\udcdb\udcdc\udcdd\udcde\udcdf\udce0\udce1"
            "\udce2\udce3\udce4\udce5\udce6\udce7\udce8\udce9"
            "\udcea\udceb\udcec\udced\udcee\udcef\udcf0\udcf1"
            "\udcf2\udcf3\udcf4\udcf5\udcf6\udcf7\udcf8\udcf9"
            "\udcfa\udcfb\udcfc\udcfd\udcfe\udcff",
            "stderr": "stdout is pretty strange ;)",
            "exit_code": 1,
            "__typename__": "ExtractCommandFailedReport",
        }

    @pytest.mark.parametrize(
        "metadata",
        [
            pytest.param(1, id="metadata_int"),
            pytest.param(0.2, id="metadata_float"),
            pytest.param(True, id="metadata_bool"),
            pytest.param([1, 2], id="metadata_list"),
            pytest.param((1, 2), id="metadata_tuple"),
        ],
    )
    def test_invalid_metadata(self, metadata):
        with pytest.raises(ValueError, match="Can only convert dict or Instance"):
            ValidChunk(start_offset=0, end_offset=100, metadata=metadata)
