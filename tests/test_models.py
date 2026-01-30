import json
from pathlib import Path

import pytest

from unblob.file_utils import InvalidInputFormat
from unblob.models import (
    Chunk,
    ProcessResult,
    ReportModelAdapter,
    Task,
    TaskResult,
    UnknownChunk,
)
from unblob.report import (
    ChunkReport,
    ExtractCommandFailedReport,
    FileMagicReport,
    HashReport,
    RandomnessMeasurements,
    RandomnessReport,
    Report,
    StatReport,
    UnknownChunkReport,
    register_report_type,
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
        task_result = TaskResult(task=task)
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
                        "id": "test_basic_conversion:id",
                        "is_encrypted": False,
                        "size": 384,
                        "start_offset": 0,
                    },
                ],
                "subtasks": [
                    {
                        "blob_id": "test_basic_conversion:id",
                        "depth": 314,
                        "is_multi_file": False,
                        "path": "/extractions/nonexistent_extract",
                    }
                ],
                "task": {
                    "blob_id": "",
                    "depth": 0,
                    "is_multi_file": False,
                    "path": "/nonexistent",
                },
            },
        ]

    def test_process_result_deserialization(self):
        task = Task(path=Path("/nonexistent"), depth=0, blob_id="")
        task_result = TaskResult(task=task)
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

        process_result = ProcessResult(results=[task_result])

        json_text = process_result.to_json()

        # output must be a valid json string
        assert isinstance(json_text, str)

        # deserialize using ReportModel TypeAdapter
        report_data = ReportModelAdapter.validate_json(json_text)

        # convert to ProcessResult object and compare
        deserialized_process_result = ProcessResult(results=report_data)
        assert process_result == deserialized_process_result

    def test_exotic_command_output(self):
        report = ExtractCommandFailedReport(
            command="dump all bytes",
            stdout=bytes(range(256)),
            stderr=b"stdout is pretty strange ;)",
            exit_code=1,
        )

        json_text = report.model_dump_json()

        decoded_report = ExtractCommandFailedReport.model_validate_json(json_text)

        assert decoded_report == report

        decoded_report = json.loads(json_text)


def test_custom_report_registration_and_deserialization():
    class CustomReport(Report):
        message: str

    register_report_type(CustomReport)

    task = Task(path=Path("/custom"), depth=0, blob_id="")
    custom_report = CustomReport(message="hello")
    chunk_report = ChunkReport(
        id="custom-chunk",
        handler_name="custom",
        start_offset=0,
        end_offset=1,
        size=1,
        is_encrypted=False,
        extraction_reports=[custom_report],
    )

    task_result = TaskResult(task=task, reports=[custom_report, chunk_report])
    process_result = ProcessResult(results=[task_result])

    json_text = process_result.to_json()
    report_data = ReportModelAdapter.validate_json(json_text)

    assert isinstance(report_data[0].reports[0], CustomReport)
    assert isinstance(report_data[0].reports[1], ChunkReport)
    assert isinstance(report_data[0].reports[1].extraction_reports[0], CustomReport)


def test_unknown_chunk_report_randomness_validation():
    randomness = RandomnessReport(
        shannon=RandomnessMeasurements(
            percentages=[0.1, 0.2],
            block_size=2,
            mean=0.15,
        ),
        chi_square=RandomnessMeasurements(
            percentages=[0.3, 0.4],
            block_size=2,
            mean=0.35,
        ),
    )
    randomness_data = randomness.model_dump(mode="json", serialize_as_any=True)

    report = UnknownChunkReport.model_validate(
        {
            "id": "chunk",
            "start_offset": 0,
            "end_offset": 1,
            "size": 1,
            "randomness": randomness_data,
        }
    )

    assert isinstance(report.randomness, RandomnessReport)
