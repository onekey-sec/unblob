from pathlib import Path

import pytest

from unblob.models import ProcessResult, Task, TaskResult
from unblob.report import ExtractCommandFailedReport
from unblob.testing import check_result


def test_check_result_accepts_debugfs_buffer_overflow():
    report = ExtractCommandFailedReport(
        command="debugfs -R 'rdump / output' input",
        stdout=b"",
        stderr=(
            b"debugfs 1.47.0\n"
            b"rdump: No such file or directory while creating symlink\n"
            b"*** buffer overflow detected ***: terminated\n"
        ),
        exit_code=-6,
    )
    result = ProcessResult(
        results=[
            TaskResult(
                task=Task(path=Path("f_badsymlinks.img"), depth=0, blob_id=""),
                reports=[report],
            )
        ]
    )

    check_result(result)


@pytest.mark.parametrize(
    "stderr",
    [
        b"debugfs: unrelated failure\n",
        b"debugfs: unrelated failure\n*** buffer overflow detected ***: terminated\n",
    ],
)
def test_check_result_rejects_other_debugfs_failures(stderr: bytes):
    report = ExtractCommandFailedReport(
        command="debugfs -R 'rdump / output' input",
        stdout=b"",
        stderr=stderr,
        exit_code=1,
    )
    result = ProcessResult(
        results=[
            TaskResult(
                task=Task(path=Path("broken.img"), depth=0, blob_id=""),
                reports=[report],
            )
        ]
    )

    with pytest.raises(AssertionError, match="Unexpected error reports"):
        check_result(result)
