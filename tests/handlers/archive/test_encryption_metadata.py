from pathlib import Path

import pytest

from unblob.file_utils import File
from unblob.handlers.archive.rar import RarHandler
from unblob.handlers.archive.zip import ZIPHandler
from unblob.report import EncryptionMetadataReport

TEST_DATA_PATH = Path(__file__).parents[2] / "integration" / "archive"


@pytest.mark.parametrize(
    "handler_type, relative_path, expected",
    [
        pytest.param(
            RarHandler,
            "rar/default/__input__/erdbeere.rar",
            False,
            id="rar-regular",
        ),
        pytest.param(
            RarHandler,
            "rar/password/__input__/cherry_password.rar",
            True,
            id="rar-password-protected",
        ),
        pytest.param(
            RarHandler,
            "rar/encrypted/__input__/cherry_encrypted.rar",
            True,
            id="rar-encrypted-headers",
        ),
        pytest.param(
            ZIPHandler,
            "zip/regular/__input__/apple.zip",
            False,
            id="zip-regular",
        ),
        pytest.param(
            ZIPHandler,
            "zip/encrypted/__input__/apple_encrypted.zip",
            True,
            id="zip-encrypted",
        ),
        pytest.param(
            ZIPHandler,
            "zip/partly_encrypted/__input__/kaki1_aes.zip",
            True,
            id="zip-partly-encrypted",
        ),
    ],
)
def test_archive_encryption_metadata(handler_type, relative_path, expected):
    with File.from_path(TEST_DATA_PATH / relative_path) as file:
        chunk = handler_type().calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.metadata_reports == [EncryptionMetadataReport(is_encrypted=expected)]
    assert chunk.is_encrypted is expected
