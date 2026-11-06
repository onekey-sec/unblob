from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.executable.mcuboot import MCUbootHandler, MCUbootMetadataReport

TEST_DATA_PATH = (
    Path(__file__).parents[2] / "integration" / "executable" / "mcuboot" / "__input__"
)


@pytest.mark.parametrize(
    "name, flags, signed, encrypted, tlv_types",
    [
        pytest.param("standard.bin", 0, False, False, [0x10], id="hash-only"),
        pytest.param("signed.bin", 0, True, False, [0x10, 0x01, 0x22], id="ecdsa-p256"),
        pytest.param("encrypted.bin", 0x4, False, True, [0x10, 0x33], id="aes128"),
        pytest.param(
            "protected.bin", 0, False, False, [0x50, 0x10], id="protected-tlv"
        ),
    ],
)
def test_mcuboot_metadata(name, flags, signed, encrypted, tlv_types):
    with File.from_path(TEST_DATA_PATH / name) as file:
        chunk = MCUbootHandler().calculate_chunk(file, 0)

    assert chunk is not None
    assert chunk.end_offset == (TEST_DATA_PATH / name).stat().st_size
    assert chunk.metadata_reports == [
        MCUbootMetadataReport(
            version="1.2.3+4",
            load_address=0,
            flags=flags,
            signed=signed,
            encrypted=encrypted,
            tlv_types=tlv_types,
        )
    ]
    # The header flag is reported, but the image is still split.
    assert chunk.is_encrypted is False


def test_mcuboot_truncated_tlv_area_is_rejected():
    data = (TEST_DATA_PATH / "standard.bin").read_bytes()[:-1]
    with File.from_bytes(data) as file, pytest.raises(InvalidInputFormat):
        MCUbootHandler().calculate_chunk(file, 0)
