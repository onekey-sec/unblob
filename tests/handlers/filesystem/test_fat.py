import io

import pytest
from dissect.cstruct import Instance
from helpers import unhex

from unblob.handlers.filesystem.fat import FATHandler

VALID_FAT12_HEADER_CONTENT = unhex(
    """\
00000000  eb 3c 90 6d 6b 66 73 2e  66 61 74 00 02 04 01 00  |.<.mkfs.fat.....|
00000010  02 00 02 80 00 f8 01 00  20 00 40 00 00 00 00 00  |........ .@.....|
00000020  00 00 00 00 80 00 29 82  a3 d0 c7 43 48 45 52 52  |......)....CHERR|
00000030  59 20 20 20 20 20 46 41  54 31 32 20 20 20 0e 1f  |Y     FAT12   ..|
00000040  be 5b 7c ac 22 c0 74 0b  56 b4 0e bb 07 00 cd 10  |.[|.".t.V.......|
00000050  5e eb f0 32 e4 cd 16 cd  19 eb fe 54 68 69 73 20  |^..2.......This |
00000060  69 73 20 6e 6f 74 20 61  20 62 6f 6f 74 61 62 6c  |is not a bootabl|
00000070  65 20 64 69 73 6b 2e 20  20 50 6c 65 61 73 65 20  |e disk.  Please |
00000080
"""
)

VALID_FAT16_HEADER_CONTENT = unhex(
    """\
00000000  eb 3c 90 6d 6b 66 73 2e  66 61 74 00 02 04 01 00  |.<.mkfs.fat.....|
00000010  02 00 02 80 00 f8 01 00  20 00 40 00 00 00 00 00  |........ .@.....|
00000020  00 00 00 00 80 00 29 48  58 c5 dc 42 41 4e 41 4e  |......)HX..BANAN|
00000030  41 20 20 20 20 20 46 41  54 31 36 20 20 20 0e 1f  |A     FAT16   ..|
00000040  be 5b 7c ac 22 c0 74 0b  56 b4 0e bb 07 00 cd 10  |.[|.".t.V.......|
00000050  5e eb f0 32 e4 cd 16 cd  19 eb fe 54 68 69 73 20  |^..2.......This |
00000060  69 73 20 6e 6f 74 20 61  20 62 6f 6f 74 61 62 6c  |is not a bootabl|
00000070  65 20 64 69 73 6b 2e 20  20 50 6c 65 61 73 65 20  |e disk.  Please |
00000080
"""
)

VALID_FAT32_HEADER_CONTENT = unhex(
    """\
00000000  eb 58 90 6d 6b 66 73 2e  66 61 74 00 02 01 20 00  |.X.mkfs.fat... .|
00000010  02 00 00 00 00 f8 00 00  20 00 40 00 00 00 00 00  |........ .@.....|
00000020  00 08 01 00 08 02 00 00  00 00 00 00 02 00 00 00  |................|
00000030  01 00 06 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000040  80 00 29 2c 49 2e 82 46  52 55 49 54 53 20 20 20  |..),I..FRUITS   |
00000050  20 20 46 41 54 33 32 20  20 20 0e 1f be 77 7c ac  |  FAT32   ...w|.|
00000060  22 c0 74 0b 56 b4 0e bb  07 00 cd 10 5e eb f0 32  |".t.V.......^..2|
00000070  e4 cd 16 cd 19 eb fe 54  68 69 73 20 69 73 20 6e  |.......This is n|
"""
)

handler = FATHandler()


def get_valid_fat12_header():
    return handler.cparser_le.fat12_16_bootsec_t(io.BytesIO(VALID_FAT12_HEADER_CONTENT))


def get_valid_fat16_header():
    return handler.cparser_le.fat12_16_bootsec_t(io.BytesIO(VALID_FAT16_HEADER_CONTENT))


def get_valid_fat32_header():
    return handler.cparser_le.fat32_bootsec_t(io.BytesIO(VALID_FAT32_HEADER_CONTENT))


VALID_FAT12_HEADER = get_valid_fat12_header()
VALID_FAT16_HEADER = get_valid_fat16_header()
VALID_FAT32_HEADER = get_valid_fat32_header()

# we have to create unique objects but shallow or deep copy triggers a
# recursion error on cstruct.Instance objects so we just parse the
# valid header again then modify it to test our specific checks.
FAT12_HEADER_INVALID_OEM = get_valid_fat12_header()
FAT12_HEADER_INVALID_OEM.common.OEMName = b"\xf8\xa1\xa1\xa1\xa1"
FAT16_HEADER_INVALID_OEM = get_valid_fat16_header()
FAT16_HEADER_INVALID_OEM.common.OEMName = b"\xf8\xa1\xa1\xa1\xa1"
FAT32_HEADER_INVALID_OEM = get_valid_fat32_header()
FAT32_HEADER_INVALID_OEM.common.OEMName = b"\xf8\xa1\xa1\xa1\xa1"

FAT12_HEADER_INVALID_BPS = get_valid_fat12_header()
FAT12_HEADER_INVALID_BPS.common.BytesPerSec += 1
FAT16_HEADER_INVALID_BPS = get_valid_fat16_header()
FAT16_HEADER_INVALID_BPS.common.BytesPerSec += 1
FAT32_HEADER_INVALID_BPS = get_valid_fat32_header()
FAT32_HEADER_INVALID_BPS.common.BytesPerSec += 1

FAT12_HEADER_INVALID_RSC = get_valid_fat12_header()
FAT12_HEADER_INVALID_RSC.common.RsvdSecCnt = 0
FAT16_HEADER_INVALID_RSC = get_valid_fat16_header()
FAT16_HEADER_INVALID_RSC.common.RsvdSecCnt = 0
FAT32_HEADER_INVALID_RSC = get_valid_fat32_header()
FAT32_HEADER_INVALID_RSC.common.RsvdSecCnt = 0

FAT12_HEADER_INVALID_MEDIA = get_valid_fat12_header()
FAT12_HEADER_INVALID_MEDIA.common.Media = 0
FAT16_HEADER_INVALID_MEDIA = get_valid_fat16_header()
FAT16_HEADER_INVALID_MEDIA.common.Media = 0
FAT32_HEADER_INVALID_MEDIA = get_valid_fat32_header()
FAT32_HEADER_INVALID_MEDIA.common.Media = 0

FAT12_HEADER_INVALID_NT = get_valid_fat12_header()
FAT12_HEADER_INVALID_NT.BootSig = 0
FAT16_HEADER_INVALID_NT = get_valid_fat16_header()
FAT16_HEADER_INVALID_NT.BootSig = 0
FAT32_HEADER_INVALID_NT = get_valid_fat32_header()
FAT32_HEADER_INVALID_NT.BootSig = 0

FAT32_HEADER_INVALID_REC = get_valid_fat32_header()
FAT32_HEADER_INVALID_REC.common.RootEntCnt = 1

FAT32_HEADER_INVALID_TS = get_valid_fat32_header()
FAT32_HEADER_INVALID_TS.common.TotSectors = 1

FAT32_HEADER_INVALID_FS16 = get_valid_fat32_header()
FAT32_HEADER_INVALID_FS16.common.FATSz16 = 1


@pytest.mark.parametrize(
    "header, expected",
    [
        pytest.param(
            VALID_FAT12_HEADER,
            True,
            id="fat12-valid-header",
        ),
        pytest.param(
            VALID_FAT16_HEADER,
            True,
            id="fat16-valid-header",
        ),
        pytest.param(
            VALID_FAT32_HEADER,
            True,
            id="fat32-valid-header",
        ),
        pytest.param(FAT12_HEADER_INVALID_OEM, False, id="fat12-invalid-header-oem"),
        pytest.param(FAT16_HEADER_INVALID_OEM, False, id="fat16-invalid-header-oem"),
        pytest.param(FAT32_HEADER_INVALID_OEM, False, id="fat32-invalid-header-oem"),
        pytest.param(FAT12_HEADER_INVALID_BPS, False, id="fat12-invalid-header-bps"),
        pytest.param(FAT16_HEADER_INVALID_BPS, False, id="fat16-invalid-header-bps"),
        pytest.param(FAT32_HEADER_INVALID_BPS, False, id="fat32-invalid-header-bps"),
        pytest.param(FAT12_HEADER_INVALID_RSC, False, id="fat12-invalid-header-rsc"),
        pytest.param(FAT16_HEADER_INVALID_RSC, False, id="fat16-invalid-header-rsc"),
        pytest.param(FAT32_HEADER_INVALID_RSC, False, id="fat32-invalid-header-rsc"),
        pytest.param(
            FAT12_HEADER_INVALID_MEDIA, False, id="fat12-invalid-header-media"
        ),
        pytest.param(
            FAT16_HEADER_INVALID_MEDIA, False, id="fat16-invalid-header-media"
        ),
        pytest.param(
            FAT32_HEADER_INVALID_MEDIA, False, id="fat32-invalid-header-media"
        ),
        pytest.param(FAT12_HEADER_INVALID_NT, False, id="fat12-invalid-header-nt"),
        pytest.param(FAT16_HEADER_INVALID_NT, False, id="fat16-invalid-header-nt"),
        pytest.param(FAT32_HEADER_INVALID_NT, False, id="fat32-invalid-header-nt"),
        pytest.param(FAT32_HEADER_INVALID_REC, False, id="fat32-invalid-header-rec"),
        pytest.param(FAT32_HEADER_INVALID_TS, False, id="fat32-invalid-header-ts"),
        pytest.param(FAT32_HEADER_INVALID_FS16, False, id="fat32-invalid-header-fs16"),
    ],
)
def test_valid_header(header: Instance, expected: bool):
    assert handler.valid_header(header) == expected


@pytest.mark.parametrize(
    "header, expected",
    [
        pytest.param(
            VALID_FAT12_HEADER,
            False,
            id="valid-fat12-header",
        ),
        pytest.param(
            VALID_FAT16_HEADER,
            False,
            id="valid-fat16-header",
        ),
        pytest.param(
            VALID_FAT32_HEADER,
            True,
            id="valid-fat32-header",
        ),
    ],
)
def test_valid_fat32_header(header: Instance, expected: bool):
    assert handler.valid_fat32_header(header) == expected
