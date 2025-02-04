from typing import Optional

from pyfatfs._exceptions import PyFATException
from pyfatfs.PyFat import PyFat
from structlog import get_logger

from unblob.extractors.command import Command
from unblob.file_utils import InvalidInputFormat

from ...models import File, Handler, HexString, ValidChunk

logger = get_logger()


class PyFatNoClose(PyFat):
    def close(self):
        return


def get_max_offset(fs: PyFat) -> int:
    # see PyFat.get_cluster_chain for context
    i = len(fs.fat)
    while i > 0 and fs.fat[i - 1] == 0:
        i -= 1
    # i - 1 is the last cluster that is part of a filesystem object
    return fs.get_data_cluster_address(i)


class FATHandler(Handler):
    NAME = "fat"

    PATTERNS = [
        HexString(
            """
            // An initial x86 short jump instruction
            // OEMName (8 bytes)
            // BytesPerSec (2 bytes)
            // SecPerClus (1 byte) "Must be one of 1, 2, 4, 8, 16, 32, 64, 128."
            // 495 (0x1EF) bytes of whatever
            // 55 AA is the "signature". "This will be the end of the sector only in case the
            // sector size is 512."
            ( EB | E9 ) [13] ( 01 | 02 | 04 | 08 | 10 | 20 | 40 | 80 ) [495] 55 AA
        """
        )
    ]

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        pyfat_fs = PyFatNoClose(offset=start_offset)
        try:
            pyfat_fs.set_fp(file)  # type: ignore
        except PyFATException as e:
            raise InvalidInputFormat from e

        # we have exactly one of these set to non-0, depending on FAT version
        total_sectors = max(
            pyfat_fs.bpb_header["BPB_TotSec16"],
            pyfat_fs.bpb_header["BPB_TotSec32"],
        )

        size = total_sectors * pyfat_fs.bpb_header["BPB_BytsPerSec"]
        file_size = file.size()
        if start_offset + size > file_size:
            size = get_max_offset(pyfat_fs)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + size,
        )
