from typing import Optional

from pyfatfs._exceptions import PyFATException
from pyfatfs.PyFat import PyFat
from structlog import get_logger

from unblob.extractors.command import Command
from unblob.file_utils import InvalidInputFormat

from ...models import File, Handler, HexString, ValidChunk

logger = get_logger()


def get_max_offset(
    fs: PyFat, root_dir, max_cluster: int = 0, max_offset: int = 0
) -> int:
    dirs, files, _ = root_dir.get_entries()

    for d in dirs:
        if d.get_cluster() > max_cluster:
            max_cluster = d.get_cluster()
            max_offset = fs.get_data_cluster_address(max_cluster) + d.get_size()
        max_offset = get_max_offset(fs, d, max_cluster, max_offset)
    for f in files:
        if f.get_cluster() > max_cluster:
            max_cluster = f.get_cluster()
            max_offset = fs.get_data_cluster_address(max_cluster) + f.get_size()
    return max_offset


def no_op():
    return


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
        pyfat_fs = PyFat()
        pyfat_fs.close = no_op
        try:
            pyfat_fs.set_fp(file)  # type: ignore
        except PyFATException as e:
            raise InvalidInputFormat from e

        if pyfat_fs.bpb_header["BPB_TotSec16"] != 0:
            total_sectors = pyfat_fs.bpb_header["BPB_TotSec16"]
        else:
            total_sectors = pyfat_fs.bpb_header["BPB_TotSec32"]

        size = total_sectors * pyfat_fs.bpb_header["BPB_BytsPerSec"]
        file_size = file.size()
        if start_offset + size > file_size:
            size = get_max_offset(pyfat_fs, pyfat_fs.root_dir)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + size,
        )
