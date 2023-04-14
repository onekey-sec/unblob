import os
import tarfile
from pathlib import Path
from typing import Optional

from structlog import get_logger

from ...file_utils import OffsetFile, SeekError, decode_int, round_up, snull
from ...models import Extractor, File, HexString, StructHandler, ValidChunk
from ._safe_tarfile import SafeTarFile

logger = get_logger()


BLOCK_SIZE = 512
END_OF_ARCHIVE_MARKER_SIZE = 2 * BLOCK_SIZE

MAGIC_OFFSET = 257

ZERO_BLOCK = bytes([0]) * BLOCK_SIZE


def _get_tar_end_offset(file: File, offset=0):
    file_with_offset = OffsetFile(file, offset)

    # First find the end of the last entry in the file
    last_offset = _get_end_of_last_tar_entry(file_with_offset)
    if last_offset == -1:
        return -1

    # Then find where the final zero blocks end
    return offset + _find_end_of_padding(file_with_offset, find_from=last_offset)


def _get_end_of_last_tar_entry(file) -> int:
    try:
        tf = tarfile.TarFile(mode="r", fileobj=file)
    except tarfile.TarError:
        return -1

    last_member = None

    try:
        for member in tf:
            last_member = member
    except (tarfile.TarError, SeekError):
        # recover what's already been parsed
        pass

    if last_member is None:
        return -1

    last_file_size = round_up(last_member.size, BLOCK_SIZE)
    end_of_last_tar_entry = last_member.offset_data + last_file_size
    try:
        file.seek(end_of_last_tar_entry)
    except SeekError:
        # last tar entry is truncated
        end_of_last_tar_entry = last_member.offset
        file.seek(end_of_last_tar_entry)

    return end_of_last_tar_entry


def _find_end_of_padding(file, *, find_from: int) -> int:
    find_from = round_up(find_from, BLOCK_SIZE)
    find_to = round_up(find_from + END_OF_ARCHIVE_MARKER_SIZE, tarfile.RECORDSIZE)

    max_padding_blocks = (find_to - find_from) // BLOCK_SIZE

    try:
        file.seek(find_from)
    except SeekError:
        # match to end of truncated file
        return file.seek(0, os.SEEK_END)

    for padding_blocks in range(max_padding_blocks):  # noqa: B007
        if file.read(BLOCK_SIZE) != ZERO_BLOCK:
            break
    else:
        padding_blocks = max_padding_blocks

    return find_from + padding_blocks * BLOCK_SIZE


class TarExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        tf = SafeTarFile.open(inpath.as_posix())
        try:
            tf.extractall(outdir.as_posix())
        except FileExistsError as file_exists_error:
            logger.warning(
                "FileExistsError during tar archive extraction", error=file_exists_error
            )


class TarHandler(StructHandler):
    NAME = "tar"

    PATTERNS = [
        HexString("75 73 74 61 72 20 20 00"),
        HexString("75 73 74 61 72 00 30 30"),
    ]

    # Since the magic is at 257, we have to subtract that from the match offset
    # to get to the start of the file.
    PATTERN_MATCH_OFFSET = -MAGIC_OFFSET

    C_DEFINITIONS = r"""
        typedef struct posix_header
        {                       /* byte offset */
            char name[100];     /*   0 */
            char mode[8];       /* 100 */
            char uid[8];        /* 108 */
            char gid[8];        /* 116 */
            char size[12];      /* 124 */
            char mtime[12];     /* 136 */
            char chksum[8];     /* 148 */
            char typeflag;      /* 156 */
            char linkname[100]; /* 157 */
            char magic[6];      /* 257 */
            char version[2];    /* 263 */
            char uname[32];     /* 265 */
            char gname[32];     /* 297 */
            char devmajor[8];   /* 329 */
            char devminor[8];   /* 337 */
            char prefix[155];   /* 345 */
                                /* 500 */
        } posix_header_t;
    """
    HEADER_STRUCT = "posix_header_t"

    EXTRACTOR = TarExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(start_offset)
        header = self.parse_header(file)
        header_size = snull(header.size)
        decode_int(header_size, 8)

        end_offset = _get_tar_end_offset(file, start_offset)
        if end_offset == -1:
            return None
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
