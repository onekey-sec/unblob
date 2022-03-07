import io
import tarfile
from typing import Optional

from structlog import get_logger

from unblob.extractors.command import Command

from ...file_utils import decode_int, round_down, round_up, snull
from ...models import StructHandler, ValidChunk

logger = get_logger()


BLOCK_SIZE = 512

MAGIC_OFFSET = 257


def _get_tar_end_offset(file: io.BufferedIOBase):
    # First find the end of the last entry in the file
    last_offset = _get_end_of_last_tar_entry(file)
    if last_offset == -1:
        return last_offset
    # Then find where the final zero blocks end
    return _find_end_of_padding(file, find_from=last_offset)


def _get_end_of_last_tar_entry(file: io.BufferedIOBase) -> int:

    try:
        tf = tarfile.TarFile(mode="r", fileobj=file)
    except tarfile.TarError:
        return -1
    try:
        members = tf.getmembers()
    except tarfile.TarError:
        # recover what's already been parsed
        members = tf.members  # type: ignore

    if not members:
        return -1
    last_member = members[-1]
    last_file_size = BLOCK_SIZE * (1 + (last_member.size // BLOCK_SIZE))
    return last_member.offset_data + last_file_size


def _find_end_of_padding(file: io.BufferedIOBase, *, find_from: int) -> int:
    file.seek(find_from)
    find_to = round_up(find_from, tarfile.RECORDSIZE)
    padding_len = find_to - find_from
    padding = file.read(padding_len)

    first_nonzero = find_from + len(padding)
    for i, b in enumerate(padding, find_from):
        if b != 0:
            first_nonzero = i
            break

    # if the first nonzero would be inside a possible next chunk, we
    # round it down
    return round_down(first_nonzero, BLOCK_SIZE)


class TarHandler(StructHandler):
    NAME = "tar"

    YARA_RULE = r"""
        strings:
            $gnu_tar_magic = {75 73 74 61 72 20 20 00}
            $posix_tar_magic =  {75 73 74 61 72 00 30 30}

        condition:
            $gnu_tar_magic or $posix_tar_magic
    """

    # Since the magic is at 257, we have to subtract that from the match offset
    # to get to the start of the file.
    YARA_MATCH_OFFSET = -MAGIC_OFFSET

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

    EXTRACTOR = Command("7z", "x", "-xr!PaxHeaders", "-y", "{inpath}", "-o{outdir}")

    def calculate_chunk(
        self, file: io.BufferedIOBase, start_offset: int
    ) -> Optional[ValidChunk]:
        header = self.parse_header(file)
        header_size = snull(header.size)
        decode_int(header_size, 8)

        file.seek(start_offset)
        end_offset = _get_tar_end_offset(file)
        if end_offset == -1:
            return
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
