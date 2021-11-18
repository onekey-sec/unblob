import io
import math
from typing import List, Union
from dissect.cstruct import cstruct
from ...models import ValidChunk, UnknownChunk
from ...file_utils import snull


NAME = "tar"

YARA_RULE = r"""
    strings:
        $tar_magic = { 75 73 74 61 72 }

    condition:
        $tar_magic
"""

cparser = cstruct()
cparser.load(
    """
struct posix_header
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
};
"""
)

MAGIC_OFFSET = 257
BLOCK_SIZE = HEADER_SIZE = 512

# Because the header of the tar file doesn't necessarily
# contain the size of the whole tar block (because "Physically,
# an archive consists of a series of file entries terminated
# by an end-of-archive entry, which consists of two 512 blocks
# of zero bytes.") - we need to parse the concurrent tar chunks,
# and then return the size of the total file once we reach the
# blocks of NULLs.
# https://www.gnu.org/software/tar/manual/html_node/Standard.html
END_BLOCK_SIZE = BLOCK_SIZE * 2
END_BLOCK = b"\x00" * END_BLOCK_SIZE


def _calc_chunk_size(size: int):
    whole_blocks = size // BLOCKSIZE
    # size=517, whole_blocks=1, total = BLOCKSIZE * 2 = 1024
    # size=6, whole_blocks=0, total = BLOCKSIZE * 1 = 512
    total = BLOCKSIZE * (1 + whole_blocks)
    return total


def _get_tar_size(file: io.BufferedReader, offset: int):
    # Try to avoid tail recursive loop by using a while loop
    # with a return. Really big (~2000+ file) tar files would
    # throw a RecursionError.
    while True:
        file.seek(offset)
        if file.read(END_BLOCKSIZE) == END_BLOCK:
            return file.tell()
        file.seek(offset)
        header = cparser.posix_header(file)
        header_size = int(snull(header.size), 8)
        offset += _calc_chunk_size(header_size) + BLOCKSIZE


def calculate_chunk(
    file: io.BufferedReader, start_offset: int
) -> Union[ValidChunk, UnknownChunk]:
    # Since the magic is at 257, we have to subtract that from the match offset
    # to get to the start of the file.
    real_start_offset = start_offset - MAGIC_OFFSET

    file.seek(real_start_offset)
    header = cparser.posix_header(file)
    header_size = snull(header.size)
    try:
        int(header_size, 8)
    except ValueError as exc:
        return UnknownChunk(
            start_offset=start_offset,
            reason=f"Size field isn't octal: {header_size} (ValueError: {exc})",
        )

    file.seek(real_start_offset)
    size = _get_tar_size(file, real_start_offset)
    return ValidChunk(
        start_offset=real_start_offset,
        end_offset=real_start_offset + size - 1,
    )


def make_extract_command(inpath: str, outdir: str) -> List[str]:
    return ["tar", "xvf", inpath, "--directory", outdir]
