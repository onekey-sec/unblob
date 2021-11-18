import py7zr, io

from pathlib import Path
from typing import List, Union
from dissect.cstruct import cstruct

from ...models import ValidChunk, UnknownChunk


NAME = "sevenzip"
# Yara doesn't like the rule starting with a number
# yara.SyntaxError: line 21: syntax error, unexpected integer number, expecting identifier

YARA_RULE = r"""
    strings:
        // '7', 'z', 0xBC, 0xAF, 0x27, 0x1C
        $sevenzip_magic = { 37 7A BC AF 27 1C } 

    condition:
        $sevenzip_magic
"""

cparser = cstruct()
cparser.load(
    """
struct sevenzip_header {
    char magic[6];
    uint8 version_maj;
    uint8 version_min;
    uint32 crc;
    uint64 next_header_offset;
    uint64 next_header_size;
    uint32 next_header_crc;
}

struct header_db {
    char property_id;
}
"""
)


def calculate_chunk(
    file: io.BufferedReader, start_offset: int
) -> Union[ValidChunk, UnknownChunk]:

    # TODO: py7zr approach will only work if the 7z file starts at 0, because as part of the
    # header reading/checksum calculation routine, the file cursor is moved to 0 + len(7z_signature).

    file.seek(start_offset)
    try:
        sevenzip_file = py7zr.SevenZipFile(file)
    except py7zr.exceptions.Bad7zFile as b7f:
        return UnknownChunk(
            start_offset=start_offset,
            reason=f"py7zr decided this isn't a valid 7z file: {b7f}",
        )
    except py7zr.exceptions.PasswordRequired as pr:
        # TODO: Ideally we shouldn't need the password for the 7z file in order to calculate the
        # size of this chunk. However, for now, py7zr needs a password in order to properly
        # create the SevenZipFile(), so we just fall back to UnknownChunk in this case.
        return UnknownChunk(
            start_offset=start_offset,
            reason=f"py7zr needs a password for this in order to make any sense of it: {pr}",
        )

    size = sevenzip_file.archiveinfo().size
    return ValidChunk(
        start_offset=start_offset,
        end_offset=start_offset + size,
    )


def make_extract_command(inpath: Path, outdir: Path) -> List[str]:
    # 7z needs the outdir to be directly after the -o, without any space.
    return ["7z", "x", "-y", inpath, f"-o{outdir}"]
