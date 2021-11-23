"""
RAR version 4.x
https://codedread.github.io/bitjs/docs/unrar.html
"""

import io
from typing import List

from dissect.cstruct import cstruct

from ...models import Chunk

NAME = "rar"


YARA_RULE = """
strings:
    $magic_v4 = { 52 61 72 21 1A 07 00 }
condition:
    $magic_v4
"""
YARA_MATCH_OFFSET = 0

cparser = cstruct()
cparser.load(
    """
struct sig_vol_header {
    char signature[7];
    ushort crc;
    uint8 type;
    ushort flags;
    ushort size;
};

struct base_vol_header {
    ushort crc;
    uint8 type;
    ushort flags;
    ushort size;
}

struct base_vol_header_data {
    ushort crc;
    uint8 type;
    ushort flags;
    ushort size;
    uint32 datasize;
}

// Only if the MHD_ENCRYPTVER flag is set
struct main_head_enc {
    base_vol_header base;
    ushort HighPosAv;
    uint32 PosAV;
    uint8 EncryptVer;
}

struct main_head {
    base_vol_header base;
    ushort HighPosAv;
    uint32 PosAV;
}
"""
)

VOL_HEADER_TYPES = [
    (0x72, "MARK_HEAD"),
    (0x73, "MAIN_HEAD"),
    (0x74, "FILE_HEAD"),
    (0x75, "COMM_HEAD"),
    (0x76, "AV_HEAD"),
    (0x77, "SUB_HEAD"),
    (0x78, "PROTECT_HEAD"),
    (0x79, "SIGN_HEAD"),
    (0x7A, "NEWSUB_HEAD"),
    (0x7B, "ENDARC_HEAD"),
]

MAIN_HEADER_FLAGS = [
    (0x0001, "MHD_VOLUME"),
    (0x0002, "MHD_COMMENT"),
    (0x0004, "MHD_LOCK"),
    (0x0008, "MHD_SOLID"),
    (0x0010, "MHD_PACK_COMMENT"),  # or MHD_NEWNUMBERING
    (0x0020, "MHD_AV"),
    (0x0040, "MHD_PROTECT"),
    (0x0080, "MHD_PASSWORD"),
    (0x0100, "MHD_FIRSTVOLUME"),
    (0x0200, "MHD_ENCRYPTVER"),
]

FILE_HEADER_FLAGS = [
    (0x0001, "LHD_SPLIT_BEFORE"),
    (0x0002, "LHD_SPLIT_AFTER"),
    (0x0004, "LHD_PASSWORD"),
    (0x0008, "LHD_COMMENT"),
    (0x0010, "LHD_SOLID"),
    (0x0100, "LHD_LARGE"),
    (0x0200, "LHD_UNICODE"),
    (0x0400, "LHD_SALT"),
    (0x0800, "LHD_VERSION"),
    (0x1000, "LHD_EXTTIME"),
    (0x2000, "LHD_EXTFLAGS"),
    (
        0x8000,
        "LHD_LONG_BLOCK",
    ),  # https://gitlab.gnome.org/GNOME/evince/-/blob/d69158ecf0e2a2f1562b06c265fc86f87fe7dd6f/cut-n-paste/unarr/rar/rar.h
]


# FIXME: C901 '_calculate_end' is too complex
def _calculate_end(file, start_offset: int):  # noqa: C901
    offset = start_offset
    while True:
        file.seek(offset)
        header = cparser.base_vol_header(file)
        file.seek(offset)

        extra_data = 0
        # LHD_LONG_BLOCK flag indicates that there's another 32-bit field after the normal
        # base header, which tells you the size of the extra data. So in this case, we would
        # want to skip past that extra data as well.
        # https://gitlab.gnome.org/GNOME/evince/-/blob/d69158ecf0e2a2f1562b06c265fc86f87fe7dd6f/cut-n-paste/unarr/rar/parse-rar.c#L29
        # This also suggests that this should be true without this flag, if the type is 0x74,
        # i.e. a FILE_HEAD section.
        if (
            header.flags
            & [x[0] for x in FILE_HEADER_FLAGS if x[1] == "LHD_LONG_BLOCK"][0]
            or header.type == 0x74
        ):
            header = cparser.base_vol_header_data(file)
            file.seek(offset)
            extra_data = header.datasize

        if header.type == 0x72:  # "MARK_HEAD"
            # This is the RAR signature (0x72 indicates MARK_HEAD)
            # It looks like 52 61 72 21 1A 07 00, and the 0x0007 is
            # the size field, and how long it is. Clever!
            pass
        elif header.type == 0x73:  # "MAIN_HEAD"
            pass
        elif header.type == 0x74:  # "FILE_HEAD"
            pass
        elif header.type == 0x75:  # "COMM_HEAD"
            pass
        elif header.type == 0x76:  # "AV_HEAD"
            pass
        elif header.type == 0x77:  # "SUB_HEAD"
            pass
        elif header.type == 0x78:  # "PROTECT_HEAD"
            pass
        elif header.type == 0x79:  # "SIGN_HEAD"
            pass
        elif header.type == 0x7A:  # "NEWSUB_HEAD"
            pass
        elif header.type == 0x7B:  # "ENDARC_HEAD"
            # End of archive here
            return offset + header.size
        else:
            # This isn't an expected RAR internal header, so we
            # assume we've hit the end of something-like-a-RAR.
            # It's not ending with the ENDARC_HEAD, so it may be
            # corrupted?
            return offset

        offset = offset + header.size + extra_data


def calculate_chunk(file: io.BufferedIOBase, start_offset: int) -> Chunk:
    end_offset = _calculate_end(file, start_offset)
    return Chunk(start_offset, end_offset)


def make_extract_command(inpath: str, outdir: str) -> List[str]:
    return ["unrar", "e", inpath, outdir]
