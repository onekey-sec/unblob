import gzip
import zlib
from typing import List, Union

from dissect.cstruct import cstruct
from structlog import get_logger

from ...file_utils import LimitedStartReader
from ...models import UnknownChunk, ValidChunk

logger = get_logger()

NAME = "gzip"

YARA_RULE = """
strings:
    $magic = { 1f 8b 08 }
condition:
    $magic
"""

cparser = cstruct()
cparser.load(
    """
struct gzip_struct
{
    char id1;
    char id2;
    char compression_method;
    uint8 flags;
    uint32 modification_time;
    char extra_flags;
    uint8 os; // Operating system
}

struct gzip_footer
{
    uint32 crc;
    uint32 decompressed_length;
}
"""
)

OS_TYPES = {
    0x0: "FAT",
    0x1: "Amiga",
    0x2: "VMS",
    0x3: "UNIX",
    0x4: "VM/CMS",
    0x5: "Atari TOS",
    0x6: "HPFS filesystem (OS/2, NT)",
    0x7: "Macintosh",
    0x8: "Z-System",
    0x9: "CP/M",
    0xA: "TOPS-20",
    0xB: "NTFS filesystem (NT)",
    0xC: "QDOS",
    0xD: "Acorn RISCOS",
    0xFF: "Unknown",
}

HEADER_STRUCT_SIZE = 10


# FIXME: C901 '_calculate_end' is too complex
def calculate_chunk(  # noqa: C901
    file: LimitedStartReader, start_offset: int
) -> Union[UnknownChunk, ValidChunk]:  # type: ignore - not yet ready feature, will be overridden
    header = cparser.gzip_struct(file)
    logger.debug("Header parsed", header=header)

    if header.os not in OS_TYPES:
        return UnknownChunk(
            start_offset=start_offset, reason=f"Invalid OS header field: {header.os}"
        )

    if header.flags & 0b11100000:
        return UnknownChunk(
            start_offset=start_offset,
            reason="One of top 3 bits are set in flags, unexpected!",
        )

    def read_until(file, start):
        """Just a stub so there is no ImportError"""

    if header.flags & 0b00001000:
        file_name = read_until(file, start=start_offset + HEADER_STRUCT_SIZE)
        try:
            file_name.decode("utf-8")  # type: ignore - not yet ready feature, will be overridden
        except UnicodeDecodeError:
            return UnknownChunk(
                start_offset=start_offset, reason="Unicode error on filename"
            )

    # zlib errors are fatal, so filter streams which throw those here
    try:
        file.seek(start_offset)
        with gzip.open(file) as g:
            g.seek(0, 2)
            g.tell()
    except zlib.error as zle:
        return UnknownChunk(
            start_offset=start_offset,
            reason=f"zlib error loading the gzip stream (f at {file.tell()}): {zle}",
        )
    except OSError as ose:
        if "CRC check failed" in ose.args[0]:
            return UnknownChunk(start_offset=start_offset, reason=f"Bad CRC: {ose}")
        # But we still want to keep the 2Not a gzipped file" OSError for later.
    except Exception:
        pass


def make_extract_command(infile: str, outdir: str) -> List[str]:
    # gzip is just a compression, doesn't have an output directory switch
    return ["gunzip", "--keep", infile]
