import io
from typing import List, Union

from dissect.cstruct import cstruct
from structlog import get_logger

from ...models import UnknownChunk, ValidChunk

logger = get_logger()

NAME = "cab"

YARA_RULE = r"""
    strings:
        $magic = { 4D 53 43 46 00 00 00 00 } // MSCF, then reserved dword
    condition:
        $magic
"""
YARA_MATCH_OFFSET = 0

cparser = cstruct()
cparser.load(
    """
struct cab_header
{
  u1  signature[4];  /* cabinet file signature contains the characters 'M','S','C','F' (bytes 0x4D, 0x53, 0x43, 0x46). */
                    /* This field is used to assure that the file is a cabinet file. */
  u4  reserved1;     /* reserved */
  u4  cbCabinet;     /* size of this cabinet file in bytes */
  u4  reserved2;     /* reserved */
  u4  coffFiles;     /* offset of the first CFFILE entry */
  u4  reserved3;     /* reserved */
  u1  versionMinor;  /* cabinet file format version, minor */
  u1  versionMajor;  /* cabinet file format version, major */
  u2  cFolders;      /* number of CFFOLDER entries in this cabinet */
  u2  cFiles;        /* number of CFFILE entries in this cabinet */
  u2  flags;         /* cabinet file option indicators */
  u2  setID;         /* must be the same for all cabinets in a set*/
  u2  iCabinet;     /* number of this cabinet file in a set */
  u2  cbCFHeader;   /* (optional) size of per-cabinet reserved area */
  u1  cbCFFolder;   /* (optional) size of per-folder reserved area */
  u1  cbCFData;         /* (optional) size of per-datablock reserved area */
  u1  szCabinetPrev[];  /* (optional) name of previous cabinet file */
  u1  szDiskPrev[];     /* (optional) name of previous disk */
  u1  szCabinetNext[];  /* (optional) name of next cabinet file */
  u1  szDiskNext[];     /* (optional) name of next disk */
};
"""
)


def calculate_chunk(
    file: io.BufferedIOBase, start_offset: int
) -> Union[ValidChunk, UnknownChunk]:

    file.seek(start_offset)
    header = cparser.cab_header(file)
    logger.debug("Header parsed", header=header)

    if header.cbCabinet < len(header):
        return UnknownChunk(
            start_offset=start_offset,
            reason=f"CAB header file size ({header.cbCabinet}) is less than header size.",
        )

    return ValidChunk(
        start_offset=start_offset,
        end_offset=start_offset + header.cbCabinet,
    )


def make_extract_command(inpath: str, outdir: str) -> List[str]:
    return ["7z", "x", "-y", inpath, f"-o{outdir}"]
