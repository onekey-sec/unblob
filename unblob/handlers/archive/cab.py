from typing import Optional

from structlog import get_logger

from ...extractors import Command
from ...models import File, HexString, StructHandler, ValidChunk

logger = get_logger()


class CABHandler(StructHandler):
    NAME = "cab"

    PATTERNS = [HexString("4D 53 43 46 00 00 00 00 // MSCF then reserved dword")]
    C_DEFINITIONS = r"""
        typedef struct cab_header
        {
            char  signature[4];  /* cabinet file signature contains the characters 'M','S','C','F' (bytes 0x4D, 0x53, 0x43, 0x46). */
                                /* This field is used to assure that the file is a cabinet file. */
            uint32  reserved1;     /* reserved */
            uint32  cbCabinet;     /* size of this cabinet file in bytes */
            uint32  reserved2;     /* reserved */
            uint32  coffFiles;     /* offset of the first CFFILE entry */
            uint32  reserved3;     /* reserved */
            uint8  versionMinor;  /* cabinet file format version, minor */
            uint8  versionMajor;  /* cabinet file format version, major */
            uint16  cFolders;      /* number of CFFOLDER entries in this cabinet */
            uint16  cFiles;        /* number of CFFILE entries in this cabinet */
            uint16  flags;         /* cabinet file option indicators */
            uint16  setID;         /* must be the same for all cabinets in a set*/
            uint16  iCabinet;     /* number of this cabinet file in a set */
            uint16  cbCFHeader;   /* (optional) size of per-cabinet reserved area */
            uint8  cbCFFolder;   /* (optional) size of per-folder reserved area */
            uint8  cbCFData;         /* (optional) size of per-datablock reserved area */
            uint8  szCabinetPrev[];  /* (optional) name of previous cabinet file */
            uint8  szDiskPrev[];     /* (optional) name of previous disk */
            uint8  szCabinetNext[];  /* (optional) name of next cabinet file */
            uint8  szDiskNext[];     /* (optional) name of next disk */
        } cab_header_t;
    """
    HEADER_STRUCT = "cab_header_t"

    EXTRACTOR = Command("7z", "x", "-y", "{inpath}", "-o{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file)

        if header.cbCabinet < len(header):
            return None

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.cbCabinet,
        )
