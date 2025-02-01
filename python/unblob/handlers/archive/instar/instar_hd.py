import mmap
import shutil
from pathlib import Path

from structlog import get_logger

from unblob.file_utils import File
from unblob.handlers.archive.zip import ZIPHandler
from unblob.models import Extractor, HexString

logger = get_logger()

LOCAL_FILE_HEADER_ZIP = b"\x50\x4b\x03\x04"
LOCAL_FILE_HEADER_INSTAR = b"\x50\x4b\x03\x07"

EOCD_ZIP = b"\x50\x4b\x05\x06"
EOCD_INSTAR = b"\x50\x4b\x05\x09"

CD_FILE_HEADER_ZIP = b"\x50\x4b\x01\x02"
CD_FILE_HEADER_INSTAR = b"\x50\x4b\x01\x08"


class InstarHDExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        outfile = outdir / "instar_hd.deobfuscated"
        shutil.copyfile(inpath, outfile)
        with File.from_path(outfile, access=mmap.ACCESS_WRITE) as mm:
            replacements = {
                LOCAL_FILE_HEADER_INSTAR: LOCAL_FILE_HEADER_ZIP,
                EOCD_INSTAR: EOCD_ZIP,
                CD_FILE_HEADER_INSTAR: CD_FILE_HEADER_ZIP,
            }
            for pattern, replacement in replacements.items():
                pos = mm.find(pattern)
                while pos != -1:
                    mm[pos : pos + len(pattern)] = replacement
                    pos = mm.find(pattern, pos + len(pattern))


class InstarHDHandler(ZIPHandler):
    NAME = "instar_hd"

    PATTERNS = [HexString("50 4b 03 07")]  # match on the modified zip header

    EXTRACTOR = InstarHDExtractor()

    EOCD_RECORD_HEADER = 0x9054B50
