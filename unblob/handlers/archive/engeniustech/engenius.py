from pathlib import Path
from typing import Optional

from dissect.cstruct import Instance
from structlog import get_logger

from unblob.file_utils import Endian, File, InvalidInputFormat, StructParser
from unblob.models import Extractor, HexString, StructHandler, ValidChunk

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct engenius_header {
        uint32 unknown_1;
        uint32 vendor_id;
        uint32 product_id;
        char version[20];
        uint32 length;
        uint32 unknown_2;
        char checksum[16];
        char padding[32];
        uint32 unknown_3;
        char magic[4];
        char reg_dom[8];
        uint32 major_version;
        uint32 minor_version;
        uint32 micro_version;
        uint32 release_date;
        uint32 c_major_version;
        uint32 c_minor_version;
        uint32 c_micro_version;
        uint32 model_len;
        char model[model_len];
    } engenius_header_t;
"""

XOR_KEY = b"\xac\x78\x3c\x9e\xcf\x67\xb3\x59"
XOR_KEY_LEN = len(XOR_KEY)


def decrypter(reference):
    def decrypt(value, offset):
        nonlocal reference
        return value ^ XOR_KEY[(offset - reference) % XOR_KEY_LEN]

    return decrypt


class EngeniusExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        outpath = outdir.joinpath(f"{inpath.name}.decrypted")

        with File.from_path(inpath) as f:
            engenius_header = self._struct_parser.parse(
                "engenius_header_t", f, Endian.BIG
            )
            logger.debug(
                "engenius_header_t",
                engenius_header=engenius_header,
                size=len(engenius_header),
                _verbosity=3,
            )
            decrypt = decrypter(f.find(XOR_KEY))
            with outpath.open("wb") as outfile:
                decrypted = bytearray()
                for offset in range(f.tell(), engenius_header.length):
                    decrypted.append(decrypt(f[offset], offset))
                outfile.write(decrypted)


class EngeniusHandler(StructHandler):
    NAME = "engenius"

    PATTERNS = [HexString("12 34 56 78 61 6c 6c")]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "engenius_header_t"
    EXTRACTOR = EngeniusExtractor()
    PATTERN_MATCH_OFFSET = -0x5C

    def is_valid_header(self, header: Instance) -> bool:
        if header.length <= len(header):
            return False
        try:
            header.model.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.BIG)

        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid Engenius header.")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + len(header) + header.length,
        )
