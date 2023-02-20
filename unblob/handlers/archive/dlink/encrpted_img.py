import io
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dissect.cstruct import Instance
from structlog import get_logger

from unblob.file_utils import File, InvalidInputFormat
from unblob.models import Endian, Extractor, Regex, StructHandler, ValidChunk

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct encrpted_img_header {
        char magic[12]; /* encrpted_img */
        uint32 size;    /* total size of file */
    } dlink_header_t;
"""

HEADER_LEN = 16
PEB_SIZE = 0x20000
UBI_HEAD = b"\x55\x42\x49\x23\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
UBI_HEAD_LEN = len(UBI_HEAD)
KEY = b"he9-4+M!)d6=m~we1,q2a3d1n&2*Z^%8"
IV = b"J%1iQl8$=lm-;8AE"


class EncrptedExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
        decryptor = cipher.decryptor()
        outpath = outdir.joinpath(f"{inpath.name}.decrypted")
        outfile = outpath.open("wb")
        with inpath.open("rb") as f:
            f.seek(HEADER_LEN, io.SEEK_SET)  # skip header
            ciphertext = f.read(PEB_SIZE)
            while ciphertext and len(ciphertext) % 16 == 0:
                plaintext = decryptor.update(ciphertext)
                outfile.write(UBI_HEAD + plaintext[UBI_HEAD_LEN:])
                ciphertext = f.read(PEB_SIZE)
        outfile.write(decryptor.finalize())
        outfile.close()


class EncrptedHandler(StructHandler):
    NAME = "encrpted_img"

    PATTERNS = [
        Regex(r"encrpted_img"),
    ]
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "dlink_header_t"
    EXTRACTOR = EncrptedExtractor()

    def is_valid_header(self, header: Instance) -> bool:
        if header.size < len(header):
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.BIG)

        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid header length")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + len(header) + header.size,
        )
