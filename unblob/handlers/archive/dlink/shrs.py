import hashlib
import io
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dissect.cstruct import Instance
from structlog import get_logger

from unblob.file_utils import File, InvalidInputFormat
from unblob.models import (
    Endian,
    Extractor,
    HexString,
    StructHandler,
    StructParser,
    ValidChunk,
)

logger = get_logger()

C_DEFINITIONS = r"""

    typedef struct dlink_shrs_header {
        char magic[4];                   /* SHRS */
        uint32 file_size;                /* Length of decrypted firmware in bytes */
        uint32 file_size_no_padding;     /* Length of decrypted firmware - padding */
        char iv[16];                     /* Length of AES 128 cbc IV */
        char decrypted_key_digest[64];          /* SHA512 64 byte message digest of decrypted firmware + key */
        char decrypted_digest[64];              /* SHA512 64 byte message digest of decrypted firmware */
        char encrypted_digest[64];              /* SHA512 64 byte message digest of encrypted firmware */
        char unused[512];                /* 512 unused NULL bytes (0xdc to 0x2dc) */
        char signature_1[512];           /* 512 byte Signature 1 */
        char signature_2[512];           /* 512 byte Signature 2 */
    } dlink_header_t;
"""

KEY = bytes.fromhex("c05fbf1936c99429ce2a0781f08d6ad8")
sha512 = hashlib.sha512()


class SHRSExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        outpath = outdir.joinpath(f"{inpath.name}.decrypted")
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse(
                "dlink_header_t", file, endian=Endian.BIG
            )
            cipher = Cipher(algorithms.AES(KEY), modes.CBC(header.iv))
            decryptor = cipher.decryptor()
            outfile = outpath.open("wb")
            ciphertext = file.read(1024)
            while ciphertext and len(ciphertext) % 16 == 0:
                plaintext = decryptor.update(ciphertext)
                outfile.write(plaintext)
                ciphertext = file.read(1024)
        outfile.write(decryptor.finalize())
        outfile.close()


class SHRSHandler(StructHandler):
    NAME = "shrs"

    PATTERNS = [HexString("53 48 52 53")]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "dlink_header_t"
    EXTRACTOR = SHRSExtractor()

    def is_valid_header(self, header: Instance, file: File) -> bool:
        if header.file_size < len(header):
            return False
        # we're exactly past the header, we compute the digest
        digest = hashlib.sha512(file.read(header.file_size_no_padding)).digest()
        # we seek back to where we were
        file.seek(-header.file_size_no_padding, io.SEEK_CUR)
        if digest != header.encrypted_digest:
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.BIG)

        if not self.is_valid_header(header, file):
            raise InvalidInputFormat("Invalid SHRS header.")

        cipher = Cipher(algorithms.AES(KEY), modes.CBC(header.iv))
        decryptor = cipher.decryptor()
        read_bytes = 0

        while read_bytes < header.file_size:
            read_bytes += len(decryptor.update(file.read(1024)))
        end_offset = file.tell()

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
