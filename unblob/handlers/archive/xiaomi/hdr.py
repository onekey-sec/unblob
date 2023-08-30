import binascii
import io
from pathlib import Path
from typing import Iterable, Optional, Tuple, cast

from dissect.cstruct import Instance
from structlog import get_logger

from unblob.file_utils import (
    File,
    FileSystem,
    InvalidInputFormat,
    iterate_file,
    snull,
)
from unblob.models import (
    Endian,
    Extractor,
    ExtractResult,
    HexString,
    StructHandler,
    StructParser,
    ValidChunk,
)

logger = get_logger()
CRC_CONTENT_OFFSET = 12  # The CRC32 value is located after 12 byte in the header
SIGNATURE_LEN = 272  # signature_header_t contains 4 bytes of size + 12 bytes for padding x3 + 0x100 is 256 in decimal
BLOB_MAGIC = 0x000000BEBA  # Blob header magic

# https://lxr.openwrt.org/source/firmware-utils/src/xiaomifw.c
C_DEFINITIONS = r"""
    struct hdr1_header {
          char magic[4];                /* HDR1 */
          uint32 signature_offset;
          uint32 crc32;
          uint16 unused;
          uint16 device_id;             /* RA70 */
          uint32 blob_offsets[8];
    } hdr1_header_t;

    struct hdr2_header {
          char magic[4];                /* HDR1 */
          uint32 signature_offset;
          uint32 crc32;
          uint32 unused1;
          uint64 device_id;             /* RA70 */
          uint64 region;                /* EU */
          uint64 unused2[2];
          uint32 blob_offsets[8];
    } hdr2_header_t;

    struct xiaomi_blob_header {
          uint32 magic;                 /* 0x0000babe */
          uint32 flash_offset;
          uint32 size;                  /* Size of blob */
          uint16 type;                  /* Type of blob */
          uint16 unused;
          char name[32];                /* Name of blob */
    } blob_header_t;

    struct xiaomi_signature_header {
          uint32 size;
          uint32 padding[3];
          uint8 content[0x100];
    } signature_header_t;
 """


def calculate_crc(file: File, start_offset: int, size: int) -> int:
    digest = 0
    for chunk in iterate_file(file, start_offset, size):
        digest = binascii.crc32(chunk, digest)
    return (digest ^ -1) & 0xFFFFFFFF


def is_valid_blob_header(blob_header: Instance) -> bool:
    if blob_header.magic == BLOB_MAGIC:
        return False
    if not blob_header.size:
        return False
    try:
        snull(blob_header.name).decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def is_valid_header(header: Instance) -> bool:
    if header.signature_offset < len(header):
        return False
    if not header.blob_offsets[0]:
        return False
    return True


class HDRExtractor(Extractor):
    def __init__(self, header_struct: str):
        self.header_struct = header_struct
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            for output_path, start_offset, size in self.parse(file):
                fs.carve(output_path, file, start_offset, size)
        return ExtractResult(reports=fs.problems)

    def parse(self, file: File) -> Iterable[Tuple[Path, int, int]]:
        header = self._struct_parser.parse(self.header_struct, file, Endian.LITTLE)
        for offset in cast(Iterable, header.blob_offsets):
            if not offset:
                break

            file.seek(offset, io.SEEK_SET)
            blob_header = self._struct_parser.parse(
                "blob_header_t", file, Endian.LITTLE
            )
            logger.debug("blob_header_t", blob_header_t=blob_header, _verbosity=3)
            if not is_valid_blob_header(blob_header):
                raise InvalidInputFormat("Invalid HDR blob header.")

            yield (
                (
                    Path(snull(blob_header.name).decode("utf-8")),
                    # file.tell() points to right after the blob_header == start_offset
                    file.tell(),
                    blob_header.size,
                )
            )


class HDRHandlerBase(StructHandler):
    HEADER_STRUCT = "hdr1_header_t"

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.LITTLE)

        if not is_valid_header(header):
            raise InvalidInputFormat("Invalid HDR header.")

        end_offset = start_offset + header.signature_offset + SIGNATURE_LEN

        if not self._is_crc_valid(file, header, start_offset, end_offset):
            raise InvalidInputFormat("CRC32 does not match in HDR header.")

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)

    def _is_crc_valid(
        self, file: File, header: Instance, start_offset: int, end_offset: int
    ) -> bool:
        computed_crc = calculate_crc(
            file,
            start_offset=start_offset + CRC_CONTENT_OFFSET,
            size=end_offset - start_offset + CRC_CONTENT_OFFSET,
        )
        return header.crc32 == computed_crc


class HDR1Handler(HDRHandlerBase):
    NAME = "hdr1"
    PATTERNS = [
        HexString(
            """
            //  48 44 52 31 90 32 e2 00  02 2a 5b 6a 00 00 11 00  HDR1.2...*[j....
            //  30 00 00 00 70 02 00 00  a4 02 e0 00 00 00 00 00  0...p...........
            48 44 52 31
        """
        ),
    ]
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "hdr1_header_t"

    EXTRACTOR = HDRExtractor("hdr1_header_t")


class HDR2Handler(HDRHandlerBase):
    NAME = "hdr2"
    PATTERNS = [
        HexString(
            """
            // 48 44 52 32 d4 02 78 02  68 54 e8 fa 00 00 00 00  HDR2..x.hT......
            // 52 41 37 30 00 00 00 00  45 55 00 00 00 00 00 00  RA70....EU......
            48 44 52 32
        """
        ),
    ]
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "hdr2_header_t"
    EXTRACTOR = HDRExtractor("hdr2_header_t")
