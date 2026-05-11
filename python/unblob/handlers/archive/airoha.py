import io
import lzma
from enum import IntEnum
from pathlib import Path

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)
from unblob.report import ExtractionProblem

C_DEFINITIONS = r"""
    typedef struct airoha_header {
        uint8  file_checksum[32];           /* SHA256 of the rest of the file */
        uint8  padding[224];                /* 0xFF padding */
        uint16 basic_info_tlv_type;         /* 0x11 BASIC_INFO */
        uint16 basic_info_tlv_length;       /* 10 */
        uint8  compression_type;            /* 0=NONE, 1=LZMA, 2=LZMA_AES */
        uint8  integrity_check_type;        /* 0=CRC32, 1=SHA256, 2=SHA256_RSA */
        uint32 firmware_offset;
        uint32 firmware_size;
    } airoha_header_t;

    typedef struct airoha_tlv_header {
        uint16 tlv_type;
        uint16 tlv_length;
    } airoha_tlv_header_t;

    typedef struct airoha_mover_info_header {
        uint32 number_of_sections;
    } airoha_mover_info_header_t;

    typedef struct airoha_section {
        uint32 source_offset;               /* offset in decompressed stream */
        uint32 decompressed_size;
        uint32 dest_offset;                 /* in-memory load address */
    } airoha_section_t;
"""

PRELUDE_SIZE = 256
PATTERN_FF_LEN = 16


class CompressionType(IntEnum):
    NONE = 0
    LZMA = 1
    LZMA_AES = 2


class TlvType(IntEnum):
    MOVER_INFO = 0x12
    TERMINATOR = 0xFFFF


class AirohaExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def _read_sections(self, file: File) -> list:
        sections: list = []
        while True:
            tlv = self._struct_parser.parse("airoha_tlv_header_t", file, Endian.LITTLE)
            if tlv.tlv_type == TlvType.TERMINATOR:
                break
            if tlv.tlv_type == TlvType.MOVER_INFO:
                mover = self._struct_parser.parse(
                    "airoha_mover_info_header_t", file, Endian.LITTLE
                )
                sections = [
                    self._struct_parser.parse("airoha_section_t", file, Endian.LITTLE)
                    for _ in range(mover.number_of_sections)
                ]
                break
            file.seek(tlv.tlv_length, io.SEEK_CUR)
        return sections

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("airoha_header_t", file, Endian.LITTLE)

            if header.compression_type == CompressionType.LZMA_AES:
                fs.record_problem(
                    ExtractionProblem(
                        problem=(
                            "Firmware blob is AES-encrypted (LZMA_AES); "
                            "decryption requires a per-vendor key/IV"
                        ),
                        resolution="Carved encrypted blob",
                    )
                )
                fs.carve(
                    Path("firmware.encrypted.bin"),
                    file,
                    header.firmware_offset,
                    header.firmware_size,
                )
                return ExtractResult(reports=fs.problems)

            sections = self._read_sections(file)
            if not sections:
                raise InvalidInputFormat("Airoha file has no MOVER_INFO sections")
            base_address = min(section.dest_offset for section in sections)
            firmware_name = Path(f"firmware_{base_address:08x}.bin")

            file.seek(header.firmware_offset, io.SEEK_SET)
            payload = file.read(header.firmware_size)  # ~5 MB max
            if header.compression_type == CompressionType.LZMA:
                payload = lzma.decompress(payload)

            with fs.open(firmware_name, "wb+") as outfile:
                for section in sections:
                    outfile.seek(section.dest_offset - base_address, io.SEEK_SET)
                    outfile.write(
                        payload[
                            section.source_offset : section.source_offset
                            + section.decompressed_size
                        ]
                    )

        return ExtractResult(reports=fs.problems)


class AirohaHandler(StructHandler):
    NAME = "airoha"
    PATTERNS = [
        HexString(
            """
                FF FF FF FF FF FF FF FF
                FF FF FF FF FF FF FF FF             // 0xFF padding
                11 00 0A 00                         // BASIC_INFO TLV header (type=0x11, length=0x0A)
                ( 00 | 01 | 02 )                    // compression_type: NONE | LZMA | LZMA_AES
                ( 00 | 01 | 02 )                    // integrity_check_type: CRC32 | SHA256 | SHA256+RSA
            """
        ),
    ]
    PATTERN_MATCH_OFFSET = -(PRELUDE_SIZE - PATTERN_FF_LEN)
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "airoha_header_t"
    EXTRACTOR = AirohaExtractor()
    DOC = HandlerDoc(
        name="Airoha BT firmware",
        description=(
            "Airoha Bluetooth audio firmware files are either compressed or encrypted. These firmwares are used on Bluetooth audio chips that can be found in popular earbuds and headphones."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="Airoha",
        references=[
            Reference(
                title="Airoha firmware parser (010 Editor template + decryptor)",
                url="https://github.com/ramikg/airoha-firmware-parser",
            ),
            Reference(
                title="Airoha Bluetooth security vulnerabilities",
                url="https://insinuator.net/2025/06/airoha-bluetooth-security-vulnerabilities/",
            ),
        ],
        limitations=[
            "AES-encrypted firmware blobs are only carved, decryption requires a per-vendor AES key/IV not embedded in the file.",
        ],
    )

    def is_valid_header(self, header) -> bool:
        return header.firmware_offset >= PRELUDE_SIZE and header.firmware_size > 0

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk:
        header = self.parse_header(file, endian=Endian.LITTLE)

        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid Airoha header.")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + header.firmware_offset + header.firmware_size,
        )
