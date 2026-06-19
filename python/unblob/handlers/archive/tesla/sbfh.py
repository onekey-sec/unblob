import binascii
import io
from pathlib import Path

from unblob.file_utils import (
    Endian,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    iterate_file,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)
from unblob.report import ExtractionProblem

C_DEFINITIONS = """
    typedef struct sbfh_header {
        char     magic[4];              /* "SBFH" */
        uint32   header_size;
        char     unk[7];
        uint32   firmware_size;
        char     padding[265];
    } sbfh_header_t;

    typedef struct mrvl_header {
        char     magic[4];              /* "MRVL" */
        uint32   unk_const;             /* 0x2E9CF17B */
        uint32   creation_time;
        uint32   num_segments;          /* <= 9 */
        uint32   elf_version;
    } mrvl_header_t;

    typedef struct mrvl_segment_header {
        uint32   segment_type;          /* always 0x2 */
        uint32   offset;                /* relative to MRVL area start */
        uint32   seg_size;
        uint32   virtual_address;
        uint32   crc_checksum;
    } mrvl_segment_header_t;
"""


class SBFHExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            sbfh = self._struct_parser.parse("sbfh_header_t", file, Endian.LITTLE)

            mrvl = self._struct_parser.parse("mrvl_header_t", file, Endian.LITTLE)

            segments = [
                self._struct_parser.parse("mrvl_segment_header_t", file, Endian.LITTLE)
                for _ in range(mrvl.num_segments)
            ]

            base_vaddr = min(seg.virtual_address for seg in segments)
            image_path = Path(f"firmware_{base_vaddr:08x}.bin")

            # The segment data lives in the firmware region the header declares
            # (header_size + firmware_size), which is also the chunk boundary.
            data_end = sbfh.header_size + sbfh.firmware_size

            with fs.open(image_path, "wb+") as outfile:
                for seg in segments:
                    crc = 0xFFFFFFFF
                    seg_start = sbfh.header_size + seg.offset
                    seg_size = max(0, min(seg.seg_size, data_end - seg_start))
                    outfile.seek(seg.virtual_address - base_vaddr, io.SEEK_SET)
                    for chunk in iterate_file(file, seg_start, seg_size):
                        crc = binascii.crc32(chunk, crc)
                        outfile.write(chunk)
                    if (crc ^ -1) & 0xFFFFFFFF != seg.crc_checksum:
                        fs.record_problem(
                            ExtractionProblem(
                                problem=f"CRC mismatch in MRVL segment at vaddr 0x{seg.virtual_address:08x}",
                                resolution="Segment written anyway",
                            )
                        )

        return ExtractResult(reports=fs.problems)


class SBFHHandler(StructHandler):
    NAME = "sbfh"
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "sbfh_header_t"
    PATTERNS = [
        HexString(
            """53 42 46 48 // SBFH magic
        1C 01 00 00 // header_size
        [7] //unknown
        [4] // firmware_size
        [265] // padding
        4D 52 56 4C // MRVL magic
        7B F1 9C 2E // unknown constant
        [4] // creation_time
        (01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09) 00 00 00 // num_segments
        [2] 00 1F // elf version"""
        ),
    ]
    EXTRACTOR = SBFHExtractor()
    DOC = HandlerDoc(
        name="Tesla Wall Connector SBFH",
        description=(
            "SBFH format is used in Tesla Wall Connector firmware, contains also a Marvell MRVL blob of ARM V7 segments "
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="Tesla",
        references=[
            Reference(
                title="Tesla Wall Connector Firmware File Structure",
                url="https://akrutsinger.github.io/2023/10/08/tesla-wall-connector-firmware-file-structure.html",
            ),
            Reference(
                title="Marvell 88MW30x Firmware Tools",
                url="https://github.com/wfr/mrvl-88mw30x-firmware-tools",
            ),
            Reference(
                title="Exploiting the Tesla Wall Connector",
                url="https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector.html",
            ),
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        sbfh_header = self.parse_header(file, Endian.LITTLE)

        if sbfh_header.firmware_size == 0:
            raise InvalidInputFormat("Invalid SBFH header")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset
            + sbfh_header.header_size
            + sbfh_header.firmware_size,
        )
