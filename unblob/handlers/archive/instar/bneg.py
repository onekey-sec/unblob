from pathlib import Path
from typing import Optional

from structlog import get_logger

from unblob.extractor import carve_chunk_to_file
from unblob.file_utils import Endian, File, InvalidInputFormat, StructParser
from unblob.models import Chunk, Extractor, HexString, StructHandler, ValidChunk

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct bneg_header {
        uint32 magic;           /* BNEG */
        uint32 major;
        uint32 minor;
        uint32 partition_1_size;
        uint32 partition_2_size;
    } bneg_header_t;
"""


class BNEGExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("bneg_header_t", file, Endian.LITTLE)
            header_end_offset = len(header)

            start_offset = header_end_offset
            end_offset = header_end_offset + header.partition_1_size

            logger.debug(
                "extracting partition 1",
                start_offset=start_offset,
                end_offset=end_offset,
                _verbosity=3,
            )
            carve_chunk_to_file(
                file=file,
                chunk=Chunk(start_offset=start_offset, end_offset=end_offset),
                carve_path=outdir.joinpath("part1"),
            )

            start_offset = end_offset
            end_offset = end_offset + header.partition_2_size

            logger.debug(
                "extracting partition 2",
                start_offset=start_offset,
                end_offset=end_offset,
                _verbosity=3,
            )
            carve_chunk_to_file(
                file=file,
                chunk=Chunk(start_offset=start_offset, end_offset=end_offset),
                carve_path=outdir.joinpath("part2"),
            )


class BNEGHandler(StructHandler):
    NAME = "bneg"

    PATTERNS = [HexString("42 4E 45 47")]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "bneg_header_t"
    EXTRACTOR = BNEGExtractor()

    def is_valid_header(self, header) -> bool:
        if header.partition_1_size == 0:
            return False
        if header.partition_2_size == 0:
            return False
        if header.major != 0x1:
            return False
        if header.minor != 0x1:  # noqa: SIM103
            return False

        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, endian=Endian.LITTLE)

        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid bneg header.")

        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset
            + len(header)
            + header.partition_1_size
            + header.partition_2_size,
        )
