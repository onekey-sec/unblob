import io
import math
import zlib
from enum import Enum
from pathlib import Path

from dissect.cstruct import Instance
from structlog import get_logger

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    iterate_file,
)
from unblob.models import Extractor, HexString, StructHandler, ValidChunk

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct ewf_header {
        char magic[8];
        uint8 field_start;
        uint16 segment_number;
        uint16 field_end;
    } ewf_header_t;

    typedef struct data_descriptor {
        char definition[16];
        uint64 next_offset;
        uint64 section_size;
        char padding[40];
        uint32 adler_32;
    } data_descriptor_t;

    typedef struct volume_descriptor {
        uint32 unknown;
        uint32 chunk_count;
        uint32 sectors_per_chunks;
        uint32 bytes_per_sectors;
        uint32 sectors_count;
    } volume_descriptor_t;

    typedef struct table_descriptor {
        uint32 number_of_entries;
        char padding[16];
        uint32 adler_32;
    } table_descriptor_t;

    typedef struct table_entry {
        char offset[3];
        char compression_type[1];
    } table_entry_t;
    typedef struct hash_descriptor {
        char md5_hash[16];
        char unknown[16];
        uint32 adler_32;
    } hash_descriptor_t;
"""

EWF_HEADER_LEN = 13
DESCRIPTOR_LEN = 76


class Definition(Enum):
    DONE = b"done".ljust(16, b"\x00")
    TABLE = b"table".ljust(16, b"\x00")
    SECTORS = b"sectors".ljust(16, b"\x00")
    VOLUME = b"volume".ljust(16, b"\x00")


class ZlibMagic(Enum):
    LOW = b"\x78\x01"
    DEFAULT = b"\x78\x9c"
    BEST = b"\x78\xda"
    COMPRESSION = b"\x78\x5e"


def find_chunk_size(header: Instance) -> int:
    size = header.sectors_per_chunks
    log = math.log(size, 2)
    power = math.pow(2, log + 9)
    return int(power)


def is_valid_header(header: Instance) -> bool:
    if header.field_start != 0x01 or header.field_end != 0x0:
        return False
    return True


class EWFExtractor(Extractor):
    def __init__(self, header_struct: str):
        self.header_struct = header_struct
        self._struct_parser = StructParser(C_DEFINITIONS)

    def table_descriptor(
        self, file: File, position: int, outdir: Path, sectors_per_chunk: int
    ) -> Instance:
        fs = FileSystem(outdir)
        entries = []
        header = self._struct_parser.parse("table_descriptor_t", file, Endian.LITTLE)
        entry_path = Path("ewf.decrypted")

        for _ in range(header.number_of_entries):
            entry = self._struct_parser.parse("table_entry_t", file, Endian.LITTLE)
            entries.append(entry.offset)

        with fs.open(entry_path) as output_file:
            for offset in entries:
                file.seek(
                    position
                    + int.from_bytes(offset, byteorder="little")
                    - DESCRIPTOR_LEN,
                    io.SEEK_SET,
                )

                magic_bytes = file.read(2)
                compressed = any(magic_bytes == magic.value for magic in ZlibMagic)

                for chunk in iterate_file(
                    file,
                    position
                    + int.from_bytes(offset, byteorder="little")
                    - DESCRIPTOR_LEN,
                    sectors_per_chunk,
                ):
                    if compressed:
                        compressed_chunk = zlib.decompress(chunk)
                        output_file.write(compressed_chunk)
                    output_file.write(chunk)

    def extract(self, inpath: Path, outdir: Path):
        with File.from_path(inpath) as file:
            file.seek(EWF_HEADER_LEN)  # we skip the initial header
            data_descriptor = self._struct_parser.parse(
                "data_descriptor_t", file, Endian.LITTLE
            )
            logger.debug("data_descriptor_t", header=data_descriptor, _verbosity=3)

            # the file is made of section, we loop over all the sections
            while data_descriptor.definition != Definition.DONE.value:
                file.seek(data_descriptor.next_offset, io.SEEK_SET)
                data_descriptor = self._struct_parser.parse(
                    "data_descriptor_t", file, Endian.LITTLE
                )
                logger.debug("data_descriptor_t", header=data_descriptor, _verbosity=3)

                if data_descriptor.definition == Definition.VOLUME.value:
                    volume_descriptor = self._struct_parser.parse(
                        "volume_descriptor_t", file, Endian.LITTLE
                    )
                    sectors_per_chunk = find_chunk_size(volume_descriptor)

                if data_descriptor.definition == Definition.SECTORS.value:
                    position = file.tell()

                if data_descriptor.definition == Definition.TABLE.value:
                    self.table_descriptor(file, position, outdir, sectors_per_chunk)


class EFWHandlerBase(StructHandler):
    HEADER_STRUCT = "ewf_header_t"

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk:
        header = self.parse_header(file, endian=Endian.LITTLE)

        if not is_valid_header(header):
            raise InvalidInputFormat("Invalid EWF header")

        data_descriptor = self._struct_parser.parse(
            "data_descriptor_t", file, Endian.LITTLE
        )
        while data_descriptor.definition != Definition.DONE.value:
            file.seek(data_descriptor.next_offset, io.SEEK_SET)
            data_descriptor = self._struct_parser.parse(
                "data_descriptor_t", file, Endian.LITTLE
            )

        return ValidChunk(start_offset=start_offset, end_offset=file.tell())


class EWFEHandler(EFWHandlerBase):
    NAME = "ewfe"

    PATTERNS = [HexString("45 56 46 09 0d 0a ff 00")]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "ewf_header_t"
    EXTRACTOR = EWFExtractor("ewf_header_t")


class EWFLHandler(EFWHandlerBase):
    NAME = "ewfl"

    PATTERNS = [HexString("4C 56 46 09 0d 0a ff 00")]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "ewf_header_t"
    EXTRACTOR = EWFExtractor("ewf_header_t")
