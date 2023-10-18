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
        char sectors_count[8];
        uint32 yes;
        uint32 no;
        uint32 yes2;
        char media[1];
        char unknwon[3];
        char unknown2[4];
        char unknown3[4];
        char smartlogs[4];
        char compression_level[1];
        char error_granularity[4];
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

    typedef struct zlib_compressed {
        uint32 compression_type;
        uint32 compressed_information;
        char check_bits[5];
        char dictionary_flag[1];
        uint16 compression_level;
    } zlib_compressed_t;
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


class EWFExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def table_descriptor(self, file: File, position: int, outdir: Path, sectors_per_chunk: int, table_offset_start):
        fs = FileSystem(outdir)
        entries = []
        header = self._struct_parser.parse("table_descriptor_t", file, Endian.LITTLE)
        entry_path = Path("ewf.extracted")

        for _ in range(header.number_of_entries):
            entry = self._struct_parser.parse("table_entry_t", file, Endian.LITTLE)
            entries.append(int.from_bytes(entry.offset, byteorder="little"))
            

        with fs.open(entry_path) as output_file:
            for offset in entries:
                offset = position + offset - DESCRIPTOR_LEN
                file.seek(offset, io.SEEK_SET)
                
                magic_bytes = file.read(2)
                compressed = any(magic_bytes == magic.value for magic in ZlibMagic)
                for chunk in iterate_file(file, offset, sectors_per_chunk):
                    if compressed:
                        compressed_chunk = zlib.decompress(chunk)
                        output_file.write(compressed_chunk)
                    output_file.write(chunk)

    def extract(self, inpath: Path, outdir: Path):
        with File.from_path(inpath) as file:
            file.seek(EWF_HEADER_LEN)  # we skip the initial header
            data_descriptor = self._struct_parser.parse("data_descriptor_t", file, Endian.LITTLE)


            sectors_per_chunk = 0
            position = 0
            # the file is made of section, we loop over all the sections
            while data_descriptor.definition != Definition.DONE.value:
                logger.debug("data_descriptor_t", header=data_descriptor, _verbosity=3)
                file.seek(data_descriptor.next_offset, io.SEEK_SET)
                data_descriptor = self._struct_parser.parse("data_descriptor_t", file, Endian.LITTLE)

                if data_descriptor.definition == Definition.VOLUME.value:
                    
                    volume_descriptor = self._struct_parser.parse("volume_descriptor_t", file, Endian.LITTLE)
                    error_granularity = int.from_bytes(volume_descriptor.error_granularity, byteorder="big")
                    logger.debug("error_granularity", error_granularity=error_granularity, _verbosity=3)
                    sectors_per_chunk = find_chunk_size(volume_descriptor)

                if data_descriptor.definition == Definition.SECTORS.value:
                    position = file.tell()

                if data_descriptor.definition == Definition.TABLE.value:
                    table_offset_start = data_descriptor.next_offset
                    self.table_descriptor(file, position, outdir, sectors_per_chunk, table_offset_start)


class _EFWHandlerBase(StructHandler):
    HEADER_STRUCT = "ewf_header_t"
    EXTRACTOR = EWFExtractor()
    C_DEFINITIONS = C_DEFINITIONS

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk:
        self.parse_header(file, endian=Endian.LITTLE)

        data_descriptor = self._struct_parser.parse("data_descriptor_t", file, Endian.LITTLE)
        while data_descriptor.definition != Definition.DONE.value:
            file.seek(data_descriptor.next_offset, io.SEEK_SET)
            data_descriptor = self._struct_parser.parse("data_descriptor_t", file, Endian.LITTLE)

        return ValidChunk(start_offset=start_offset, end_offset=file.tell())


class EWFEHandler(_EFWHandlerBase):
    NAME = "ewfe"
    PATTERNS = [HexString("45 56 46 09 0d 0a ff 00 01 [2] 00")]

class EWFLHandler(_EFWHandlerBase):
    NAME = "ewfl"
    PATTERNS = [HexString("4C 56 46 09 0d 0a ff 00 01 [2] 00")]
    
