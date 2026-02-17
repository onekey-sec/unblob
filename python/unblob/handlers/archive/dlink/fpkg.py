from __future__ import annotations

import io
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from struct import Struct
from typing import TYPE_CHECKING

from unblob.file_utils import Endian, FileSystem, InvalidInputFormat, StructParser
from unblob.models import (
    Extractor,
    File,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    ValidChunk,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


C_DEFINITIONS = r"""
    typedef struct cpkg_header {
        char     magic[4];           // "CPKG"
        uint32   unknown;            // 0x01_00_00_00 in all samples (maybe version)
        uint32   first_entry_offset;
    } cpkg_header_t;

    typedef struct fpkg_header {
        char     magic[4];           // "FPKG"
        uint32   unknown;            // 0x01_00_00_00 in all samples
        uint32   first_entry_offset;
        uint32   unknown2;           // only 0x00_00_00_01 observed
        uint32   name_len;           // length of model name field
        char     name[name_len];
    } fpkg_header_t;

    typedef struct file_header {
        uint32   header_len;         // only 0x1C (28) observed
        uint16   type;               // probably file type
        uint16   unknown;            // observed values: 0x0 and 0x6874
        uint32   file_size;          // size of file data
        char     filename[];
    } file_header_t;
"""
CPKG_HEADER = "cpkg_header_t"
FILE_HEADER = "file_header_t"
CPKG_HEADER_SIZE = 12
FILE_HEADER_SIZE = 0x1C
VALID_MAGICS = {b"FPKG", b"CPKG"}


@dataclass
class FileHeader(Struct):
    header_len: int
    type: int
    start_offset: int
    file_size: int
    filename: str
    total_size: int


class FileType(IntEnum):
    REGULAR_FILE = 0x100
    UNKNOWN = 0x101  # NOTE: not observed in the wild, but makes sense in sequence
    CHECKSUM = 0x102
    SIGNATURE = 0x103


class FPKGParser:
    def __init__(self, file: File, start_offset: int = 0):
        self.file = file
        self.start_offset = start_offset
        self.struct_parser = StructParser(C_DEFINITIONS)
        self.header = self.struct_parser.parse(CPKG_HEADER, file, Endian.BIG)
        self._validate_header(self.header)
        self.file_data_offset = start_offset + self.header.first_entry_offset

    def iter_entries(self) -> Iterable[FileHeader]:
        current_offset = self.file_data_offset
        while current_offset < self.file.size():
            self.file.seek(current_offset, io.SEEK_SET)
            entry = self.struct_parser.parse(FILE_HEADER, self.file, Endian.BIG)
            self._validate_file_header(entry)
            yield FileHeader(
                header_len=entry.header_len,
                file_size=entry.file_size,
                start_offset=current_offset + entry.header_len,
                type=entry.type,
                filename=entry.filename.rstrip().decode("utf-8", errors="replace"),
                total_size=entry.file_size + entry.header_len,
            )
            current_offset += entry.header_len + entry.file_size

    @staticmethod
    def _validate_file_header(file_header) -> None:
        if file_header.header_len != FILE_HEADER_SIZE:
            raise InvalidInputFormat(
                f"Invalid file header length: {file_header.header_len}"
            )
        if not file_header.filename.isascii():
            raise InvalidInputFormat(f"Invalid filename: {file_header.filename}")
        try:
            FileType(file_header.type)
        except ValueError as e:
            raise InvalidInputFormat(f"Invalid file type: {file_header.type}") from e

    @staticmethod
    def _validate_header(header) -> None:
        if header.magic not in VALID_MAGICS:
            raise InvalidInputFormat("Invalid magic")
        if header.first_entry_offset < CPKG_HEADER_SIZE:
            raise InvalidInputFormat(
                f"Invalid first entry offset: {header.first_entry_offset}"
            )


class FPKGExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            parser = FPKGParser(file)
            for entry in parser.iter_entries():
                fs.carve(
                    Path(entry.filename), file, entry.start_offset, entry.file_size
                )


class FPKGHandler(Handler):
    NAME = "fpkg"
    PATTERNS = [HexString("(43 | 46) 50 4B 47 01 00 00 00")]  # (C | F) P K G
    # FPKG and CPKG headers are compatible if we only care about the "first_entry_offset"
    EXTRACTOR = FPKGExtractor()
    DOC = HandlerDoc(
        name="D-Link FPKG",
        description="CPKG and FPKG are archive formats used in D-Link DFL firewall firmware",
        handler_type=HandlerType.ARCHIVE,
        vendor="D-Link",
        references=[],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        parser = FPKGParser(file, start_offset)
        entries = list(parser.iter_entries())
        if not entries:
            raise InvalidInputFormat("No valid entries found")

        end_offset = parser.file_data_offset + sum(e.total_size for e in entries)
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
