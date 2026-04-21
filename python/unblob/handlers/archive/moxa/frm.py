from __future__ import annotations

import gzip
import io
from enum import IntEnum
from pathlib import Path

from unblob.file_utils import Endian, File, FileSystem, InvalidInputFormat, StructParser
from unblob.models import (
    Extractor,
    HandlerDoc,
    HandlerType,
    HexString,
    StructHandler,
    ValidChunk,
)

C_DEFINITIONS = r"""
    typedef struct frm_container_header {
        char    magic[4];       /* *FRM */
        uint32  unknown1;       /* version maybe, only 00 00 00 01 observed */
        uint32  total_length;   /* the size of the whole container (should equal the sum of the section sizes + header_length) */
        uint16  header_length;  /* only 60 00 observed -> size 0x60 = 96 */
        uint16  section_count;  /* only 02 00 observed -> 2 section entries (webserver FS and FW binary) */
        uint8   unknown2[48];   /* optional unknown entries; empty in some samples */
    } frm_container_header_t;

    typedef struct frm_section_entry {
        uint32  type;   /* probably type; values 1 (FW binary) and 2 (webserver FS) observed */
        uint32  offset;
        uint32  length;
        uint32  unknown;
    } frm_section_entry_t;

    typedef struct frm_fs_header {
        char    device_name[32];
        uint8   unknown1[4];        /* version maybe? */
        uint32  timestamp;          /* creation time (UNIX timestamp) */
        uint32  unknown2;
        uint32  unknown3;           /* maybe checksum? */
        uint32  file_table_offset;  /* offset of the file table; only 0x100 observed -> usually starts at 0x160 */
        uint32  file_table_length;  /* size of the file table (= file_header_length * file_count) */
        uint16  file_header_length; /* size of each entry; only 0x40 (64) observed */
        uint16  file_count;         /* the number of table entries (files) */
        uint32  data_length;        /* the length of the file content data */
        uint16  unknown4;
        uint16  file_count2;        /* for some devices (e.g. Nport 5600) this field contains the file count and file_count is 0 */
        uint32  file_table_length2;
        uint32  unknown5;
    } frm_fs_header_t;

    typedef struct frm_file_header {
        char    name[48];
        uint8   unknown[8];    /* could be the creation time */
        uint32  file_length;
        uint32  data_offset;
    } frm_file_header_t;
"""

MAGIC = b"*FRM"
GZIP_MAGIC = bytes.fromhex("1f 8b")


class SectionTypes(IntEnum):
    FW_BINARY = 1
    FILESYSTEM = 2


class MoxaFRMExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse(
                "frm_container_header_t", file, Endian.LITTLE
            )
            sections = self._parse_section_table(file, header.section_count)
            for section in sections:
                self._extract_section(section, file, fs)

    def _parse_section_table(self, file: File, section_count: int):
        return [
            self._struct_parser.parse("frm_section_entry_t", file, Endian.LITTLE)
            for _ in range(section_count)
        ]

    def _extract_section(self, section, file: File, fs: FileSystem):
        match section.type:
            case SectionTypes.FW_BINARY:
                fs.carve(Path("firmware.bin"), file, section.offset, section.length)
            case SectionTypes.FILESYSTEM:
                self._extract_fs_section(file, fs, section.offset)
            case _:
                raise InvalidInputFormat(f"Unknown section type: {section.type}")

    def _extract_fs_section(self, file: File, fs: FileSystem, section_offset: int):
        file.seek(section_offset, io.SEEK_SET)
        fs_header = self._struct_parser.parse("frm_fs_header_t", file, Endian.LITTLE)

        file_table_offset = section_offset + fs_header.file_table_offset
        for index in range(fs_header.file_count or fs_header.file_count2):
            entry_offset = file_table_offset + index * fs_header.file_header_length
            file.seek(entry_offset, io.SEEK_SET)
            entry = self._struct_parser.parse("frm_file_header_t", file, Endian.LITTLE)

            name = bytes(entry.name).rstrip(b"\x00")
            if not name:
                continue

            file.seek(section_offset + entry.data_offset, io.SEEK_SET)
            raw = file.read(entry.file_length)
            self._write_file(fs, Path(name.decode("ascii", errors="replace")), raw)

    @staticmethod
    def _write_file(fs: FileSystem, file_path: Path, file_contents: bytes):
        # some (but usually not all) files are GZIP compressed
        if file_contents[:2] == GZIP_MAGIC:
            file_contents = gzip.decompress(file_contents)
        fs.write_bytes(file_path, file_contents)


class MoxaFRMHandler(StructHandler):
    NAME = "moxa_frm"

    PATTERNS = [HexString("2A 46 52 4D 00 00 00 01 [4] 60 00 02 00")]

    DOC = HandlerDoc(
        name="Moxa FRM",
        description=(
            "Firmware container format used in Moxa firmware (e.g. NPort, MGate and MiiNePort devices)."
        ),
        handler_type=HandlerType.ARCHIVE,
        vendor="Moxa",
        references=[],
        limitations=[],
    )

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "frm_container_header_t"
    EXTRACTOR = MoxaFRMExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file)
        return ValidChunk(
            start_offset=start_offset, end_offset=start_offset + header.total_length
        )
