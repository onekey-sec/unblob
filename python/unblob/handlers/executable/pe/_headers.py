"""PE headers and section table, shared by the payloads of the PE handler."""

import io
from enum import IntEnum
from typing import Any

import attrs

from unblob.file_utils import Endian, File, InvalidInputFormat, StructParser
from unblob.models import Reference

# PE structures follow the Microsoft PE format specification:
#   https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
PE_REFERENCE = Reference(
    title="PE Format",
    url="https://learn.microsoft.com/en-us/windows/win32/debug/pe-format",
)

C_DEFINITIONS = r"""
    typedef struct dos_header {
        char   e_magic[2];        // "MZ"
        char   e_reserved[58];    // e_cblp .. e_res2, unused here
        uint32 e_lfanew;          // file offset of the PE signature
    } dos_header_t;

    typedef struct pe_file_header {
        char   signature[4];      // "PE\0\0"
        uint16 machine;
        uint16 number_of_sections;
        uint32 time_date_stamp;
        uint32 pointer_to_symbol_table;
        uint32 number_of_symbols;
        uint16 size_of_optional_header;
        uint16 characteristics;
    } pe_file_header_t;

    typedef struct optional_header_32 {
        uint16 magic;             // 0x10b
        uint8  major_linker_version;
        uint8  minor_linker_version;
        uint32 size_of_code;
        uint32 size_of_initialized_data;
        uint32 size_of_uninitialized_data;
        uint32 address_of_entry_point;
        uint32 base_of_code;
        uint32 base_of_data;
        uint32 image_base;
        uint32 section_alignment;
        uint32 file_alignment;
        uint16 major_operating_system_version;
        uint16 minor_operating_system_version;
        uint16 major_image_version;
        uint16 minor_image_version;
        uint16 major_subsystem_version;
        uint16 minor_subsystem_version;
        uint32 win32_version_value;
        uint32 size_of_image;
        uint32 size_of_headers;
        uint32 checksum;
        uint16 subsystem;
        uint16 dll_characteristics;
        uint32 size_of_stack_reserve;
        uint32 size_of_stack_commit;
        uint32 size_of_heap_reserve;
        uint32 size_of_heap_commit;
        uint32 loader_flags;
        uint32 number_of_rva_and_sizes;
    } optional_header_32_t;

    typedef struct optional_header_64 {
        uint16 magic;             // 0x20b
        uint8  major_linker_version;
        uint8  minor_linker_version;
        uint32 size_of_code;
        uint32 size_of_initialized_data;
        uint32 size_of_uninitialized_data;
        uint32 address_of_entry_point;
        uint32 base_of_code;
        uint64 image_base;
        uint32 section_alignment;
        uint32 file_alignment;
        uint16 major_operating_system_version;
        uint16 minor_operating_system_version;
        uint16 major_image_version;
        uint16 minor_image_version;
        uint16 major_subsystem_version;
        uint16 minor_subsystem_version;
        uint32 win32_version_value;
        uint32 size_of_image;
        uint32 size_of_headers;
        uint32 checksum;
        uint16 subsystem;
        uint16 dll_characteristics;
        uint64 size_of_stack_reserve;
        uint64 size_of_stack_commit;
        uint64 size_of_heap_reserve;
        uint64 size_of_heap_commit;
        uint32 loader_flags;
        uint32 number_of_rva_and_sizes;
    } optional_header_64_t;

    typedef struct data_directory {
        uint32 virtual_address;   // a file offset for the certificate table
        uint32 dir_size;
    } data_directory_t;

    typedef struct section_header {
        char   name[8];
        uint32 virtual_size;
        uint32 virtual_address;
        uint32 size_of_raw_data;
        uint32 pointer_to_raw_data;
        uint32 pointer_to_relocations;
        uint32 pointer_to_linenumbers;
        uint16 number_of_relocations;
        uint16 number_of_linenumbers;
        uint32 characteristics;
    } section_header_t;

    typedef struct debug_directory {
        uint32 characteristics;
        uint32 time_date_stamp;
        uint16 major_version;
        uint16 minor_version;
        uint32 debug_type;
        uint32 size_of_data;
        uint32 address_of_raw_data;
        uint32 pointer_to_raw_data;   // file offset of the debug data
    } debug_directory_t;
"""

PE_SIGNATURE = b"PE\x00\x00"

# IMAGE_NUMBEROF_DIRECTORY_ENTRIES: the loader ignores directories beyond these
MAX_DATA_DIRECTORIES = 16
# resource limit, real images have a handful of debug entries
MAX_DEBUG_ENTRIES = 64
# COFF symbol table entries are 18 bytes, the string table starts with its uint32 length
COFF_SYMBOL_SIZE = 18
COFF_STRING_TABLE_LENGTH_SIZE = 4
# the certificate table is quadword aligned after the image (PE format, "The Attribute
# Certificate Table")
CERTIFICATE_TABLE_ALIGNMENT = 8

_parser = StructParser(C_DEFINITIONS)


class OptionalHeaderMagic(IntEnum):
    PE32 = 0x10B
    PE32_PLUS = 0x20B


class Machine(IntEnum):
    I386 = 0x14C
    AMD64 = 0x8664


class DataDirectory(IntEnum):
    # The certificate table is the only data directory whose address is a file offset
    # and that is not mapped into a section: Authenticode signatures are appended there.
    SECURITY = 4
    DEBUG = 6


@attrs.frozen
class PEHeaders:
    """PE headers and section table of a PE file starting at ``start_offset``.

    All offsets in the structures are relative to ``start_offset``.
    """

    start_offset: int
    # cstruct instances
    file_header: Any
    optional_header: Any
    data_directories: list[Any]
    sections: list[Any]
    section_table_end: int

    @classmethod
    def parse(cls, file: File, start_offset: int) -> "PEHeaders":
        file.seek(start_offset, io.SEEK_SET)
        dos_header = _parser.parse("dos_header_t", file, Endian.LITTLE)

        file.seek(start_offset + dos_header.e_lfanew, io.SEEK_SET)
        file_header = _parser.parse("pe_file_header_t", file, Endian.LITTLE)
        if file_header.signature != PE_SIGNATURE:
            raise InvalidInputFormat("Missing PE signature")
        # number_of_sections is a uint16, which bounds the section table
        if not file_header.number_of_sections:
            raise InvalidInputFormat("PE without sections")

        optional_header = cls._parse_optional_header(file, file_header)
        data_directories = [
            _parser.parse("data_directory_t", file, Endian.LITTLE)
            for _ in range(
                min(optional_header.number_of_rva_and_sizes, MAX_DATA_DIRECTORIES)
            )
        ]

        file.seek(
            start_offset
            + dos_header.e_lfanew
            + len(file_header)
            + file_header.size_of_optional_header,
            io.SEEK_SET,
        )
        sections = [
            _parser.parse("section_header_t", file, Endian.LITTLE)
            for _ in range(file_header.number_of_sections)
        ]
        return cls(
            start_offset=start_offset,
            file_header=file_header,
            optional_header=optional_header,
            data_directories=data_directories,
            sections=sections,
            section_table_end=file.tell() - start_offset,
        )

    @staticmethod
    def _parse_optional_header(file: File, file_header):
        optional_header_offset = file.tell()
        magic = _parser.parse("uint16", file, Endian.LITTLE)
        match magic:
            case OptionalHeaderMagic.PE32:
                struct_name = "optional_header_32_t"
            case OptionalHeaderMagic.PE32_PLUS:
                struct_name = "optional_header_64_t"
            case _:
                raise InvalidInputFormat(f"Invalid optional header magic: {magic:#x}")

        file.seek(optional_header_offset, io.SEEK_SET)
        optional_header = _parser.parse(struct_name, file, Endian.LITTLE)

        data_directories_size = (
            min(optional_header.number_of_rva_and_sizes, MAX_DATA_DIRECTORIES)
            * _parser.cparser_le.data_directory_t.size
        )
        if (
            file_header.size_of_optional_header
            < len(optional_header) + data_directories_size
        ):
            raise InvalidInputFormat(
                f"Optional header too small: {file_header.size_of_optional_header}"
            )
        return optional_header

    def get_data_directory(self, index: DataDirectory):
        if len(self.data_directories) <= index:
            return None
        directory = self.data_directories[index]
        if not directory.virtual_address or not directory.dir_size:
            return None
        return directory

    def get_image_end(self, file: File) -> int:
        """Return the end of the PE image: headers, sections, debug data and COFF symbols."""
        return max(
            # SizeOfHeaders should cover the section table, but is not trusted to
            self.optional_header.size_of_headers,
            self.section_table_end,
            *(
                section.pointer_to_raw_data + section.size_of_raw_data
                for section in self.sections
                if section.size_of_raw_data
            ),
            self._get_debug_data_end(file),
            self._get_symbol_table_end(file),
        )

    def _rva_to_offset(self, rva: int, length: int) -> int | None:
        """Map an RVA range to a file offset, if it lies within a section's raw data."""
        for section in self.sections:
            if (
                section.pointer_to_raw_data
                and section.virtual_address <= rva
                and rva + length <= section.virtual_address + section.size_of_raw_data
            ):
                return rva - section.virtual_address + section.pointer_to_raw_data
        return None

    def _get_debug_data_end(self, file: File) -> int:
        """Return the end of debug data (e.g. CodeView records) stored outside of sections."""
        debug = self.get_data_directory(DataDirectory.DEBUG)
        if debug is None:
            return 0

        entry_size = _parser.cparser_le.debug_directory_t.size
        if debug.dir_size // entry_size > MAX_DEBUG_ENTRIES:
            raise InvalidInputFormat(f"Too many debug entries: {debug.dir_size}")

        # the debug directory itself is addressed by RVA, inside a section
        directory_offset = self._rva_to_offset(debug.virtual_address, debug.dir_size)
        if directory_offset is None:
            return 0

        file.seek(self.start_offset + directory_offset, io.SEEK_SET)
        entries = [
            _parser.parse("debug_directory_t", file, Endian.LITTLE)
            for _ in range(debug.dir_size // entry_size)
        ]
        return max(
            (
                entry.pointer_to_raw_data + entry.size_of_data
                for entry in entries
                if entry.pointer_to_raw_data
            ),
            default=0,
        )

    def _get_symbol_table_end(self, file: File) -> int:
        """Return the end of the COFF symbol and string tables (kept by e.g. MinGW)."""
        if (
            not self.file_header.pointer_to_symbol_table
            or not self.file_header.number_of_symbols
        ):
            return 0
        symbol_table_end = (
            self.file_header.pointer_to_symbol_table
            + self.file_header.number_of_symbols * COFF_SYMBOL_SIZE
        )
        # the string table follows the symbols, its length includes the length field
        file.seek(self.start_offset + symbol_table_end, io.SEEK_SET)
        string_table_length = _parser.parse("uint32", file, Endian.LITTLE)
        if string_table_length < COFF_STRING_TABLE_LENGTH_SIZE:
            raise InvalidInputFormat(
                f"Invalid COFF string table length: {string_table_length}"
            )
        return symbol_table_end + string_table_length
