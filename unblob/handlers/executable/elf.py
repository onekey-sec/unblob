import io
from pathlib import Path
from typing import Optional

import lief
from dissect.cstruct import Instance

from unblob.extractor import carve_chunk_to_file
from unblob.file_utils import (
    Endian,
    File,
    convert_int8,
    convert_int32,
    convert_int64,
    round_up,
)
from unblob.models import ExtractError, Extractor, HexString, StructHandler, ValidChunk

lief.logging.set_level(lief.logging.LOGGING_LEVEL.ERROR)


class NullExtract(ExtractError):
    pass


class ELFKernelExtractor(Extractor):
    KERNEL_SYMBOLS_SECTION = "__ksymtab"
    KERNEL_INIT_DATA_SECTION = ".init.data"

    def extract(self, inpath: Path, outdir: Path):
        elf = lief.ELF.parse(str(inpath))

        if not (
            elf.header.file_type == lief.ELF.E_TYPE.EXECUTABLE
            and elf.has_section(self.KERNEL_SYMBOLS_SECTION)
        ):
            # Non Linux kernel image
            raise NullExtract()

        self.extract_initramfs(elf, inpath, outdir)

    def extract_initramfs(self, elf, inpath, outdir):
        if not elf.has_section(self.KERNEL_INIT_DATA_SECTION):
            raise NullExtract()

        init_data = elf.get_section(self.KERNEL_INIT_DATA_SECTION)

        if not init_data.size:
            raise NullExtract()

        is_64bit = elf.header.identity_class == lief.ELF.ELF_CLASS.CLASS64
        endian = (
            Endian.LITTLE
            if elf.header.identity_data == lief.ELF.ELF_DATA.LSB
            else Endian.BIG
        )

        with File.from_path(inpath) as file:
            init_data_end_offset = init_data.file_offset + init_data.size

            # initramfs size is at the end of the section either 64bit or 32bit depending on the platform
            # see usr/initramfs_data.S in the kernel
            # The size is padded to 8 bytes, see include/asm-generic/vmlinux.lds.h
            # The actual initramfs is right before the size
            if is_64bit:
                initramfs_size_offset = init_data.file_offset + init_data.size - 8
                initramfs_size = convert_int64(
                    file[initramfs_size_offset:init_data_end_offset],
                    endian=endian,
                )
            else:
                initramfs_size_offset = init_data.file_offset + init_data.size - 4
                initramfs_size = convert_int32(
                    file[initramfs_size_offset:init_data_end_offset],
                    endian=endian,
                )

            max_padding = 0
            while (
                file[initramfs_size_offset - max_padding - 1] == 0 and max_padding < 8
            ):
                max_padding += 1

            padding = min(max_padding, round_up(initramfs_size, 8) - initramfs_size + 4)

            initramfs_end = initramfs_size_offset - padding
            initramfs_start = initramfs_end - initramfs_size

            carve_chunk_to_file(
                outdir.joinpath("initramfs"),
                file,
                ValidChunk(start_offset=initramfs_start, end_offset=initramfs_end),
            )


class _ELFBase(StructHandler):

    EXTRACTOR = ELFKernelExtractor()
    SECTION_HEADER_STRUCT = "elf_shdr_t"
    PROGRAM_HEADER_STRUCT = "elf_phdr_t"

    @staticmethod
    def _check_field(field, value):
        # LIEF uses pybind11 where Enum lookup always finds a value, but unknown values are returned as '???'
        # https://github.com/pybind/pybind11/blob/68a0b2dfd8cb3f5ac1846f22b6a8d0d539cb493c/include/pybind11/pybind11.h#L1907
        # we need to validate if the matched value is indeed a valid value
        if field(value).name not in field.__members__:
            raise ValueError

    def is_valid_header(self, header: Instance) -> bool:
        # check that header fields have valid values
        try:
            self._check_field(lief.ELF.E_TYPE, header.e_type)
            self._check_field(lief.ELF.ARCH, header.e_machine)
            self._check_field(lief.ELF.VERSION, header.e_version)
            return True
        except ValueError:
            return False

    @staticmethod
    def get_endianness(file: File, start_offset: int) -> Endian:
        file.seek(start_offset + 5, io.SEEK_SET)
        e_ident_data = convert_int8(file.read(1), Endian.LITTLE)
        return Endian.LITTLE if e_ident_data == 0x1 else Endian.BIG

    def get_last_section_end(
        self, file: File, sections_start_offset: int, sections_num: int, endian
    ) -> int:
        last_section_end = 0
        file.seek(sections_start_offset)

        for _ in range(sections_num):
            section_header = self._struct_parser.parse(
                self.SECTION_HEADER_STRUCT, file, endian
            )

            if (
                lief.ELF.SECTION_TYPES(section_header.sh_type)
                == lief.ELF.SECTION_TYPES.NOBITS
            ):
                continue

            section_end = section_header.sh_offset + section_header.sh_size
            if section_end > last_section_end:
                last_section_end = section_end

        return last_section_end

    def get_last_program_end(
        self, file: File, programs_start_offset: int, programs_num: int, endian
    ) -> int:
        last_program_end = 0
        file.seek(programs_start_offset)

        for _ in range(programs_num):
            program_header = self._struct_parser.parse(
                self.PROGRAM_HEADER_STRUCT, file, endian
            )

            program_end = program_header.p_offset + program_header.p_filesz
            if program_end > last_program_end:
                last_program_end = program_end

        return last_program_end

    def get_end_offset(
        self, file: File, start_offset: int, header: Instance, endian
    ) -> int:
        # Usually the section header is the last, but in some cases the program headers are
        # put to the end of the file, and in some cases sections header and actual sections
        # can be also intermixed, so we need also to check the end of the last section and
        # also the last program segment.
        # We check which one is the last and use it as a file size.
        section_headers_end = (
            start_offset + header.e_shoff + (header.e_shnum * header.e_shentsize)
        )
        program_headers_end = (
            start_offset + header.e_phoff + (header.e_phnum * header.e_phentsize)
        )

        last_section_end = self.get_last_section_end(
            file, start_offset + header.e_shoff, header.e_shnum, endian
        )

        last_program_end = self.get_last_program_end(
            file, start_offset + header.e_phoff, header.e_phnum, endian
        )

        return max(
            section_headers_end, program_headers_end, last_section_end, last_program_end
        )

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        endian = self.get_endianness(file, start_offset)
        file.seek(start_offset, io.SEEK_SET)
        header = self.parse_header(file, endian)
        if not self.is_valid_header(header):
            return
        end_offset = self.get_end_offset(file, start_offset, header, endian)
        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )


class ELF32Handler(_ELFBase):

    NAME = "elf32"

    PATTERNS = [
        HexString(
            """
            // uint32 e_ident_magic;
            7F 45 4C 46
            // e_ident_class must be 0x1 (32bit) or 0x2 (64bit)
            01
            // e_ident_data must be 0x1 (little-endian) or 0x2 (big-endian)
            (01 | 02)
            // e_ident_version must be 0x1.
            01
            """
        )
    ]

    C_DEFINITIONS = r"""
        typedef struct elf_header_32 {
            uint32 e_ident_magic;
            uint8 e_ident_class;
            uint8 e_ident_data;
            uint8 e_ident_version;
            uint8 e_ident_osabi;
            uint8 e_ident_abi_version;
            uint8 e_ident_pad[7];
            uint16 e_type;
            uint16 e_machine;
            uint32 e_version;
            uint32 e_entry;
            uint32 e_phoff;
            uint32 e_shoff;
            uint32 e_flags;
            uint16 e_ehsize;
            uint16 e_phentsize;
            uint16 e_phnum;
            uint16 e_shentsize;
            uint16 e_shnum;
            uint16 e_shstrndx;
        } elf_header_32_t;

        typedef struct elf32_shdr {
               uint32   sh_name;
               uint32   sh_type;
               uint32   sh_flags;
               uint32   sh_addr;
               uint32   sh_offset;
               uint32   sh_size;
               uint32   sh_link;
               uint32   sh_info;
               uint32   sh_addralign;
               uint32   sh_entsize;
       } elf_shdr_t;

       typedef struct elf32_phdr {
               uint32  p_type;
               uint32  p_offset;
               uint32  p_vaddr;
               uint32  p_paddr;
               uint32  p_filesz;
               uint32  p_memsz;
               uint32  p_flags;
               uint32  p_align;
           } elf_phdr_t;
    """
    HEADER_STRUCT = "elf_header_32_t"


class ELF64Handler(_ELFBase):

    NAME = "elf64"

    PATTERNS = [
        HexString(
            """
            // uint32 e_ident_magic;
            7F 45 4C 46
            // e_ident_class must be 0x1 (32bit) or 0x2 (64bit)
            02
            // e_ident_data must be 0x1 (little-endian) or 0x2 (big-endian)
            (01 | 02)
            // e_ident_version must be 0x1.
            01
            """
        )
    ]

    C_DEFINITIONS = r"""
        typedef struct elf_header_64 {
            uint32 e_ident_magic;
            uint8 e_ident_class;
            uint8 e_ident_data;
            uint8 e_ident_version;
            uint8 e_ident_osabi;
            uint8 e_ident_abi_version;
            uint8 e_ident_pad[7];
            uint16 e_type;
            uint16 e_machine;
            uint32 e_version;
            uint64 e_entry;
            uint64 e_phoff;
            uint64 e_shoff;
            uint32 e_flags;
            uint16 e_ehsize;
            uint16 e_phentsize;
            uint16 e_phnum;
            uint16 e_shentsize;
            uint16 e_shnum;
            uint16 e_shstrndx;
        } elf_header_64_t;

        typedef struct elf64_shdr {
               uint32   sh_name;
               uint32   sh_type;
               uint64   sh_flags;
               uint64   sh_addr;
               uint64   sh_offset;
               uint64   sh_size;
               uint32   sh_link;
               uint32   sh_info;
               uint64   sh_addralign;
               uint64   sh_entsize;
       } elf_shdr_t;

       typedef struct elf64_phdr {
               uint32   p_type;
               uint32   p_flags;
               uint64   p_offset;
               uint64   p_vaddr;
               uint64   p_paddr;
               uint64   p_filesz;
               uint64   p_memsz;
               uint64   p_align;
           } elf_phdr_t;
    """
    HEADER_STRUCT = "elf_header_64_t"
