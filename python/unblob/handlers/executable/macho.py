import io
from enum import Enum, IntEnum
from pathlib import Path

import attrs

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
)
from unblob.models import (
    ExtractResult,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)


class MachOMagic(bytes, Enum):
    """Mach-O magics as they appear on disk (first 4 bytes).

    Fat headers are always big-endian; a thin magic is byte-swapped ("cigam")
    when the binary's endianness is big.
    """

    FAT = b"\xca\xfe\xba\xbe"  # fat / universal binary
    THIN_64_LE = b"\xcf\xfa\xed\xfe"  # 64-bit little-endian (arm64, x86_64)
    THIN_32_LE = b"\xce\xfa\xed\xfe"  # 32-bit little-endian (armv7, x86)
    THIN_64_BE = b"\xfe\xed\xfa\xcf"  # 64-bit big-endian
    THIN_32_BE = b"\xfe\xed\xfa\xce"  # 32-bit big-endian


# Header sizes in bytes
_HEADER_SIZE_32 = 28
_HEADER_SIZE_64 = 32  # adds a 4-byte reserved field

# Maps (cputype, cpusubtype) to a human-readable name for fat binary slice filenames
_CPU_ARCH_NAMES: dict[tuple[int, int], str] = {
    (0xC, 5): "arm_v4t",
    (0xC, 6): "arm_v6",
    (0xC, 9): "arm_v7",
    (0xC, 11): "arm_v7s",
    (0xC, 12): "arm_v7k",
    (0x100000C, 0): "arm64",
    (0x100000C, 1): "arm64_v8",
    (0x100000C, 2): "arm64e",
    (0x7, 3): "i386",
    (0x1000007, 3): "x86_64",
    (0x12, 0): "ppc",
    (0x1000012, 0): "ppc64",
}

# Single source of truth for every Mach-O structure, shared by the handler's struct parser
# and the fat binary extractor below.
C_DEFINITIONS = r"""
    typedef struct macho_header {
        uint32 magic;
        uint32 cputype;
        uint32 cpusubtype;
        uint32 filetype;
        uint32 ncmds;
        uint32 sizeofcmds;
        uint32 flags;
    } macho_header_t;

    typedef struct macho_load_command {
        uint32 cmd;
        uint32 cmdsize;
    } macho_load_command_t;

    // Covers both LC_SEGMENT (32-bit) and LC_SEGMENT_64 via a union. Only the fields up to
    // filesize are modelled (all we need to compute file extents), so the struct is 56 bytes
    // and never reads past the smaller 32-bit segment command.
    typedef struct macho_segment_command {
        uint32 cmd;
        uint32 cmdsize;
        char   segname[16];
        union {
            struct {
                uint32 vmaddr;
                uint32 vmsize;
                uint32 fileoff;
                uint32 filesize;
            } bits32;
            struct {
                uint64 vmaddr;
                uint64 vmsize;
                uint64 fileoff;
                uint64 filesize;
            } bits64;
        } seg;
    } macho_segment_command_t;

    typedef struct fat_header {
        uint32 magic;      // 0xcafebabe, always big-endian
        uint32 nfat_arch;  // number of architecture slices
    } fat_header_t;

    typedef struct fat_arch {
        uint32 cputype;    // CPU architecture type
        uint32 cpusubtype; // CPU subtype
        uint32 offset;     // file offset to this architecture's Mach-O slice
        uint32 slice_size; // size of this architecture's Mach-O slice
        uint32 align;      // slice alignment as a power of 2
    } fat_arch_t;
"""

_parser = StructParser(C_DEFINITIONS)


def _cpu_arch_name(cputype: int, cpusubtype: int) -> str:
    return _CPU_ARCH_NAMES.get(
        (cputype, cpusubtype), f"cputype_{cputype:#x}_{cpusubtype:#x}"
    )


class LoadCommandType(IntEnum):
    SEGMENT = 0x1
    SEGMENT_64 = 0x19


@attrs.define(repr=False)
class MachOChunk(ValidChunk):
    """A fat (universal) Mach-O binary whose architecture slices are carved out on extraction."""

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            fat_hdr = _parser.parse("fat_header_t", file, Endian.BIG)
            architectures = [
                _parser.parse("fat_arch_t", file, Endian.BIG)
                for _ in range(fat_hdr.nfat_arch)
            ]
            for arch in architectures:
                if arch.slice_size == 0:
                    continue
                cpu_name = _cpu_arch_name(arch.cputype, arch.cpusubtype)
                fs.carve(
                    Path(f"arch_{cpu_name}.macho"), file, arch.offset, arch.slice_size
                )
        return ExtractResult(reports=fs.problems)


class MachOHandler(StructHandler):
    NAME = "macho"

    EXTRACTOR = None

    PATTERNS = [
        # Thin Mach-O: magic (4) + [24] wildcards = full 28-byte common header guaranteed present,
        # avoiding false positives from partial matches and removing the need for truncation checks.
        HexString("CF FA ED FE [24]"),  # 64-bit little-endian (arm64, x86_64)
        HexString("CE FA ED FE [24]"),  # 32-bit little-endian (armv7, x86)
        HexString("FE ED FA CF [24]"),  # 64-bit big-endian
        HexString("FE ED FA CE [24]"),  # 32-bit big-endian
        # Fat (universal) binary:
        # CA FE BA BE              — fat magic (always big-endian)
        # 00 00 00 (01-08)         — nfat_arch 1-8; limits to <=8 architectures which
        #                            disambiguates from Java class files (major version ≥ 45)
        HexString("CA FE BA BE 00 00 00 (01|02|03|04|05|06|07|08)"),
    ]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "macho_header_t"

    DOC = HandlerDoc(
        name="Mach-O",
        description="Mach-O (Mach Object) is the native executable and library binary format used by macOS, iOS, tvOS, and watchOS. It encodes load commands describing memory segments, dynamic libraries, and code signing, and supports multiple CPU architectures via fat/universal binaries.",
        handler_type=HandlerType.EXECUTABLE,
        vendor="Apple",
        references=[
            Reference(
                title="Mach-O Programming Topics",
                url="https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/0-Introduction/introduction.html",
            ),
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        magic = file[start_offset : start_offset + 4]
        match magic:
            case MachOMagic.FAT:
                return self._calculate_fat_chunk(file, start_offset)
            case MachOMagic.THIN_64_LE:
                endian, is_64bit = Endian.LITTLE, True
            case MachOMagic.THIN_32_LE:
                endian, is_64bit = Endian.LITTLE, False
            case MachOMagic.THIN_64_BE:
                endian, is_64bit = Endian.BIG, True
            case MachOMagic.THIN_32_BE:
                endian, is_64bit = Endian.BIG, False
            case _:
                raise InvalidInputFormat(f"Unknown Mach-O magic: {magic.hex()}")
        return self._calculate_thin_chunk(file, start_offset, endian, is_64bit=is_64bit)

    def _calculate_thin_chunk(
        self, file: File, start_offset: int, endian: Endian, *, is_64bit: bool
    ) -> ValidChunk:
        header = self.parse_header(file, endian)

        # 64-bit headers have an extra 4-byte reserved field after flags
        hdr_size = _HEADER_SIZE_64 if is_64bit else _HEADER_SIZE_32
        file.seek(start_offset + hdr_size, io.SEEK_SET)

        end_offset = start_offset + hdr_size + header.sizeofcmds

        for _ in range(header.ncmds):
            lc_start = file.tell()
            lc = self._struct_parser.parse("macho_load_command_t", file, endian)

            if lc.cmdsize < 8:
                raise InvalidInputFormat(
                    f"Mach-O load command size too small: {lc.cmdsize}"
                )

            if lc.cmd in (LoadCommandType.SEGMENT, LoadCommandType.SEGMENT_64):
                file.seek(lc_start, io.SEEK_SET)
                command = self._struct_parser.parse(
                    "macho_segment_command_t", file, endian
                )
                seg = (
                    command.seg.bits64
                    if lc.cmd == LoadCommandType.SEGMENT_64
                    else command.seg.bits32
                )
                if seg.filesize > 0:
                    end_offset = max(
                        end_offset, start_offset + seg.fileoff + seg.filesize
                    )

            file.seek(lc_start + lc.cmdsize, io.SEEK_SET)

        # Thin Mach-O binaries are leaf files: the handler has no extractor, so the carved
        # chunk is preserved as-is (see Handler.extract).
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)

    def _calculate_fat_chunk(self, file: File, start_offset: int) -> MachOChunk:
        # Fat headers are always big-endian regardless of the contained architectures
        fat_hdr = self._struct_parser.parse("fat_header_t", file, Endian.BIG)

        end_offset = start_offset
        for _ in range(fat_hdr.nfat_arch):
            arch = self._struct_parser.parse("fat_arch_t", file, Endian.BIG)
            if arch.slice_size > 0:
                end_offset = max(
                    end_offset, start_offset + arch.offset + arch.slice_size
                )

        return MachOChunk(start_offset=start_offset, end_offset=end_offset)
