from enum import IntEnum

from unblob.file_utils import Endian, File, InvalidInputFormat
from unblob.models import (
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

# Mach-O magic values (bytes in file order)
_MAGIC_64_LE = 0xFEEDFACF  # CF FA ED FE — 64-bit little-endian (arm64, x86_64)
_MAGIC_32_LE = 0xFEEDFACE  # CE FA ED FE — 32-bit little-endian (armv7, x86)
_MAGIC_64_BE = 0xCFFAEDFE  # FE ED FA CF — 64-bit big-endian
_MAGIC_32_BE = 0xCEFAEDFE  # FE ED FA CE — 32-bit big-endian

# Header sizes in bytes
_HEADER_SIZE_32 = 28
_HEADER_SIZE_64 = 32  # adds a 4-byte reserved field


class LoadCommandType(IntEnum):
    SEGMENT = 0x1
    SEGMENT_64 = 0x19


class MachOHandler(StructHandler):
    NAME = "macho"

    EXTRACTOR = None

    PATTERNS = [
        # magic (4) + [24] wildcards = full 28-byte common header guaranteed present
        HexString("CF FA ED FE [24]"),  # 64-bit little-endian (arm64, x86_64)
        HexString("CE FA ED FE [24]"),  # 32-bit little-endian (armv7, x86)
        HexString("FE ED FA CF [24]"),  # 64-bit big-endian
        HexString("FE ED FA CE [24]"),  # 32-bit big-endian
    ]

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

        typedef struct macho_segment_command_32 {
            uint32 cmd;
            uint32 cmdsize;
            char   segname[16];
            uint32 vmaddr;
            uint32 vmsize;
            uint32 fileoff;
            uint32 filesize;
            uint32 maxprot;
            uint32 initprot;
            uint32 nsects;
            uint32 flags;
        } macho_segment_command_32_t;

        typedef struct macho_segment_command_64 {
            uint32 cmd;
            uint32 cmdsize;
            char   segname[16];
            uint64 vmaddr;
            uint64 vmsize;
            uint64 fileoff;
            uint64 filesize;
            uint32 maxprot;
            uint32 initprot;
            uint32 nsects;
            uint32 flags;
        } macho_segment_command_64_t;
    """
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
        magic = int.from_bytes(file.read(4), "little")
        file.seek(start_offset)

        if magic in (_MAGIC_64_LE, _MAGIC_32_LE):
            endian = Endian.LITTLE
            is_64bit = magic == _MAGIC_64_LE
        elif magic in (_MAGIC_64_BE, _MAGIC_32_BE):
            endian = Endian.BIG
            is_64bit = magic == _MAGIC_64_BE
        else:
            raise InvalidInputFormat(f"Unknown Mach-O magic: {magic:#010x}")

        header = self.parse_header(file, endian)

        # 64-bit headers have an extra 4-byte reserved field after flags
        if is_64bit:
            file.seek(start_offset + _HEADER_SIZE_64)

        hdr_size = _HEADER_SIZE_64 if is_64bit else _HEADER_SIZE_32
        end_offset = start_offset + hdr_size + header.sizeofcmds

        for _ in range(header.ncmds):
            lc_start = file.tell()
            lc = self._struct_parser.parse("macho_load_command_t", file, endian)

            if lc.cmdsize < 8:
                raise InvalidInputFormat(
                    f"Mach-O load command size too small: {lc.cmdsize}"
                )

            if lc.cmd == LoadCommandType.SEGMENT_64:
                file.seek(lc_start)
                seg = self._struct_parser.parse(
                    "macho_segment_command_64_t", file, endian
                )
                if seg.filesize > 0:
                    end_offset = max(
                        end_offset, start_offset + seg.fileoff + seg.filesize
                    )
            elif lc.cmd == LoadCommandType.SEGMENT:
                file.seek(lc_start)
                seg = self._struct_parser.parse(
                    "macho_segment_command_32_t", file, endian
                )
                if seg.filesize > 0:
                    end_offset = max(
                        end_offset, start_offset + seg.fileoff + seg.filesize
                    )

            file.seek(lc_start + lc.cmdsize)

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
