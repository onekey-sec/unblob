import bz2
import gzip
import io
import lzma
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any

import pyzstd
from structlog import get_logger

from ...file_utils import FileSystem, convert_int32, convert_int64, round_up
from ...models import (
    Endian,
    Extractor,
    ExtractResult,
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    InvalidInputFormat,
    Reference,
    StructHandler,
    StructParser,
    ValidChunk,
)
from .cpio import CPIOEntry, PortableASCIIParser, StrippedCPIOParser

logger = get_logger()

RPM_SIGNATURE_ALIGNMENT = 8
RPMSIGTAG_SIZE = 1000  # INT32
RPMSIGTAG_LONGSIZE = 270  # INT64
RPMTAG_PAYLOADCOMPRESSOR = 1125
RPMTAG_PAYLOADFLAGS = 1126

RPMTAG_FILEMODES = 1030
RPMTAG_FILERDEVS = 1033
RPMTAG_FILELINKTOS = 1036
RPMTAG_DIRINDEXES = 1116
RPMTAG_BASENAMES = 1117
RPMTAG_DIRNAMES = 1118
RPMTAG_LONGFILESIZES = 5008


class RPMType(IntEnum):
    INT16 = 3
    INT32 = 4
    INT64 = 5
    STRING_ARRAY = 8
    I18NSTRING_ARRAY = 9


C_DEFINITIONS = """
        typedef struct rpm_lead {
            char   magic[4];        // ED AB EE DB
            uint8  major;
            uint8  minor;
            uint16 type;
            uint16 archnum;
            char   name[66];
            uint16 osnum;
            uint16 signature_type;
            char   reserved[16];
        } rpm_lead_t;

        // Shared layout for both the Signature header and the Main header.
        // The variable-length index entries (nindex * 16 bytes) and data
        // section (hsize bytes) follow immediately after this fixed part.
        typedef struct rpm_header {
            char   magic[3];        // 8E AD E8
            uint8  version;
            char   reserved[4];
            uint32 nindex;
            uint32 hsize;
        } rpm_header_t;

        typedef struct rpm_index_entry {
            uint32 tag;
            uint32 type;
            uint32 offset;          // offset into the header's data section
            uint32 count;
        } rpm_index_entry_t;

        typedef struct rpm_cstring {
            char value[];
        } rpm_cstring_t;
    """


class RPMParser:
    @dataclass(frozen=True)
    class HeaderSection:
        header: Any
        entries: dict[int, Any]
        offset: int
        data_offset: int
        size: int

        @property
        def end_offset(self) -> int:
            return self.offset + self.size

    def __init__(self, file: File, start_offset: int):
        self._file = file
        self._start_offset = start_offset
        self._struct_parser = StructParser(C_DEFINITIONS)

        self._lead: Any | None = None
        self._signature: RPMParser.HeaderSection | None = None
        self._main_header: RPMParser.HeaderSection | None = None
        self._package_size: int | None = None
        self.compressor: str = "none"

    def parse(self):
        self._file.seek(self._start_offset, io.SEEK_SET)
        self._lead = self._struct_parser.cparser_be.rpm_lead_t(self._file)

        if self._lead is None:
            raise InvalidInputFormat("RPM lead is missing or malformed")

        self._signature = self._read_header_section(
            offset=self._start_offset + len(self._lead),
            alignment=RPM_SIGNATURE_ALIGNMENT,
        )

        size_entry = self._signature.entries.get(
            RPMSIGTAG_LONGSIZE
        ) or self._signature.entries.get(RPMSIGTAG_SIZE)
        if not size_entry:
            raise InvalidInputFormat(
                "RPM signature header must contain a SIZE or LONGSIZE tag"
            )

        self._package_size = self._read_entry_integer(self._signature, size_entry)

        self._main_header = self._read_header_section(offset=self._signature.end_offset)

        compressor_entry = self._main_header.entries.get(RPMTAG_PAYLOADCOMPRESSOR)
        if compressor_entry:
            self.compressor = self._read_cstring_entry(
                self._main_header, compressor_entry
            )
        else:
            # if RPMTAG_PAYLOADCOMPRESSOR is absent on v3/v4 rpm file, the default compression is gzip
            # while w0.ufdio (none compression) packages omit the tag and set PAYLOADFLAGS = "0" instead.
            payload_flags_entry = self._main_header.entries.get(RPMTAG_PAYLOADFLAGS)
            payload_flags = (
                self._read_cstring_entry(self._main_header, payload_flags_entry)
                if payload_flags_entry
                else None
            )
            self.compressor = "none" if payload_flags == "0" else "gzip"

    def _read_header_section(self, offset: int, alignment: int = 1) -> HeaderSection:
        self._file.seek(offset, io.SEEK_SET)
        header = self._struct_parser.cparser_be.rpm_header_t(self._file)
        entries = {
            entry.tag: entry
            for entry in (
                self._struct_parser.cparser_be.rpm_index_entry_t(self._file)
                for _ in range(header.nindex)
            )
        }

        entry_table_size = (
            header.nindex * self._struct_parser.cparser_be.rpm_index_entry_t.size
        )
        data_size = round_up(header.hsize + entry_table_size, alignment)

        return self.HeaderSection(
            header=header,
            entries=entries,
            offset=offset,
            data_offset=offset + len(header) + entry_table_size,
            size=len(header) + data_size,
        )

    def _read_entry_integer(self, section: HeaderSection, entry: Any) -> int:
        self._file.seek(section.data_offset + entry.offset, io.SEEK_SET)
        if entry.tag == RPMSIGTAG_LONGSIZE:
            return convert_int64(self._file.read(8), Endian.BIG)
        return convert_int32(self._file.read(4), Endian.BIG)

    def _read_cstring_entry(self, section: HeaderSection, entry: Any) -> str:
        self._file.seek(section.data_offset + entry.offset, io.SEEK_SET)
        return self._struct_parser.cparser_be.rpm_cstring_t(self._file).value.decode(
            "ascii"
        )

    def _read_array_entry(self, section: HeaderSection, entry: Any) -> list:
        """Read a fixed-count array tag value, dispatching on the entry's type."""
        self._file.seek(section.data_offset + entry.offset, io.SEEK_SET)
        # this line avoid false pylance errors
        cparser: Any = self._struct_parser.cparser_be
        match entry.type:
            case RPMType.INT16:
                return list(cparser.uint16[entry.count](self._file))
            case RPMType.INT32:
                return list(cparser.uint32[entry.count](self._file))
            case RPMType.INT64:
                return list(cparser.uint64[entry.count](self._file))
            case RPMType.STRING_ARRAY | RPMType.I18NSTRING_ARRAY:
                return [
                    self._struct_parser.cparser_be.rpm_cstring_t(
                        self._file
                    ).value.decode("utf-8", errors="replace")
                    for _ in range(entry.count)
                ]
        raise InvalidInputFormat(f"Unsupported RPM tag type: {entry.type}")

    def build_stripped_entries(self) -> list[CPIOEntry]:
        """Reconstruct metadata per-file from the main header arrays."""
        if self._main_header is None:
            raise InvalidInputFormat("RPM main header has not been parsed")
        h = self._main_header
        file_names: list[str] = self._read_array_entry(h, h.entries[RPMTAG_BASENAMES])
        dirnames: list[str] = self._read_array_entry(h, h.entries[RPMTAG_DIRNAMES])
        dirindexes: list[int] = self._read_array_entry(h, h.entries[RPMTAG_DIRINDEXES])
        file_sizes: list[int] = self._read_array_entry(
            h, h.entries[RPMTAG_LONGFILESIZES]
        )
        modes: list[int] = self._read_array_entry(h, h.entries[RPMTAG_FILEMODES])
        links: list[str] = self._read_array_entry(h, h.entries[RPMTAG_FILELINKTOS])
        rdevs: list[int] = self._read_array_entry(h, h.entries[RPMTAG_FILERDEVS])
        self._file.seek(self.payload_offset, io.SEEK_SET)
        return [
            CPIOEntry(
                header=None,
                path=Path(dirnames[dirindexes[i]] + file_names[i]),
                size=file_sizes[i],
                mode=modes[i],
                rdev=rdevs[i],
                link=links[i],
            )
            for i in range(len(file_names))
        ]

    @property
    def payload_offset(self) -> int:
        if self._main_header is None:
            raise InvalidInputFormat("RPM main header has not been parsed")
        return self._main_header.end_offset

    @property
    def end_offset(self) -> int:
        if self._main_header is None or self._package_size is None:
            raise InvalidInputFormat("RPM package has not been parsed")
        return self._main_header.offset + self._package_size

    @property
    def has_stripped_payload(self) -> bool:
        """Stripped CPIO is used whenever LONGFILESIZES is needed (any file >4 GiB)."""
        if self._main_header is None:
            raise InvalidInputFormat("RPM main header has not been parsed")
        return RPMTAG_LONGFILESIZES in self._main_header.entries


class RPMExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            parser = RPMParser(file, 0)
            parser.parse()
            file.seek(parser.payload_offset, io.SEEK_SET)
            with RPMExtractor.open_payload_stream(file, parser.compressor) as decoder:
                if parser.has_stripped_payload:
                    StrippedCPIOParser(
                        decoder,  # pyright: ignore[reportArgumentType]
                        0,
                        parser.build_stripped_entries(),
                    ).parse(fs)
                else:
                    PortableASCIIParser(decoder, 0).parse(fs)  # pyright: ignore[reportArgumentType]
        return ExtractResult(reports=fs.problems)

    @staticmethod
    def open_payload_stream(file: File, compressor: str):
        """Return a forward-only decompressing reader over the RPM payload.

        The caller must have already positioned `file` at the payload start.
        """
        match compressor:
            case "gzip":
                return gzip.GzipFile(fileobj=file, mode="rb")
            case "bzip2":
                return bz2.BZ2File(file, mode="rb")  # pyright: ignore[reportArgumentType]
            case "xz" | "lzma":
                return lzma.LZMAFile(file, mode="rb")  # pyright: ignore[reportArgumentType]
            case "zstd":
                return pyzstd.ZstdFile(file, mode="rb")  # pyright: ignore[reportArgumentType]
            case "none":
                return file
        raise InvalidInputFormat(f"Unsupported RPM payload compressor: {compressor}")


class RPMHandler(StructHandler):
    NAME = "rpm"
    PATTERNS = [
        HexString(
            "ED AB EE DB (03 | 04) ?? 00 (00 | 01) ?? ?? [65] 00 ?? ?? 00 05"
        )  # RPM lead magic + major version (03 or 04) + minor version (?) + type (0x00 or 0x01) + name + signature type (0x5)
    ]
    EXTRACTOR = RPMExtractor()
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "rpm_header_t"

    DOC = HandlerDoc(
        name="RPM",
        description="RPM (Red Hat Package Manager) is a package archive format used by Red Hat-based Linux distributions. An RPM file contains metadata (signature, header) and a compressed cpio archive as payload.",
        handler_type=HandlerType.ARCHIVE,
        vendor="Red Hat",
        references=[
            Reference(
                title="RPM File Format",
                url="https://rpm-software-management.github.io/rpm/manual/format.html",
            ),
            Reference(
                title="RPM Package Manager",
                url="https://en.wikipedia.org/wiki/RPM_Package_Manager",
            ),
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        parser = RPMParser(file, start_offset)
        parser.parse()
        return ValidChunk(
            start_offset=start_offset,
            end_offset=parser.end_offset,
        )
