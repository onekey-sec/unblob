from pathlib import Path

from lz4.block import decompress

from unblob.file_utils import File, FileSystem, InvalidInputFormat, StructParser
from unblob.models import (
    Endian,
    Extractor,
    ExtractResult,
    HandlerDoc,
    HandlerType,
    Reference,
    Regex,
    StructHandler,
    ValidChunk,
)

C_DEFINITIONS = r"""
typedef struct xalz_header {
    uint32 magic;
    uint32 descriptor_index;
    uint32 uncompressed_size;
} xalz_header_t;
"""


class XALZExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("xalz_header_t", file, Endian.LITTLE)

            fs.write_bytes(
                Path(f"{inpath.name}.uncompressed"),
                decompress(file.read(), uncompressed_size=header.uncompressed_size),
            )
        return ExtractResult(reports=fs.problems)


class XALZHandler(StructHandler):
    NAME = "xalz"

    PATTERNS = [Regex("^\x58\x41\x4c\x5a")]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "xalz_header_t"
    EXTRACTOR = XALZExtractor()

    DOC = HandlerDoc(
        name="Xamarin Compressed assemblies",
        description="Xamarin compressed assemblies are Xamarin DLL compressed with LZ4 + a custom header.",
        handler_type=HandlerType.EXECUTABLE,
        vendor="Microsoft",
        references=[
            Reference(
                title="Reverse Engineering a Xamarin Application",
                url="https://web.archive.org/web/20250114215653/https://securitygrind.com/reverse-engineering-a-xamarin-application/",
            )
        ],
        limitations=[],
    )

    def is_valid_header(self, header) -> bool:
        return header.uncompressed_size > 0

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk:
        header = self.parse_header(file, endian=Endian.LITTLE)

        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid XALZ header")

        # NOTE: XALZ does not store compressed size and python's lz4 is too dumb
        # to allow us to find out where the lz4 raw compressed stream ends without
        # lots of rewriting.
        return ValidChunk(start_offset=start_offset, end_offset=file.size())
