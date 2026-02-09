import lzma
import re
import zlib
from collections.abc import Callable
from pathlib import Path

import pyzstd

from unblob.file_utils import (
    Endian,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    iterate_file,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    File,
    HandlerDoc,
    HandlerType,
    Reference,
    Regex,
    StructHandler,
    ValidChunk,
)

# [Ref] https://github.com/freebsd/freebsd-src/tree/master/sys/geom/uzip
C_DEFINITIONS = r"""
    typedef struct uzip_header{
        char magic[16];
        char format[112];
        uint32_t block_size;
        uint32_t block_count;
        uint64_t toc[block_count];
    } uzip_header_t;
"""

HEADER_STRUCT = "uzip_header_t"

ZLIB_COMPRESSION = "#!/bin/sh\x0a#V2.0\x20"
LZMA_COMPRESSION = "#!/bin/sh\x0a#L3.0\x0a"
ZSTD_COMPRESSION = "#!/bin/sh\x0a#Z4.0\x20"


class Decompressor:
    DECOMPRESSOR: Callable

    def __init__(self):
        self._decompressor = self.DECOMPRESSOR()

    def decompress(self, data: bytes) -> bytes:
        return self._decompressor.decompress(data)

    def flush(self) -> bytes:
        return b""


class LZMADecompressor(Decompressor):
    DECOMPRESSOR = lzma.LZMADecompressor


class ZLIBDecompressor(Decompressor):
    DECOMPRESSOR = zlib.decompressobj

    def flush(self) -> bytes:
        return self._decompressor.flush()


class ZSTDDecompressor(Decompressor):
    DECOMPRESSOR = pyzstd.EndlessZstdDecompressor


DECOMPRESS_METHOD: dict[bytes, type[Decompressor]] = {
    ZLIB_COMPRESSION.encode(): ZLIBDecompressor,
    LZMA_COMPRESSION.encode(): LZMADecompressor,
    ZSTD_COMPRESSION.encode(): ZSTDDecompressor,
}


class UZIPExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        with File.from_path(inpath) as infile:
            parser = StructParser(C_DEFINITIONS)
            header = parser.parse(HEADER_STRUCT, infile, Endian.BIG)
            fs = FileSystem(outdir)
            outpath = Path(inpath.stem)

            try:
                decompressor_cls = DECOMPRESS_METHOD[header.magic]
            except LookupError:
                raise InvalidInputFormat("unsupported compression format") from None

            with fs.open(outpath, "wb+") as outfile:
                for current_offset, next_offset in zip(header.toc[:-1], header.toc[1:]):
                    compressed_len = next_offset - current_offset
                    if compressed_len == 0:
                        continue
                    decompressor = decompressor_cls()
                    for chunk in iterate_file(infile, current_offset, compressed_len):
                        outfile.write(decompressor.decompress(chunk))
                    outfile.write(decompressor.flush())
            return ExtractResult(reports=fs.problems)


class UZIPHandler(StructHandler):
    NAME = "uzip"
    PATTERNS = [
        Regex(re.escape(ZLIB_COMPRESSION)),
        Regex(re.escape(LZMA_COMPRESSION)),
        Regex(re.escape(ZSTD_COMPRESSION)),
    ]
    HEADER_STRUCT = HEADER_STRUCT
    C_DEFINITIONS = C_DEFINITIONS
    EXTRACTOR = UZIPExtractor()

    DOC = HandlerDoc(
        name="UZIP",
        description="FreeBSD UZIP is a block-based compressed disk image format. It uses a table of contents to index compressed blocks, supporting ZLIB, LZMA, and ZSTD compression algorithms.",
        handler_type=HandlerType.COMPRESSION,
        vendor="FreeBSD",
        references=[
            Reference(
                title="FreeBSD UZIP Documentation",
                url="https://github.com/freebsd/freebsd-src/tree/master/sys/geom/uzip",
            ),
        ],
        limitations=[],
    )

    def is_valid_header(self, header) -> bool:
        return (
            header.block_count > 0
            and header.block_size > 0
            and header.block_size % 512 == 0
        )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, Endian.BIG)

        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid uzip header.")

        # take the last TOC block offset, end of file is that block offset,
        # starting from the start offset
        end_offset = start_offset + header.toc[-1]
        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
