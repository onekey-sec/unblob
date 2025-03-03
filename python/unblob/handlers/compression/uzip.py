import lzma
import zlib
from pathlib import Path
from typing import Optional

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

ZLIB_COMPRESSION = b"#!/bin/sh\x0a#V2.0\x20"
LZMA_COMPRESSION = b"#!/bin/sh\x0a#L3.0\x0a"
ZSTD_COMPRESSION = b"#!/bin/sh\x0a#Z4.0\x20"


class UZIPExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        infile = File.from_path(inpath)
        parser = StructParser(C_DEFINITIONS)
        header = parser.parse(HEADER_STRUCT, infile, Endian.BIG)
        fs = FileSystem(outdir)
        outpath = Path(inpath.stem)

        if header.magic == ZLIB_COMPRESSION:
            decompressor_cls = zlib.decompressobj
        elif header.magic == LZMA_COMPRESSION:
            decompressor_cls = lzma.LZMADecompressor
        elif header.magic == ZSTD_COMPRESSION:
            decompressor_cls = pyzstd.ZstdDecompressor
        else:
            raise InvalidInputFormat("unsupported compression format")

        with fs.open(outpath, "wb+") as outfile:
            for current_offset, next_offset in zip(header.toc[:-1], header.toc[1:]):
                compressed_len = next_offset - current_offset
                if compressed_len == 0:
                    continue
                decompressor = decompressor_cls()
                for chunk in iterate_file(infile, current_offset, compressed_len):
                    outfile.write(decompressor.decompress(chunk))
        return ExtractResult(reports=fs.problems)


class UZIPHandler(StructHandler):
    NAME = "uzip"
    PATTERNS = [
        Regex(r"#!/bin/sh\x0A#V2.0"),
        Regex(r"#!/bin/sh\x0A#L3.0"),
        Regex(r"#!/bin/sh\x0A#Z4.0"),
    ]
    HEADER_STRUCT = HEADER_STRUCT
    C_DEFINITIONS = C_DEFINITIONS
    EXTRACTOR = UZIPExtractor()

    def is_valid_header(self, header) -> bool:
        return (
            header.block_count > 0
            and header.block_size > 0
            and (header.block_size & (header.block_size - 1)) == 0
        )

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
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
