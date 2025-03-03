import io
import lzma
import zlib
from pathlib import Path
from typing import Optional

import pyzstd

from unblob.file_utils import (
    Endian,
    FileSystem,
    StructParser,
    iterate_file,
    read_until_past,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    File,
    Regex,
    StructHandler,
    ValidChunk,
)

C_DEFINITIONS = r"""
    typedef struct geom_header{
        char magic[16];             /* 16 bytes */
        char format[112];           /* 112 bytes */
        uint32_t block_size;
        uint32_t block_count;
        uint64_t toc[block_count];  /* table of content */
    } geom_header_t;
"""

HEADER_STRUCT = "geom_header_t"

VERSION_ZLIB = b"#!/bin/sh\x0a#V2.0\x20"
VERSION_LZMA = b"#!/bin/sh\x0a#L3.0\x0a"
VERSION_ZSTD = b"#!/bin/sh\x0a#Z4.0\x20"


class GEOMExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path):
        infile = File.from_path(inpath)
        parser = StructParser(C_DEFINITIONS)
        header = parser.parse(HEADER_STRUCT, infile, Endian.BIG)
        fs = FileSystem(outdir)
        outpath = Path(inpath.stem)
        with fs.open(outpath, "wb+") as outfile:
            for current_offset, next_offset in zip(header.toc[:-1], header.toc[1:]):
                compressed_len = next_offset - current_offset
                if compressed_len == 0:
                    continue
                if header.magic == VERSION_ZLIB:
                    decompressor = zlib.decompressobj()
                elif header.magic == VERSION_LZMA:
                    decompressor = lzma.LZMADecompressor()
                elif header.magic == VERSION_ZSTD:
                    decompressor = pyzstd.ZstdDecompressor()
                for chunk in iterate_file(infile, current_offset, compressed_len):
                    outfile.write(decompressor.decompress(chunk))
        return ExtractResult(reports=fs.problems)


class GEOMHandler(StructHandler):
    NAME = "geom"
    PATTERNS = [
        Regex(r"^#!/bin/sh\x0A#V2.0"),
        Regex(r"^#!/bin/sh\x0A#L3.0"),
        Regex(r"^#!/bin/sh\x0A#Z4.0"),
    ]

    HEADER_STRUCT = HEADER_STRUCT
    C_DEFINITIONS = C_DEFINITIONS
    EXTRACTOR = GEOMExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file, Endian.BIG)
        # take the last TOC block offset, end of file is that block offset + null byte padding (if present),
        # starting from the start offset
        if header.block_count > 0:
            end_offset = start_offset + header.toc[-1]
            file.seek(end_offset, io.SEEK_SET)
        # if file doesn't contain compressed blocks, goes directly to eof
        end_offset = read_until_past(file, b"\x00")
        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
