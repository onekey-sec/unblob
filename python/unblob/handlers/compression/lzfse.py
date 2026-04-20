from pathlib import Path

import lzfse

from unblob.file_utils import File, FileSystem, InvalidInputFormat, iterate_patterns
from unblob.models import (
    Extractor,
    ExtractResult,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    ValidChunk,
)

# LZFSE block magic values
_MAGIC_BVX_MINUS = b"bvx-"  # uncompressed block
_MAGIC_BVX1 = b"bvx1"  # LZVN compressed block
_MAGIC_BVXN = b"bvxn"  # uncompressed block (newer)
_MAGIC_BVX2 = b"bvx2"  # LZFSE compressed block
_MAGIC_BCOMP = b"bcomp"  # LZFSE2 / LZBITMAP block (5-byte magic)

# End-of-stream marker common to all LZFSE streams
_MAGIC_BVX_END = b"bvx$"


class LZFSEExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult | None:
        fs = FileSystem(outdir)

        with File.from_path(inpath) as file:
            decompressed = lzfse.decompress(file.read())

        fs.write_bytes(Path(f"{inpath.stem}.bin"), decompressed)

        return ExtractResult(reports=fs.problems)


class LZFSEHandler(Handler):
    NAME = "lzfse"

    PATTERNS = [
        HexString("62 76 78 2D"),  # "bvx-" uncompressed block
        HexString("62 76 78 31"),  # "bvx1" LZVN compressed block
        HexString("62 76 78 6E"),  # "bvxn" uncompressed block (newer)
        HexString("62 76 78 32"),  # "bvx2" LZFSE compressed block
        HexString("62 63 6F 6D 70"),  # "bcomp" LZFSE2 / LZBITMAP block
    ]

    EXTRACTOR = LZFSEExtractor()

    DOC = HandlerDoc(
        name="LZFSE",
        description="LZFSE is a lossless compression algorithm developed by Apple and open-sourced in 2016. It combines Lempel-Ziv back-references with Finite State Entropy coding and is the default compression format used in iOS and macOS firmware images.",
        handler_type=HandlerType.COMPRESSION,
        vendor="Apple",
        references=[
            Reference(
                title="lzfse - Apple open-source LZFSE library",
                url="https://github.com/lzfse/lzfse",
            ),
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        for pos in iterate_patterns(file, _MAGIC_BVX_END):
            return ValidChunk(start_offset=start_offset, end_offset=pos + len(_MAGIC_BVX_END))
        raise InvalidInputFormat("LZFSE end-of-stream marker not found")
