import io
from enum import Enum
from pathlib import Path

import lzfse

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
)
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


class LZFSEMagic(bytes, Enum):
    END = b"bvx$"  # end-of-stream block
    UNCOMPRESSED = b"bvx-"  # raw block
    LZVN = b"bvxn"  # LZVN-compressed block
    LZFSE_V1 = b"bvx1"  # LZFSE v1 block (legacy)
    LZFSE_V2 = b"bvx2"  # LZFSE v2 block


# sizeof(lzfse_compressed_block_header_v1), including struct alignment padding
_V1_HEADER_SIZE = 772

# length of every LZFSE block magic
MAGIC_LEN = 4

C_DEFINITIONS = r"""
    typedef struct lzfse_uncompressed {
        char   magic[4];
        uint32 n_raw_bytes;
    } lzfse_uncompressed_t;

    typedef struct lzvn_compressed {
        char   magic[4];
        uint32 n_raw_bytes;
        uint32 n_payload_bytes;
    } lzvn_compressed_t;

    typedef struct lzfse_v1 {
        char   magic[4];
        uint32 n_raw_bytes;
        uint32 n_payload_bytes;
        uint32 n_literals;
        uint32 n_matches;
        uint32 n_literal_payload_bytes;
        uint32 n_lmd_payload_bytes;
    } lzfse_v1_t;

    typedef struct lzfse_v2 {
        char   magic[4];
        uint32 n_raw_bytes;
        uint64 packed_fields_0;
        uint64 packed_fields_1;
        uint64 packed_fields_2;
    } lzfse_v2_t;
"""

_parser = StructParser(C_DEFINITIONS)


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
        HexString("62 76 78 31"),  # "bvx1" LZFSE v1 compressed block (legacy)
        HexString("62 76 78 6E"),  # "bvxn" LZVN compressed block
        HexString("62 76 78 32"),  # "bvx2" LZFSE v2 compressed block
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
        # An LZFSE stream is a sequence of blocks terminated by an end-of-stream
        # block. Walk the blocks using each header's declared size instead of
        # scanning for "bvx$", which could otherwise be matched inside payload data.
        offset = start_offset
        magic = file[offset : offset + MAGIC_LEN]
        while magic != LZFSEMagic.END:
            if len(magic) < MAGIC_LEN:
                raise InvalidInputFormat("Truncated LZFSE stream: no end block")
            block_size = self._block_size(file, offset, magic)
            if block_size <= 0:
                raise InvalidInputFormat("Invalid LZFSE block size")
            offset += block_size
            magic = file[offset : offset + MAGIC_LEN]

        return ValidChunk(start_offset=start_offset, end_offset=offset + MAGIC_LEN)

    @staticmethod
    def _block_size(file: File, offset: int, magic: bytes) -> int:
        """Size in bytes of the LZFSE block at offset, including its header."""
        file.seek(offset, io.SEEK_SET)
        match magic:
            case LZFSEMagic.UNCOMPRESSED:
                header = _parser.parse("lzfse_uncompressed_t", file, Endian.LITTLE)
                size = 8 + header.n_raw_bytes
            case LZFSEMagic.LZVN:
                header = _parser.parse("lzvn_compressed_t", file, Endian.LITTLE)
                size = 12 + header.n_payload_bytes
            case LZFSEMagic.LZFSE_V1:
                header = _parser.parse("lzfse_v1_t", file, Endian.LITTLE)
                size = (
                    _V1_HEADER_SIZE
                    + header.n_literal_payload_bytes
                    + header.n_lmd_payload_bytes
                )
            case LZFSEMagic.LZFSE_V2:
                header = _parser.parse("lzfse_v2_t", file, Endian.LITTLE)
                # v2 packs the sizes into bit-fields across three uint64s.
                n_literal = (header.packed_fields_0 >> 20) & 0xFFFFF
                n_lmd = (header.packed_fields_1 >> 40) & 0xFFFFF
                header_size = header.packed_fields_2 & 0xFFFFFFFF
                size = header_size + n_literal + n_lmd
            case _:
                raise InvalidInputFormat(f"Unknown LZFSE block magic: {magic!r}")
        return size
