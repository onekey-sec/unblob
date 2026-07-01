from pathlib import Path

import lzfse

from unblob.file_utils import File, FileSystem, InvalidInputFormat
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

_MAGIC_END = b"bvx$"  # end-of-stream block (magic only, 4 bytes)
_MAGIC_UNCOMPRESSED = b"bvx-"  # header: magic + n_raw_bytes; payload = n_raw_bytes
_MAGIC_LZVN = b"bvxn"  # header: magic + n_raw_bytes + n_payload_bytes
_MAGIC_LZFSE_V1 = b"bvx1"  # fixed 772-byte header + literal & lmd payloads
_MAGIC_LZFSE_V2 = b"bvx2"  # variable header (header_size) + literal & lmd payloads

# sizeof(lzfse_compressed_block_header_v1), including struct alignment padding
_V1_HEADER_SIZE = 772


def _read_int(file: File, offset: int, size: int) -> int:
    file.seek(offset)
    data = file.read(size)
    if len(data) < size:
        raise InvalidInputFormat("Truncated LZFSE block header")
    return int.from_bytes(data, "little")


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
        # block. Walk the blocks using each header's size instead of scanning for
        # the "bvx$" marker, which could otherwise be matched inside payload data.
        offset = start_offset
        while True:
            magic = file[offset : offset + 4]
            if len(magic) < 4:
                raise InvalidInputFormat("Truncated LZFSE stream: no end block")
            if magic == _MAGIC_END:
                return ValidChunk(
                    start_offset=start_offset, end_offset=offset + len(_MAGIC_END)
                )
            block_size = self._block_size(file, offset, magic)
            if block_size <= 0:
                raise InvalidInputFormat("Invalid LZFSE block size")
            offset += block_size

    @staticmethod
    def _block_size(file: File, offset: int, magic: bytes) -> int:
        """Size in bytes of the LZFSE block at offset, including its header."""
        if magic == _MAGIC_UNCOMPRESSED:
            return 8 + _read_int(file, offset + 4, 4)  # + n_raw_bytes
        if magic == _MAGIC_LZVN:
            return 12 + _read_int(file, offset + 8, 4)  # + n_payload_bytes
        if magic == _MAGIC_LZFSE_V1:
            n_literal = _read_int(file, offset + 20, 4)  # n_literal_payload_bytes
            n_lmd = _read_int(file, offset + 24, 4)  # n_lmd_payload_bytes
            return _V1_HEADER_SIZE + n_literal + n_lmd
        if magic == _MAGIC_LZFSE_V2:
            # magic(4) + n_raw_bytes(4) + packed_fields[3] (3 x little-endian uint64)
            packed0 = _read_int(file, offset + 8, 8)
            packed1 = _read_int(file, offset + 16, 8)
            packed2 = _read_int(file, offset + 24, 8)
            n_literal = (packed0 >> 20) & 0xFFFFF  # bits 20..39
            n_lmd = (packed1 >> 40) & 0xFFFFF  # bits 40..59
            header_size = packed2 & 0xFFFFFFFF  # bits 0..31
            return header_size + n_literal + n_lmd
        raise InvalidInputFormat(f"Unknown LZFSE block magic: {magic!r}")
