import lzma
from collections.abc import Iterator
from pathlib import Path

from unblob.file_utils import Endian, File, FileSystem, InvalidInputFormat, StructParser
from unblob.models import (
    Extractor,
    ExtractResult,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

C_DEFINITIONS = r"""
    typedef struct qca_lzma_header {
        uint16 literal_context_bits;    /* only 0x0003 observed */
        uint16 position_bits;           /* only 0x0002 observed */
        uint32 dict_size;               /* only 0x00001000 observed */
        uint32 compressed_size;
        uint32 decompressed_size;
    } qca_lzma_header_t;
"""


class QcaLzmaExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            header = self._struct_parser.parse("qca_lzma_header_t", file, Endian.LITTLE)
            fs.write_chunks(
                Path(f"{inpath.stem}.uncompressed"), _decompress(file, header)
            )
        return ExtractResult(reports=fs.problems)


def _decompress(file: File, header, chunk_size: int = 1_024) -> Iterator[bytes]:
    decompressor = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=[
            {
                "id": lzma.FILTER_LZMA1,
                "lc": header.literal_context_bits,
                "lp": 0,
                "pb": header.position_bits,
                "dict_size": header.dict_size,
            }
        ],
    )
    bytes_read = 0

    while not decompressor.eof and bytes_read < header.compressed_size:
        chunk = file.read(min(chunk_size, header.compressed_size - bytes_read))
        if not chunk:
            break
        bytes_read += len(chunk)
        yield decompressor.decompress(chunk)


class QcaLzmaHandler(StructHandler):
    NAME = "qca_lzma"
    PATTERNS = [HexString("00 00 00 00 ?? ?? ?? ?? 03 00 02 00 00 10 00 00")]

    DOC = HandlerDoc(
        name="QCA LZMA",
        description=(
            "Compressed LZMA streams with custom header format found in "
            "powerline firmware images using Qualcomm Atheros (QCA) chips "
            "of various vendors (TP-Link, Netgear, Trendnet, etc.). The "
            "images use the NVM format and contain the compressed firmware "
            "executable."
        ),
        handler_type=HandlerType.COMPRESSION,
        vendor="Qualcomm Atheros",
        references=[
            Reference(
                title="open-plc-utils",
                url="https://github.com/qca/open-plc-utils",
            ),
        ],
        limitations=[],
    )

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "qca_lzma_header_t"
    EXTRACTOR = QcaLzmaExtractor()
    PATTERN_MATCH_OFFSET = 8

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, Endian.LITTLE)
        end_offset = start_offset + header.size + header.compressed_size
        self._validate_header(header)
        try:
            for _ in _decompress(file, header):
                pass
        except lzma.LZMAError as exc:
            raise InvalidInputFormat("LZMA Decompression failed") from exc

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)

    @staticmethod
    def _validate_header(header) -> None:
        if header.compressed_size == 0:
            raise InvalidInputFormat(
                f"Invalid compressed size {header.compressed_size}"
            )
        if (
            header.decompressed_size == 0
            or header.decompressed_size < header.compressed_size
        ):
            raise InvalidInputFormat(
                f"Invalid decompressed size {header.decompressed_size}"
            )
