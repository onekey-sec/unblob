import io
from pathlib import Path

from lzallright import LZOCompressor

from unblob.file_utils import (
    Endian,
    FileSystem,
    InvalidInputFormat,
    StructParser,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

QNX_C_DEFINITION = """
    struct filehdr {
        char     signature[8];
        int32    usize;     // Uncompressed size of the file
        uint16   blksize;   // Size of compression blocks
        uint8    cmptype;   // Type of compression (CMP_LZO, ...)
        uint8    flags;
    } filehdr_t;

    struct cmphdr {
        uint16   prev;      // Offset to previous hdr
        uint16   next;      // Offset to next hdr
        uint16   pusize;    // Size of prev uncompressed blk
        uint16   usize;     // Size of this uncompressed blk
    } cmphdr_t;

    struct cmpblk {
	struct cmphdr	hdr;
	uint8_t			buf[32*1024];
    } cmpblk_t;
"""
SUPPORTED_BLOCK_SIZES = [2**i for i in range(12, 16)]


class QNXDeflateExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(QNX_C_DEFINITION)

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            # skip filehdr to reach the first cmphdr
            file.seek(16, io.SEEK_CUR)
            lzo_decompressor = LZOCompressor()

            with fs.open(Path(f"{inpath.stem}.uncompressed")) as outfile:
                cmphdr = self._struct_parser.cparser_le.cmphdr_t(file)
                while cmphdr.next != 0:
                    compressed_part = file.read(cmphdr.next - 8)
                    outfile.write(
                        lzo_decompressor.decompress(compressed_part, cmphdr.usize)
                    )
                    cmphdr = self._struct_parser.cparser_le.cmphdr_t(file)
            return ExtractResult(reports=fs.problems)


class QNXDeflateHandler(StructHandler):
    NAME = "qnx_deflate"
    C_DEFINITIONS = QNX_C_DEFINITION
    HEADER_STRUCT = "filehdr_t"
    PATTERNS = [
        HexString("69 77 6c 79 66 6d 62 70 [6] 00")  # iwlyfmbp
    ]
    EXTRACTOR = QNXDeflateExtractor()
    DOC = HandlerDoc(
        name="QNX Deflate",
        description="QNX deflate are compressed files using a block-based compression format with either LZO or UCL algorithm.",
        handler_type=HandlerType.COMPRESSION,
        vendor="Blackberry",
        references=[
            Reference(title="QNX wikipedia", url="https://en.wikipedia.org/wiki/QNX"),
        ],
        limitations=["UCL compression mode is not supported"],
    )

    def is_valid_header(self, header) -> bool:
        return header.usize > 0 and header.blksize in SUPPORTED_BLOCK_SIZES

    def calculate_chunk(self, file, start_offset) -> ValidChunk:
        header = self.parse_header(file, Endian.LITTLE)
        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid QNX header")

        cmphdr = self.cparser_le.cmphdr_t(file)
        while cmphdr.next != 0:
            # return from 8 bytes because it parse the cmpheader
            file.seek(cmphdr.next - 8, io.SEEK_CUR)
            cmphdr = self.cparser_le.cmphdr_t(file)
        end_offset = file.tell()

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
