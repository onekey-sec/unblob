import io
import zlib

from structlog import get_logger

from unblob.file_utils import (
    Endian,
    File,
    InvalidInputFormat,
    convert_int32,
    iterate_file,
)
from unblob.models import (
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct png_header {
        char signature[8];
        uint32 ihdr_length;
        char ihdr_type[4];
        uint32 width;
        uint32 height;
        uint8 bit_depth;
        uint8 color_type;
        uint8 compression_method;
        uint8 filter_method;
        uint8 interlace_method;
    } png_header_t;

    typedef struct png_chunk_header {
        uint32 length;
        char type[4];
    } png_chunk_header_t;
"""

SIGNATURE_SIZE = 8
MAX_VALUE = 2**31 - 1  # chunk lengths, width and height (PNG spec 5.3, 11.2.2)

# allowed bit depths per colour type (PNG spec 11.2.2)
BIT_DEPTHS = {
    0: {1, 2, 4, 8, 16},  # greyscale
    2: {8, 16},  # truecolour
    3: {1, 2, 4, 8},  # indexed
    4: {8, 16},  # greyscale with alpha
    6: {8, 16},  # truecolour with alpha
}


class PNGHandler(StructHandler):
    NAME = "png"

    PATTERNS = [
        # signature, IHDR length (13) and type, width, height, bit depth and colour
        # type, compression method 0, filter method 0, interlace method 0 or 1
        HexString(
            "89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 [10] 00 00 (00 | 01)"
        )
    ]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "png_header_t"

    EXTRACTOR = None

    DOC = HandlerDoc(
        name="PNG",
        description="Portable Network Graphics (PNG) is a lossless raster image format made of CRC-protected chunks. unblob carves PNG images embedded in other data, such as web UI assets in RTOS firmware; standalone PNG files are skipped based on their file type.",
        handler_type=HandlerType.MEDIA,
        vendor=None,
        references=[
            Reference(
                title="PNG Specification (Third Edition)",
                url="https://www.w3.org/TR/png-3/",
            ),
            Reference(
                title="PNG Wikipedia",
                url="https://en.wikipedia.org/wiki/PNG",
            ),
        ],
        limitations=[
            "Apple's CgBI variant of PNG, used in iOS app bundles, is not recognised.",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, Endian.BIG)
        self._check_header(header)

        # the walk below checks the CRC of IHDR too
        file.seek(start_offset + SIGNATURE_SIZE, io.SEEK_SET)

        has_image_data = False
        while True:
            chunk_type = self._verify_chunk(file)
            if chunk_type == b"IDAT":
                has_image_data = True
            elif chunk_type == b"IEND":
                break

        if not has_image_data:
            raise InvalidInputFormat("PNG without IDAT chunk")

        return ValidChunk(start_offset=start_offset, end_offset=file.tell())

    @staticmethod
    def _check_header(header):
        if not (0 < header.width <= MAX_VALUE and 0 < header.height <= MAX_VALUE):
            raise InvalidInputFormat("Invalid PNG dimensions")
        if header.bit_depth not in BIT_DEPTHS.get(header.color_type, ()):
            raise InvalidInputFormat("Invalid PNG bit depth / colour type")

    def _verify_chunk(self, file: File) -> bytes:
        """Verify the CRC of one chunk, move past it and return its type."""
        chunk_header = self._struct_parser.parse("png_chunk_header_t", file, Endian.BIG)
        if chunk_header.length > MAX_VALUE or not chunk_header.type.isalpha():
            raise InvalidInputFormat("Invalid PNG chunk header")

        crc = zlib.crc32(chunk_header.type)
        for data in iterate_file(file, file.tell(), chunk_header.length):
            crc = zlib.crc32(data, crc)
        # on truncated data the CRC read comes up short and fails
        if convert_int32(file.read(4), Endian.BIG) != crc:
            raise InvalidInputFormat("PNG chunk CRC mismatch")

        return chunk_header.type
