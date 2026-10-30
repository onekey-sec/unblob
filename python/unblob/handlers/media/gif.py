import io

from structlog import get_logger

from unblob.file_utils import Endian, File, InvalidInputFormat, convert_int8
from unblob.models import (
    HandlerDoc,
    HandlerType,
    Reference,
    Regex,
    StructHandler,
    ValidChunk,
)

logger = get_logger()

C_DEFINITIONS = r"""
    typedef struct gif_header {
        char signature[6];
        uint16 width;
        uint16 height;
        uint8 flags;
        uint8 background_color_index;
        uint8 pixel_aspect_ratio;
    } gif_header_t;

    typedef struct gif_image_descriptor {
        uint16 left;
        uint16 top;
        uint16 width;
        uint16 height;
        uint8 flags;
    } gif_image_descriptor_t;
"""

EXTENSION_INTRODUCER = 0x21
IMAGE_SEPARATOR = 0x2C
TRAILER = 0x3B

COLOR_TABLE_FLAG = 0x80
COLOR_TABLE_SIZE_MASK = 0x07

# LZW minimum code size of the image data. The spec (appendix F) uses 2-8, but
# decoders accept anything below the 12-bit maximum code width, and so do encoders.
MIN_LZW_CODE_SIZE = 2
MAX_LZW_CODE_SIZE = 11


def color_table_size(flags: int) -> int:
    if not flags & COLOR_TABLE_FLAG:
        return 0
    return 3 * 2 ** ((flags & COLOR_TABLE_SIZE_MASK) + 1)


class GIFHandler(StructHandler):
    NAME = "gif"

    # signature, then width and height, neither of them 0
    PATTERNS = [Regex(r"GIF8[79]a([^\x00].|\x00[^\x00]){2}")]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "gif_header_t"

    EXTRACTOR = None

    DOC = HandlerDoc(
        name="GIF",
        description="The Graphics Interchange Format (GIF) is an indexed-colour image format made of blocks and data sub-blocks, ending with a trailer byte. unblob carves GIF images embedded in other data, such as web UI assets in RTOS firmware; standalone GIF files are skipped based on their file type.",
        handler_type=HandlerType.MEDIA,
        vendor=None,
        references=[
            Reference(
                title="GIF89a Specification",
                url="https://www.w3.org/Graphics/GIF/spec-gif89a.txt",
            ),
            Reference(
                title="GIF Wikipedia",
                url="https://en.wikipedia.org/wiki/GIF",
            ),
        ],
        limitations=[],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, Endian.LITTLE)
        file.seek(color_table_size(header.flags), io.SEEK_CUR)

        image_count = 0
        while (block_type := convert_int8(file.read(1), Endian.LITTLE)) != TRAILER:
            if block_type == EXTENSION_INTRODUCER:
                file.seek(1, io.SEEK_CUR)  # extension label
                self._skip_sub_blocks(file)
            elif block_type == IMAGE_SEPARATOR:
                self._skip_image(file)
                image_count += 1
            else:
                raise InvalidInputFormat(f"Invalid GIF block type 0x{block_type:02x}")

        if not image_count:
            raise InvalidInputFormat("GIF without image")

        return ValidChunk(start_offset=start_offset, end_offset=file.tell())

    def _skip_image(self, file: File):
        descriptor = self._struct_parser.parse(
            "gif_image_descriptor_t", file, Endian.LITTLE
        )
        file.seek(color_table_size(descriptor.flags), io.SEEK_CUR)

        lzw_code_size = convert_int8(file.read(1), Endian.LITTLE)
        if not MIN_LZW_CODE_SIZE <= lzw_code_size <= MAX_LZW_CODE_SIZE:
            raise InvalidInputFormat("Invalid GIF LZW minimum code size")
        self._skip_sub_blocks(file)

    @staticmethod
    def _skip_sub_blocks(file: File):
        # image data is split into sub-blocks of at most 255 bytes: index the mmap
        # directly, which is several times faster than a read and a seek per block
        pos = file.tell()
        try:
            while block_size := file[pos]:
                pos += block_size + 1
        except IndexError:
            raise InvalidInputFormat("GIF is truncated") from None
        file.seek(pos + 1, io.SEEK_SET)
