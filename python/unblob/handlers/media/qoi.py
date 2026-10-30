from structlog import get_logger

from unblob.file_utils import Endian, File, InvalidInputFormat
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
    typedef struct qoi_header {
        char magic[4];
        uint32 width;
        uint32 height;
        uint8 channels;
        uint8 colorspace;
    } qoi_header_t;
"""

END_MARKER = b"\x00" * 7 + b"\x01"

# Bounds the pure Python walk below (one iteration per op, at most one op per pixel).
# Embedded display assets are far smaller.
MAX_PIXELS = 4096 * 4096

OP_RGB = 0xFE
OP_RGBA = 0xFF
OP_TAG_MASK = 0xC0
OP_LUMA = 0x80
OP_RUN = 0xC0
RUN_LENGTH_MASK = 0x3F


def _op_size(op: int) -> int:
    if op == OP_RGB:
        return 4
    if op == OP_RGBA:
        return 5
    if op & OP_TAG_MASK == OP_LUMA:
        return 2
    return 1  # INDEX, DIFF, RUN


def _op_pixels(op: int) -> int:
    if op & OP_TAG_MASK == OP_RUN and op not in (OP_RGB, OP_RGBA):
        return (op & RUN_LENGTH_MASK) + 1
    return 1


# lookup tables indexed by the first byte of an op
OP_SIZES = [_op_size(op) for op in range(256)]
OP_PIXELS = [_op_pixels(op) for op in range(256)]


class QOIHandler(StructHandler):
    NAME = "qoi"

    # qoif, width, height, channels 3 (RGB) or 4 (RGBA), colorspace 0 (sRGB) or 1 (linear)
    PATTERNS = [HexString("71 6f 69 66 [8] (03 | 04) (00 | 01)")]

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "qoi_header_t"

    EXTRACTOR = None

    DOC = HandlerDoc(
        name="QOI",
        description="The Quite OK Image format (QOI) is a simple lossless image format used by embedded GUIs. It has no length field: the end is found by walking the op stream until every pixel is covered, followed by an end marker. unblob carves QOI images embedded in other data, such as GUI assets in RTOS firmware. Standalone QOI files are not skipped by file type, as firmware stores QOI assets back to back in one file that file type detection reports as a single QOI image; an image spanning the whole file is not carved instead.",
        handler_type=HandlerType.MEDIA,
        vendor=None,
        references=[
            Reference(
                title="QOI Specification",
                url="https://qoiformat.org/qoi-specification.pdf",
            ),
            Reference(
                title="QOI Wikipedia",
                url="https://en.wikipedia.org/wiki/QOI_(image_format)",
            ),
        ],
        limitations=[
            f"Images with more than {MAX_PIXELS} pixels are not recognised.",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, Endian.BIG)
        pixels = header.width * header.height
        if not 0 < pixels <= MAX_PIXELS:
            raise InvalidInputFormat("Invalid or too large QOI dimensions")

        # index the mmap directly: reading ahead would have to copy the worst case
        # (5 bytes per pixel), while the ops of a typical image are much smaller
        position = file.tell()
        covered = 0
        try:
            while covered < pixels:
                op = file[position]
                position += OP_SIZES[op]
                covered += OP_PIXELS[op]
        except IndexError:
            raise InvalidInputFormat("QOI data is truncated") from None

        if covered != pixels:
            raise InvalidInputFormat("QOI ops cover more pixels than the image has")
        if file[position : position + len(END_MARKER)] != END_MARKER:
            raise InvalidInputFormat("Missing QOI end marker")

        end_offset = position + len(END_MARKER)
        # not skipped by file magic (see DOC), so standalone files are left alone here
        if start_offset == 0 and end_offset == file.size():
            raise InvalidInputFormat("Standalone QOI file, not embedded")

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
