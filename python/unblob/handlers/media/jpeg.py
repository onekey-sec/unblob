import io
import re

from structlog import get_logger

from unblob.file_utils import (
    Endian,
    File,
    InvalidInputFormat,
    convert_int8,
    convert_int16,
)
from unblob.models import (
    Handler,
    HandlerDoc,
    HandlerType,
    Reference,
    Regex,
    ValidChunk,
)

logger = get_logger()

MARKER_PREFIX = 0xFF
SOI = 0xD8
EOI = 0xD9
SOS = 0xDA

# markers without a length field: TEM and RST0-RST7 (SOI and EOI are handled apart)
STANDALONE_MARKERS = {0x01, *range(0xD0, 0xD8)}

# start of frame markers, excluding DHT (0xC4), JPG (0xC8) and DAC (0xCC)
SOF_MARKERS = {*range(0xC0, 0xD0)} - {0xC4, 0xC8, 0xCC}

# 0x02-0xBF are reserved and never appear in a valid stream
FIRST_VALID_MARKER = 0xC0

# entropy-coded data ends at the first 0xFF that is neither byte stuffing
# (0xFF 0x00) nor a restart marker (0xFF 0xD0-0xD7)
ENTROPY_CODED_DATA_END = re.compile(rb"\xff[^\x00\xd0-\xd7]")


class JPEGHandler(Handler):
    NAME = "jpeg"

    # SOI followed by the first real marker (APPn, DQT, DHT, SOFn, COM, ...)
    PATTERNS = [Regex(r"\xff\xd8\xff[\xc0-\xfe]")]

    EXTRACTOR = None

    DOC = HandlerDoc(
        name="JPEG",
        description="JPEG is a lossy image format made of marker segments and entropy-coded scan data, ending with an end-of-image marker. unblob carves JPEG images embedded in other data, such as web UI assets in RTOS firmware; standalone JPEG files are skipped based on their file type.",
        handler_type=HandlerType.MEDIA,
        vendor=None,
        references=[
            Reference(
                title="ITU-T T.81 (JPEG) Specification",
                url="https://www.w3.org/Graphics/JPEG/itu-t81.pdf",
            ),
            Reference(
                title="JPEG Wikipedia",
                url="https://en.wikipedia.org/wiki/JPEG",
            ),
        ],
        limitations=[
            "Only complete images are carved: a frame header, at least one scan and an end-of-image marker are required.",
            "JPEG-LS and JPEG 2000 are not recognised.",
        ],
    )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        if self._read_marker(file) != SOI:
            raise InvalidInputFormat("JPEG does not start with SOI")

        markers = []
        while (marker := self._read_marker(file)) != EOI:
            self._skip_segment(file, marker)
            markers.append(marker)

        if SOS not in markers:
            raise InvalidInputFormat("JPEG without image data")
        if not SOF_MARKERS.intersection(markers[: markers.index(SOS)]):
            raise InvalidInputFormat("JPEG scan before frame header")

        return ValidChunk(start_offset=start_offset, end_offset=file.tell())

    def _skip_segment(self, file: File, marker: int):
        if marker in STANDALONE_MARKERS:
            return
        if marker < FIRST_VALID_MARKER or marker == SOI:
            raise InvalidInputFormat(f"Invalid JPEG marker 0x{marker:02x}")

        # the segment length includes the length field itself
        length = convert_int16(file.read(2), Endian.BIG)
        if length < 2:
            raise InvalidInputFormat("Invalid JPEG segment length")
        file.seek(length - 2, io.SEEK_CUR)

        if marker == SOS:
            self._skip_entropy_coded_data(file)

    @staticmethod
    def _read_marker(file: File) -> int:
        """Read a marker, skipping the optional 0xFF fill bytes before it."""
        if convert_int8(file.read(1), Endian.BIG) != MARKER_PREFIX:
            raise InvalidInputFormat("Missing JPEG marker")
        while (marker := convert_int8(file.read(1), Endian.BIG)) == MARKER_PREFIX:
            pass
        return marker

    @staticmethod
    def _skip_entropy_coded_data(file: File):
        match = ENTROPY_CODED_DATA_END.search(file, file.tell())
        if match is None:
            raise InvalidInputFormat("JPEG scan data is truncated")
        file.seek(match.start(), io.SEEK_SET)
