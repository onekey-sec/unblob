import io
import re

import attrs
from structlog import get_logger

from unblob.file_utils import Endian, File, InvalidInputFormat
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
    // the RIFF header too: id "RIFF", then the size of the form type and the chunks
    typedef struct riff_chunk_header {
        char id[4];
        uint32 data_size;
    } riff_chunk_header_t;

    typedef struct wav_format {
        uint16 format_tag;
        uint16 channels;
        uint32 sample_rate;
        uint32 bytes_per_second;
        uint16 block_align;
        uint16 bits_per_sample;
    } wav_format_t;
"""

FORM_TYPE_SIZE = 4
CHUNK_ID_PATTERN = re.compile(rb"[\x20-\x7e]{4}")


@attrs.frozen
class RIFFChunk:
    id: bytes
    offset: int  # of the chunk data
    size: int


class _RIFFHandler(StructHandler):
    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "riff_chunk_header_t"

    EXTRACTOR = None

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, Endian.LITTLE)
        if header.data_size < FORM_TYPE_SIZE:
            raise InvalidInputFormat("Invalid RIFF size")
        end_offset = start_offset + len(header) + header.data_size
        # the form type is matched by the pattern
        file.seek(FORM_TYPE_SIZE, io.SEEK_CUR)

        chunks = self._read_chunks(file, end_offset)
        if not chunks:
            raise InvalidInputFormat("RIFF form without chunks")
        self.check_chunks(file, chunks)

        return ValidChunk(start_offset=start_offset, end_offset=end_offset)

    def _read_chunks(self, file: File, end_offset: int) -> list[RIFFChunk]:
        """Walk the chunks, which must fill the RIFF form exactly."""
        chunks = []
        while file.tell() < end_offset:
            chunk_header = self._struct_parser.parse(
                "riff_chunk_header_t", file, Endian.LITTLE
            )
            if not CHUNK_ID_PATTERN.fullmatch(chunk_header.id):
                raise InvalidInputFormat("Invalid RIFF chunk id")
            chunks.append(
                RIFFChunk(chunk_header.id, file.tell(), chunk_header.data_size)
            )
            file.seek(chunk_header.data_size, io.SEEK_CUR)
            # chunk data is padded to even size, but writers commonly leave out
            # the pad byte of the last chunk (and do not count it in the RIFF size)
            if chunk_header.data_size % 2 and file.tell() < end_offset:
                file.seek(1, io.SEEK_CUR)

        if file.tell() != end_offset:
            raise InvalidInputFormat("RIFF chunks do not match the RIFF size")
        return chunks

    def check_chunks(self, file: File, chunks: list[RIFFChunk]):
        """Validate the form type specific chunks."""


MAX_CHANNELS = 8
MAX_SAMPLE_RATE = 384_000
MIN_FORMAT_SIZE = 16


class WAVHandler(_RIFFHandler):
    NAME = "wav"

    PATTERNS = [Regex(r"RIFF.{4}WAVE")]

    DOC = HandlerDoc(
        name="WAV",
        description="WAV is the RIFF audio format: a RIFF form of type WAVE with a format chunk followed by the sample data. unblob carves WAV sounds embedded in other data, such as alarm or prompt sounds in RTOS firmware; standalone WAV files are skipped based on their file type.",
        handler_type=HandlerType.MEDIA,
        vendor=None,
        references=[
            Reference(
                title="Multimedia Programming Interface and Data Specifications 1.0 (RIFF)",
                url="https://www.aelius.com/njh/wavemetatool/riffmci.pdf",
            ),
            Reference(
                title="WAV Wikipedia",
                url="https://en.wikipedia.org/wiki/WAV",
            ),
        ],
        limitations=[],
    )

    def check_chunks(self, file: File, chunks: list[RIFFChunk]):
        # other chunks (fact, LIST, cue, ...) may appear anywhere
        wave_chunks = [chunk for chunk in chunks if chunk.id in (b"fmt ", b"data")]
        if [chunk.id for chunk in wave_chunks] != [b"fmt ", b"data"]:
            raise InvalidInputFormat("WAV needs one format chunk, then one data chunk")
        format_chunk, _ = wave_chunks
        if format_chunk.size < MIN_FORMAT_SIZE:
            raise InvalidInputFormat("WAV format chunk is too small")
        file.seek(format_chunk.offset, io.SEEK_SET)
        wav_format = self._struct_parser.parse("wav_format_t", file, Endian.LITTLE)
        # format tag 0 is WAVE_FORMAT_UNKNOWN
        if not (
            wav_format.format_tag
            and 0 < wav_format.channels <= MAX_CHANNELS
            and 0 < wav_format.sample_rate <= MAX_SAMPLE_RATE
            and wav_format.block_align
        ):
            raise InvalidInputFormat("Invalid WAV format")
